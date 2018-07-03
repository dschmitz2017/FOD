# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

# Copyright (C) 2010-2014 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse, NoReverseMatch

from flowspec.helpers import send_new_mail, get_peer_techc_mails
from utils import proxy as PR
from ipaddr import *
import datetime
import logging

from junos import create_junos_name


import beanstalkc
from utils.randomizer import id_generator as id_gen

from tasks import *


FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


FRAGMENT_CODES = (
    ("dont-fragment", "Don't fragment"),
    ("first-fragment", "First fragment"),
    ("is-fragment", "Is fragment"),
    ("last-fragment", "Last fragment"),
    ("not-a-fragment", "Not a fragment")
)

THEN_CHOICES = (
    ("accept", "Accept"),
    ("discard", "Discard"),
    ("community", "Community"),
    ("next-term", "Next term"),
    ("routing-instance", "Routing Instance"),
    ("rate-limit", "Rate limit"),
    ("sample", "Sample")
)

MATCH_PROTOCOL = (
    ("ah", "ah"),
    ("egp", "egp"),
    ("esp", "esp"),
    ("gre", "gre"),
    ("icmp", "icmp"),
    ("icmp6", "icmp6"),
    ("igmp", "igmp"),
    ("ipip", "ipip"),
    ("ospf", "ospf"),
    ("pim", "pim"),
    ("rsvp", "rsvp"),
    ("sctp", "sctp"),
    ("tcp", "tcp"),
    ("udp", "udp"),
)

ROUTE_STATES = (
    ("ACTIVE", "ACTIVE"),
    ("ERROR", "ERROR"),
    ("EXPIRED", "EXPIRED"),
    ("PENDING", "PENDING"),
    ("OUTOFSYNC", "OUTOFSYNC"),
    ("INACTIVE", "INACTIVE"),
    ("ADMININACTIVE", "ADMININACTIVE"),
)


def days_offset(): return datetime.date.today() + datetime.timedelta(days = settings.EXPIRATION_DAYS_OFFSET)

class MatchPort(models.Model):
    port = models.CharField(max_length=24, unique=True)
    def __unicode__(self):
        return self.port
    class Meta:
        db_table = u'match_port'

class MatchDscp(models.Model):
    dscp = models.CharField(max_length=24)
    def __unicode__(self):
        return self.dscp
    class Meta:
        db_table = u'match_dscp'

class MatchProtocol(models.Model):
    protocol = models.CharField(max_length=24, unique=True)
    def __unicode__(self):
        return self.protocol
    class Meta:
        db_table = u'match_protocol'

class FragmentType(models.Model):
    fragmenttype = models.CharField(max_length=20, choices=FRAGMENT_CODES, verbose_name="Fragment Type")

    def __unicode__(self):
        return "%s" %(self.fragmenttype)


class ThenAction(models.Model):
    action = models.CharField(max_length=60, choices=THEN_CHOICES, verbose_name="Action")
    action_value = models.CharField(max_length=255, blank=True, null=True, verbose_name="Action Value")

    def __unicode__(self):
        ret = "%s:%s" %(self.action, self.action_value)
        return ret.rstrip(":")

    class Meta:
        db_table = u'then_action'
        ordering = ['action', 'action_value']
        unique_together = ("action", "action_value")


class Rule(models.Model):
    name = models.SlugField(max_length=128, verbose_name=_("Name"))
    applier = models.ForeignKey(User, blank=True, null=True)
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True, default=datetime.datetime.now, null=False)
    last_updated = models.DateTimeField(auto_now=True, default=datetime.datetime.now, null=False)
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"))
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="INACTIVE")


    class Meta:
        db_table = u'flowspec_rule'
        verbose_name = "Rule"
        verbose_name_plural = "Rules"

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None

    def save(self, *args, **kwargs):
        if not self.pk:
            hash = id_gen()
            self.name = "%s_%s" % (self.name, hash)
        super(Rule, self).save(*args, **kwargs) # Call the "real" save() method.

    def _send_mail(self, *args, **kwargs):
        args = kwargs.get("args")

        fqdn = Site.objects.get_current().domain
        try:
            admin_url = 'https://%s%s' % (fqdn, reverse(args.get("url_path"), kwargs={args.get("url_id"): self.name}))
        except NoReverseMatch:
            admin_url = "Unknown"
        args["url"] = admin_url
        mail_body = render_to_string('rule_action.txt', args)
        user_mail = '%s' % self.applier.email
        user_mail = user_mail.split(';')
        send_new_mail(
            args.get("subject"),
            mail_body,
            settings.SERVER_EMAIL, user_mail,
            get_peer_techc_mails(self.applier, args.get("peer"))
        )
        return mail_body
      
    def commit_add(self, *args, **kwargs):
        peers = self.applier.get_profile().peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                for route in self.routes.all():
                    if IPNetwork(route.destination) in net:
                        username = peer
                        break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        send_message("[%s] Adding rule %s. Please wait..." % (self.applier.username, self.name), peer)
        response = add.delay(self)
        logger.info('Got add job id: %s' % response)
        mail_body = self._send_mail(args={
                'url_path': 'edit-route',
                'url_id': 'route_slug',
                'rule': self,
                'routes': self.routes.all(),
                'address': self.requesters_address,
                'action': 'creation',
                'peer': username,
                'subject': settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier.username),
        })

        d = {
            'clientip': '%s' % self.requesters_address,
            'user': self.applier.username
        }
        logger.info(mail_body, extra=d)

    def commit_edit(self, *args, **kwargs):
        peers = self.applier.get_profile().peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                for route in self.routes.all():
                    if IPNetwork(route.destination) in net:
                        username = peer
                        break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        send_message(
            '[%s] Editing rule %s. Please wait...' %
            (
                self.applier.username,
                self.name
            ), peer
        )
        response = edit.delay(self)
        logger.info('Got edit job id: %s' % response)
        mail_body = self._send_mail(args={
                'url_path': 'edit-route',
                'url_id': 'route_slug',
                'rule': self,
                'routes': self.routes.all(),
                'address': self.requesters_address,
                'action': 'edit',
                'peer': username,
                'subject': settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier.username),
        })

        d = {
            'clientip': self.requesters_address,
            'user': self.applier.username
        }
        logger.info(mail_body, extra=d)

    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.get_profile().peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                for route in self.routes.all():
                    if IPNetwork(route.destination) in net:
                        username = peer
                        break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        send_message(
            '[%s] Suspending rule %s. %sPlease wait...' % (
                self.applier.username,
                self.name,
                reason_text
            ), peer
        )
        response = delete.delay(self, reason=reason)
        logger.info('Got delete job id: %s' % response)

        mail_body = self._send_mail(args={
                'url_path': 'edit-route',
                'url_id': 'route_slug',
                'rule': self,
                'routes': self.routes.all(),
                'address': self.requesters_address,
                'action': 'removal',
                'peer': username,
                'subject': settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier.username),
        })
        d = {
            'clientip': self.requesters_address,
            'user': self.applier.username
        }
        logger.info(mail_body, extra=d)


class Route(models.Model):
    name = models.SlugField(max_length=128, verbose_name=_("Name"))
    rule = models.ForeignKey(Rule, related_name='routes', null=True)
    source = models.CharField(max_length=32, help_text=_("Network address. Use address/CIDR notation"), verbose_name=_("Source Address"))
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Network address. Use address/CIDR notation"), verbose_name=_("Destination Address"))
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, null=True, verbose_name="DSCP")
    fragmenttype = models.ManyToManyField(FragmentType, blank=True, null=True, verbose_name="Fragment Type")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP Type")
    packetlength = models.IntegerField(blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, null=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=128, blank=True, null=True, verbose_name="TCP flag")
#    is_online = models.BooleanField(default=False)
#    is_active = models.BooleanField(default=False)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))

    @property
    def applier_username(self):
        if self.rule and self.rule.applier:
            return self.rule.applier.username
        else:
            return None

    def __unicode__(self):
        return self.name

    class Meta:
        db_table = u'route'
        verbose_name = "Route"
        verbose_name_plural = "Routes"

    def save(self, *args, **kwargs):
        if not self.pk:
            hash = id_gen()
            self.name = "%s_%s" % (self.name, hash)
        super(Route, self).save(*args, **kwargs) # Call the "real" save() method.

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))

    def has_expired(self):
        today = datetime.date.today()
        if today > self.expires:
            return True
        return False

    def status(self):
        if self.rule:
            return self.rule.status
        else:
            return ROUTE_STATES["INACTIVE"]

    def check_sync(self):
        if not self.is_synced():
            self.status = "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status = "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass


#                try:
#                    assert(self.fragmenttype)
#                    assert(devicematch['fragment'][0])
#                    if self.fragmenttype == devicematch['fragment'][0]:
#                        found = found and True
#                        logger.info('Found a matching fragment type')
#                    else:
#                        found = False
#                        logger.info('Fragment type fields do not match')
#                except:
#                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status != "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status = "ACTIVE"
                    self.save()
                    found = True
            if self.status == "ADMININACTIVE" or self.status == "INACTIVE" or self.status == "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        if self.fragmenttype.all():
            ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True

    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})


def send_message(msg, user):
#    username = user.username
    peer = user
    b = beanstalkc.Connection()
    b.use(settings.POLLS_TUBE)
    tube_message = json.dumps({'message': str(msg), 'username': peer})
    b.put(tube_message)
    b.close()
