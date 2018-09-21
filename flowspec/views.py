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

import json
from django import forms
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib.sites.models import Site
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import get_object_or_404, render_to_response, render
from django.template.context import RequestContext
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _
from django.core.urlresolvers import reverse
from django.contrib import messages
from accounts.models import *
from ipaddr import *
from django.db.models import Q
from django.contrib.auth import authenticate, login

from django.forms.models import model_to_dict

from flowspec.forms import *
from flowspec.models import *
from peers.models import *

from registration.models import RegistrationProfile

from copy import deepcopy

from django.views.decorators.cache import never_cache
from django.conf import settings
from django.template.defaultfilters import slugify
from flowspec.helpers import send_new_mail, get_peer_techc_mails
import datetime
import os

from flowspec.snmpstats import load_history, get_last_msrm_delay_time

LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'gunicorn_views.log')
# FORMAT = '%(asctime)s %(levelname)s: %(message)s'
# logging.basicConfig(format=FORMAT)
#formatter = logging.Formatter('%(asctime)s %(levelname)s %(clientip)s %(user)s: %(message)s') # leads to strange errors on test-lab
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s') 

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)

@login_required
def user_routes(request):
    user_routes = Route.objects.filter(applier=request.user)
    return render(
        request,
        'user_routes.html',
        {
            'routes': user_routes
        },
    )


def welcome(request):
    return render(
        request,
        'welcome.html',
        {}
    )


@login_required
@never_cache
def dashboard(request):
    all_group_rules = []
    message = ''
    try:
        peers = request.user.get_profile().peers.select_related('user_profile')
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(
            request,
            'error.html',
            {
                'error': error
            }
        )
    if peers:
        if request.user.is_superuser:
            all_group_rules = Rule.objects.all().order_by('-last_updated')[:10]
        else:
            query = Q()
            for peer in peers:
                query |= Q(applier__userprofile__in=peer.user_profile.all())
            all_group_rules = Rule.objects.filter(query)
        if all_group_rules is None:
            message = 'You have not added any rules yet'
    else:
        message = 'You are not associated with a peer.'
        return render(
            request,
            'dashboard.html',
            {
                'message': message
            }
        )
    return render(
        request,
        'dashboard.html',
        {
            'routes': all_group_rules.prefetch_related(
                'applier',
                'applier',
                'fragmenttype',
                'protocol',
                'dscp',
            ),
            'message': message
        },
    )


@login_required
@never_cache
def group_routes(request):
    try:
        request.user.get_profile().peers.all()
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(
            request,
            'error.html',
            {
                'error': error
            }
        )
    return render(
        request,
        'user_routes.html',
        {}
    )


@login_required
@never_cache
def group_routes_ajax(request):
    #logger.info("views::group_routes_ajax(): called")
    all_group_rules = []
    try:
        peers = request.user.get_profile().peers.prefetch_related('networks')
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(
            request,
            'error.html',
            {'error': error}
        )
    if request.user.is_superuser:
        all_group_rules = Rule.objects.all()
    else:
        query = Q()
        for peer in peers:
            query |= Q(applier__userprofile__in=peer.user_profile.all())
        all_group_rules = Route.objects.filter(query)
    jresp = {}
    rules = build_routes_json(all_group_rules)
    jresp['aaData'] = rules
    #logger.info("views::group_routes_ajax(): before return HttpResponse")
    return HttpResponse(json.dumps(jresp), mimetype='application/json')


@login_required
@never_cache
def overview_routes_ajax(request):
    all_group_rules = []
    try:
        peers = request.user.get_profile().peers.all().select_related()
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render_to_response('error.html', {'error': error}, context_instance=RequestContext(request))
    if request.user.is_superuser or request.user.has_perm('accounts.overview'):
        all_group_rules = Rule.objects.all()
    else:
        query = Q()
        for peer in peers:
            query |= Q(applier__userprofile__in=peer.user_profile.all())
        all_group_rules = Rule.objects.filter(query)
    jresp = {}
    rules = build_routes_json(all_group_rules)
    jresp['aaData'] = rules
    return HttpResponse(json.dumps(jresp), mimetype='application/json')


def build_routes_json(grules):
    routes = []
    for r in grules.prefetch_related(
            'applier',
            'routes',
    ):
        rd = {}
        rd['id'] = r.pk
        rd['name'] = r.name
        rd['details'] = '<a href="%s">%s</a>' % (r.get_absolute_url(), r.name)
        rd['routes'] = list()
        #for routei in r.routes.all():
        for routei in r.get_routes_nondeleted:
            route = {}
            route['port'] = routei.port
            route['sourceport'] = routei.sourceport
            route['destinationport'] = routei.destinationport
            route['response'] = "%s" % routei.response
            route['match'] = routei.get_match()
            rd['routes'].append(route)
        # name with link to rule details
        if not r.comments:
            rd['comments'] = 'Not Any'
        else:
            rd['comments'] = r.comments
        rd['match'] = r.get_match()
        rd['response'] = r.get_responses()
        rd['then'] = r.get_then()
        rd['status'] = r.status
        # in case there is no applier (this should not occur)
        try:
            rd['applier'] = r.applier.username
        except:
            rd['applier'] = 'unknown'
            rd['peer'] = ''
        else:
            rd['peer'] = r.helper_get_matching_peers()[1]
        rd['expires'] = "%s" % r.expires
        routes.append(rd)
    return routes

def helper_prepare_user_request_data(request, applier, request_data):
        if request.user.is_superuser:
            request_data['issuperuser'] = request.user.username
        else:
            request_data['applier'] = applier
            try:
                del request_data['issuperuser']
            except:
                pass

def helper_calc_applier_peer_networks(request):
    applier_peer_networks = []
    if request.user.is_superuser:
        applier_peer_networks = PeerRange.objects.all()
    else:
        user_peers = request.user.get_profile().peers.all()
        for peer in user_peers:
            applier_peer_networks.extend(peer.networks.all())
    return applier_peer_networks

@login_required
@never_cache
def add_route(request):
    #logger.info("views::add_route(): request="+str(request))
    logger.info("views::add_route(): called")
    applier = request.user.pk
    #applier_peer_networks = []
    #if request.user.is_superuser:
    #    applier_peer_networks = PeerRange.objects.all()
    #else:
    #    user_peers = request.user.get_profile().peers.all()
    #    for peer in user_peers:
    #        applier_peer_networks.extend(peer.networks.all())
    applier_peer_networks = helper_calc_applier_peer_networks(request)
    if not applier_peer_networks:
        messages.add_message(
            request,
            messages.WARNING,
            ('Insufficient rights on administrative networks. Cannot add rule. Contact your administrator')
        )
        return HttpResponseRedirect(reverse("group-routes"))
    if request.method == "GET":
        expires = datetime.date.today() + datetime.timedelta(days=settings.EXPIRATION_DAYS_OFFSET - 1)
        form = RouteForm(initial={'applier': applier, 'expires': expires})
        form.fields['expires'] = forms.DateField()
        form.fields['applier'] = forms.ModelChoiceField(queryset=User.objects.filter(pk=request.user.pk), required=True, empty_label=None)
        if request.user.is_superuser:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.all().order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.all().order_by('protocol'), required=False)
        else:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
        return render_to_response('apply.html', {'form': form,
            'applier': applier,
            'maxexpires': settings.MAX_RULE_EXPIRE_DAYS },
            context_instance=RequestContext(request))

    else:
        request_data = request.POST.copy()
        #if request.user.is_superuser:
        #    request_data['issuperuser'] = request.user.username
        #else:
        #    request_data['applier'] = applier
        #    try:
        #        del request_data['issuperuser']
        #    except:
        #       pass
        helper_prepare_user_request_data(request, applier, request_data)
        logger.info("views::add_route(): create new Rule " + request_data['name'])
        rule = Rule()
        rule.name = request_data['name']
        rule.applier = request.user
        rule.expires = request_data['expires']
        rule.save()
        rule.then.add(request_data['then'])
        rule.save()
        logger.info("views::add_route(): created new Rule " + str(rule.pk) + " " + str(rule))
        request_data['rule'] = rule.pk
        
        logger.info("views::add_route(): request_data " + str(request_data))
           
        source_prefix_list_str = request_data['source']
        logger.info("views::add_route(): source_prefix_list_str=" + str(source_prefix_list_str))
        source_prefix_list = source_prefix_list_str.split()

        for source_prefix in source_prefix_list:
          logger.info("views::add_route(): source_prefix loop: iter start source_prefix="+str(source_prefix))
          request_data['source'] = source_prefix

          form = RouteForm(request_data)
          #route_status_speced = request_data['status']
          if form.is_valid():
              route = form.save(commit=False)
              if not request.user.is_superuser:
                  route.applier = request.user
              route_status_speced = route.status
              logger.info("views::add_route(): route_status_speced="+str(route_status_speced))
              rule.routes.add(route)
              #rule.save()
              route.status = "PENDING"
              route.response = "Applying"
              route.source = IPNetwork('%s/%s' % (IPNetwork(route.source).network.compressed, IPNetwork(route.source).prefixlen)).compressed
              route.destination = IPNetwork('%s/%s' % (IPNetwork(route.destination).network.compressed, IPNetwork(route.destination).prefixlen)).compressed
              try:
                  route.requesters_address = request.META['HTTP_X_FORWARDED_FOR']
              except:
                  # in case the header is not provided
                  route.requesters_address = 'unknown'
              #route.save()
              form.save_m2m()
              # We have to make the commit after saving the form
              # in order to have all the m2m relations.
              route.status = route_status_speced
          else:
              form.fields['expires'] = forms.DateField()
              form.fields['applier'] = forms.ModelChoiceField(queryset=User.objects.filter(pk=request.user.pk), required=True, empty_label=None)
              if request.user.is_superuser:
                  form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.all().order_by('action'), required=True)
                  form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.all().order_by('protocol'), required=False)
              else:
                  form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
                  form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
              return render(
                  request,
                  'apply.html',
                  {
                      'form': form,
                      'applier': applier,
                      'maxexpires': settings.MAX_RULE_EXPIRE_DAYS
                  }
              )
          logger.info("views::add_route(): source_prefix loop: iter end source_prefix="+str(source_prefix))

        logger.info("views::add_route(): before actually commint rule")
        for route in rule.routes.all():
          route.save()
        rule.editing = False
        rule.save()
        rule.commit_add()
        logger.info("views::add_route(): after actually commint rule")
        return HttpResponseRedirect(reverse("group-routes"))


@login_required
@never_cache
def edit_route(request, rule_slug):
    #logger.info("views::edit_route(): rule_slug="+str(rule_slug)+" request="+str(request))
    logger.info("views::edit_route(): rule_slug="+str(rule_slug))
    applier = request.user.pk
    rule_edit = get_object_or_404(Rule, name=rule_slug)
    
    if rule_edit.routes:
        if rule_edit.routes.count() > 1:
            if rule_edit.status != "INACTIVE":

                rule_routes_are_compatible = rule_edit.check_if_nondeleted_routes_differ_only_in_source_prefix()
                logger.info("views::edit_route(): rule_edit="+str(rule_edit)+" rule_routes_are_compatible="+str(rule_routes_are_compatible))
                if not rule_routes_are_compatible:
                  #raise Exception("Not implemented editing multiple routes in a single rule.")
                  raise Exception("Not implemented editing multiple routes in a single rule, if routes differ in more than source prefix.")                
            else:
                rule_edit.status = "PENDING"
                rule_edit.response = "Applying"
                maxexpires = datetime.date.today() + datetime.timedelta(days = settings.EXPIRATION_DAYS_OFFSET - 1)
                rule_edit.expires = maxexpires
                rule_edit.save()
                rule_edit.commit_edit()
                return HttpResponseRedirect(reverse("group-routes"))
        #route_edit = rule_edit.routes.get()
    else:
        raise Exception("There is no configured route for this rule.")

    #applier_peer_networks = []
    #if request.user.is_superuser:
    #    applier_peer_networks = PeerRange.objects.all()
    #else:
    #    user_peers = request.user.get_profile().peers.all()
    #    for peer in user_peers:
    #        applier_peer_networks.extend(peer.networks.all())
    applier_peer_networks = helper_calc_applier_peer_networks(request)
    if not applier_peer_networks:
        messages.add_message(
            request,
            messages.WARNING,
            ('Insufficient rights on administrative networks. Cannot add rule. Contact your administrator')
        )
        return HttpResponseRedirect(reverse("group-routes"))
    if rule_edit.status == 'PENDING':
        messages.add_message(
            request,
            messages.WARNING,
            ('Cannot edit a pending rule: %s.') % (rule_slug)
        )
        return HttpResponseRedirect(reverse("group-routes"))
    rule_original = deepcopy(rule_edit)
    if request.POST:
        request_data = request.POST.copy()
        #if request.user.is_superuser:
        #    request_data['issuperuser'] = request.user.username
        #else:
        #    request_data['applier'] = applier
        #    try:
        #        del request_data['issuperuser']
        #    except:
        #        pass
        helper_prepare_user_request_data(request, applier, request_data)
        request_data["rule"] = rule_edit.id

        ###

        source_prefix_list_str = request_data['source']
        logger.info("views::edit_route(): source_prefix_list_str=" + str(source_prefix_list_str))
        source_prefix_list = source_prefix_list_str.split()

        # calculate based on source attribute:
        # 1. which nondeleted (=> so also compatible) routes to reuse, 
        # 2. which deleted+compatible routes to reuse (but prefer nondeleted first if possible)
        # 3. which nondeleted routes to delete (also in NETCONF) 
        # 4. and which routes missing to create and use
        # and finally to replace all now used routes in NETCONF
        (source_prefix_to_reused_route__hash, current_routes_to_make_deleted) = calculate_route_reuse(rule_edit, source_prefix_list)
        new_nondeleted_routes = []
        form_list=[]

        for source in source_prefix_list:
          request_data['source'] = source

          try:
            route_reused = source_prefix_to_reused_route__hash[source]
            route_original = deepcopy(route_reused)
            logger.info("views::edit_route(): source_prefix_list loop: source="+str(source)+" => route_reused="+str(route_reused)+" => route_reused.source="+str(route_reused.source))
          except:
            route_reused = None            
            logger.info("views::edit_route(): source_prefix_list loop: source="+str(source)+" => route_reused="+str(route_reused))

          form = RouteForm(
              request_data,
              #instance=rule_edit.routes.get()
              instance=route_reused
          )
          form.fields['expires'] = forms.DateField()
          form.fields['applier'] = forms.ModelChoiceField(queryset=User.objects.filter(pk=request.user.pk), required=True, empty_label=None)
          critical_changed_values = ['source', 'destination', 'sourceport', 'destinationport', 'port', 'protocol', 'then', 'fragmenttype']
          if form.is_valid():
              form_list.append(form)
              logger.info("views::edit_route(): source_prefix_list loop: source="+str(source)+" => route_original="+str(route_original)+" form valid")

              changed_data = form.changed_data
              route = form.save(commit=False)
              
              #route_edit = rule_edit.routes.get()
              route_edit = route_reused

              if route_reused!=None:
                route.name = route_original.name
                #route.status = rule_original.status
                route.response = route_original.response
              new_nondeleted_routes.append(route)

              if not request.user.is_superuser:
                route.rule.applier = request.user # TODO: check whether this makes still sense and is secure

              if bool(set(changed_data) & set(critical_changed_values)) or (not rule_original.status == 'ACTIVE'):
                  route.status = "PENDING"
                  route.response = "Applying"
                  route.source = IPNetwork('%s/%s' % (IPNetwork(route.source).network.compressed, IPNetwork(route.source).prefixlen)).compressed
                  route.destination = IPNetwork('%s/%s' % (IPNetwork(route.destination).network.compressed, IPNetwork(route.destination).prefixlen)).compressed
                  try:
                      route.requesters_address = request.META['HTTP_X_FORWARDED_FOR']
                  except:
                      # in case the header is not provided
                      route.requesters_address = 'unknown'

              #route.rule.expires = request_data["expires"]
              #route.rule.save()
              #route.save()
              #if bool(set(changed_data) & set(critical_changed_values)) or (not rule_original.status == 'ACTIVE'):
              #    form.save_m2m()
              #    route.rule.commit_edit()
              #return HttpResponseRedirect(reverse("group-routes"))
          else:
              logger.info("views::edit_route(): source_prefix_list loop: source="+str(source)+" => route_original="+str(route_original)+" => NOT form valid")
              if request.user.is_superuser:
                  form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.all().order_by('action'), required=True)
                  form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.all().order_by('protocol'), required=False)
              else:
                  form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
                  form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
              return render_to_response(
                  'apply.html',
                  {
                      'form': form,
                      'edit': True,
                      'applier': applier,
                      'maxexpires': settings.MAX_RULE_EXPIRE_DAYS
                  },
                  context_instance=RequestContext(request)
              )
        #endfor

        #route.rule.expires = request_data["expires"]
        rule_edit.expires = request_data["expires"]
        #route.rule.save()
        rule_edit.save()
        #route.save()
        rule_edit.status = "ACTIVE" # ???
        rule_edit.editing = False
        rule_edit.save()
  
        for route in new_nondeleted_routes:
          route.deleted = False
          route.save()

        for route in current_routes_to_make_deleted:
          route.deleted = True;
          route.save()

        if bool(set(changed_data) & set(critical_changed_values)) or (not rule_original.status == 'ACTIVE'):
            for form in form_list:
              form.save_m2m()
              #route.rule.commit_edit()

        #if rule_edit.status=="ACTIVE":
        rule_edit.commit_edit(current_routes_to_delete=current_routes_to_make_deleted)

        return HttpResponseRedirect(reverse("group-routes"))

    else:
        rule_edit.expires = rule_original.expires
        maxexpires = datetime.date.today() + datetime.timedelta(days = settings.EXPIRATION_DAYS_OFFSET - 1)
        if (not rule_original.status == 'ACTIVE' and rule_edit.expires < maxexpires):
            rule_edit.expires = maxexpires

        #route_edit = rule_edit.routes.get()
        route_edit_all = rule_edit.get_routes_nondeleted
        route_edit = route_edit_all[0] # take first nondeleted route as temple for all attributes, except source prefixes

        dictionary = model_to_dict(route_edit, fields=[], exclude=[])
        dictionary.update(model_to_dict(rule_edit, fields=[], exclude=[]))

        all_sources_str = " ".join([route.source for route in route_edit_all])
        logger.info("views::edit_route(): all_sources_str="+str(all_sources_str))
        dictionary['source'] = all_sources_str

        if request.user.is_superuser:
            dictionary['issuperuser'] = request.user.username
        else:
            try:
                del dictionary['issuperuser']
            except:
                pass
        form = RouteForm(dictionary)
        logger.info("views::edit_route(): form="+str(form))

        form.fields['expires'] = forms.DateField()
        form.fields['applier'] = forms.ModelChoiceField(queryset=User.objects.filter(pk=request.user.pk), required=True, empty_label=None)
        if request.user.is_superuser:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.all().order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.all().order_by('protocol'), required=False)
        else:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
        return render_to_response(
            'apply.html',
            {
                'form': form,
                'edit': True,
                'applier': applier,
                'maxexpires': settings.MAX_RULE_EXPIRE_DAYS
            },
            context_instance=RequestContext(request)
        )


def calculate_route_reuse(rule_edit, source_prefix_list):

    source_prefix_set = set(source_prefix_list)

    old_routes_nondeleted_compatible = rule_edit.get_routes__source_compatible(include_nondeleted=True, include_deleted=False, compatible_or_incompatible=True)
    old_routes_deleted_compatible = rule_edit.get_routes__source_compatible(include_nondeleted=False, include_deleted=True, compatible_or_incompatible=True)

    source_prefix_to_reused_route__hash = {}
    current_routes_to_make_deleted = []

    for route in old_routes_nondeleted_compatible:
      prefix = route.source
      if prefix in source_prefix_set:
        source_prefix_to_reused_route__hash[prefix] = route
        source_prefix_set.remove(prefix)
      else:
        current_routes_to_make_deleted.append(route)

    for route in old_routes_deleted_compatible:
      prefix = route.source
      if prefix in source_prefix_set:
        source_prefix_to_reused_route__hash[prefix] = route
        source_prefix_set.remove(prefix)
    
    return (source_prefix_to_reused_route__hash, current_routes_to_make_deleted)

@login_required
@never_cache
def delete_rule(request, rule_slug):
    logger.info("views::delete_route(): rule_slug="+str(rule_slug))
    #logger.info("views::delete_route(): rule_slug="+str(rule_slug)+ " request="+str(request))
    #logger.info("views::delete_route(): rule_slug="+str(rule_slug)+ " request.dir="+str(dir(request)))
    #logger.info("views::delete_route(): rule_slug="+str(rule_slug)+ " request.REQUEST="+str(dir(request.REQUEST)))
    #logger.info("views::delete_route(): rule_slug="+str(rule_slug)+ " request.REQUEST.keys="+str(dir(request.REQUEST.keys)))
    if request.is_ajax():
        rule = get_object_or_404(Rule, name=rule_slug)
        # get peers of original applier
        applier_peers = rule.helper_get_matching_peers()[0]
        logger.info("views::delete_route(): rule_slug="+str(rule_slug)+ " "+str(applier_peers))
        #logger.info("views::delete_route(): rule_slug="+str(rule_slug)+ " "+str(rule.helper_get_matching_peers()[0])
        # get request user peers
        requester_peers = request.user.get_profile().peers.all()
        if any([requester_peer in applier_peers for requester_peer in requester_peers]) or request.user.is_superuser:
            rule.status = "PENDING"
            rule.expires = datetime.date.today()
            if not request.user.is_superuser:
                rule.applier = request.user
            rule.response = "Deactivating"
            try:
                rule.requesters_address = request.META['HTTP_X_FORWARDED_FOR']
            except:
                # in case the header is not provided
                rule.requesters_address = 'unknown'

            if (not request.user.is_superuser) and (not settings.ALLOW_DELETE_FULL_FOR_NONADMIN) and rule.status=="INACTIVE_TODELETE":
                logger.info("views::delete_route(): non admin full delete forbidden, lowering to normal delete")
                rule.status="INACTIVE"

            rule.save()
            rule.commit_delete()
        html = "<html><body>Done</body></html>"
        return HttpResponse(html)
    else:
        return HttpResponseRedirect(reverse("group-routes"))


@login_required
@never_cache
def user_profile(request):
    user = request.user
    try:
        peers = request.user.get_profile().peers.all()
        if user.is_superuser:
            peers = Peer.objects.all()
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % user.username
        return render(
            request,
            'error.html',
            {'error': error}
        )
    return render(
        request,
        'profile.html',
        {
            'user': user,
            'peers': peers
        },
    )


@never_cache
def user_login(request):
    try:
        error_username = False
        error_orgname = False
        error_entitlement = False
        error_mail = False
        has_entitlement = False
        error = ''
        username = lookupShibAttr(settings.SHIB_USERNAME, request.META)
        if not username:
            error_username = True
        firstname = lookupShibAttr(settings.SHIB_FIRSTNAME, request.META)
        lastname = lookupShibAttr(settings.SHIB_LASTNAME, request.META)
        mail = lookupShibAttr(settings.SHIB_MAIL, request.META)
        entitlement = lookupShibAttr(settings.SHIB_ENTITLEMENT, request.META)

        if settings.SHIB_AUTH_ENTITLEMENT in entitlement.split(";"):
            has_entitlement = True
        if not has_entitlement:
            error_entitlement = True
        if not mail:
            error_mail = True
        if error_username:
            error = _("Your idP should release the HTTP_EPPN attribute towards this service<br>")
        if error_entitlement:
            error = error + _("Your idP should release an appropriate HTTP_SHIB_EP_ENTITLEMENT attribute towards this service<br>")
        if error_mail:
            error = error + _("Your idP should release the HTTP_SHIB_INETORGPERSON_MAIL attribute towards this service")
        if error_username or error_orgname or error_entitlement or error_mail:
            return render(
                request,
                'error.html',
                {
                    'error': error,
                    "missing_attributes": True
                },
            )
        try:
            if settings.SHIB_SLUGIFY_USERNAME:
                username = slugify(username)
            user = User.objects.get(username__exact=username)
            user.email = mail
            user.first_name = firstname
            user.last_name = lastname
            user.save()
            user_exists = True
        except:
            user_exists = False
        user = authenticate(username=username, firstname=firstname, lastname=lastname, mail=mail, authsource='shibboleth')

        if user is not None:
            try:
                user.get_profile().peers.all()
            except:
                form = UserProfileForm()
                form.fields['user'] = forms.ModelChoiceField(queryset=User.objects.filter(pk=user.pk), empty_label=None)
                form.fields['peer'] = forms.ModelChoiceField(queryset=Peer.objects.all(), empty_label=None)
                return render_to_response('registration/select_institution.html', {'form': form}, context_instance=RequestContext(request))
            if not user_exists:
                user_activation_notify(user)
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect(reverse("dashboard"))
            else:
                error = _("User account <strong>%s</strong> is pending activation. Administrators have been notified and will activate this account within the next days. <br>If this account has remained inactive for a long time contact your technical coordinator or GEANT Helpdesk") %user.username
                return render(
                    request,
                    'error.html',
                    {
                        'error': error,
                        'inactive': True
                    },
                )
        else:
            error = _("Something went wrong during user authentication. Contact your administrator")
            return render(
                request,
                'error.html',
                {'error': error},
            )
    except User.DoesNotExist as e:
        error = _("Invalid login procedure. Error: %s" % e)
        return render(
            request,
            'error.html',
            {
                'error': error
            },
        )


def user_activation_notify(user):
    current_site = Site.objects.get_current()
    peers = user.get_profile().peers.all()

    # Email subject *must not* contain newlines
    # TechCs will be notified about new users.
    # Platform admins will activate the users.
    subject = render_to_string(
        'registration/activation_email_subject.txt',
        {
            'site': current_site
        }
    )
    subject = ''.join(subject.splitlines())
    registration_profile = RegistrationProfile.objects.create_profile(user)
    message = render_to_string(
        'registration/activation_email.txt',
        {
            'activation_key': registration_profile.activation_key,
            'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
            'site': current_site,
            'user': user
        }
    )
    if settings.NOTIFY_ADMIN_MAILS:
        admin_mails = settings.NOTIFY_ADMIN_MAILS
        send_new_mail(
            settings.EMAIL_SUBJECT_PREFIX + subject,
            message,
            settings.SERVER_EMAIL,
            admin_mails,
            []
        )
    for peer in peers:
        try:
            PeerNotify.objects.get(peer=peer, user=user)
        except:
            peer_notification = PeerNotify(peer=peer, user=user)
            peer_notification.save()
            # Mail to domain techCs plus platform admins (no activation hash sent)
            subject = render_to_string(
                'registration/activation_email_peer_notify_subject.txt',
                {
                    'site': current_site,
                    'peer': peer
                }
            )
            subject = ''.join(subject.splitlines())
            message = render_to_string(
                'registration/activation_email_peer_notify.txt',
                {
                    'user': user,
                    'peer': peer
                }
            )
            send_new_mail(
                settings.EMAIL_SUBJECT_PREFIX + subject,
                message,
                settings.SERVER_EMAIL,
                get_peer_techc_mails(user, peer), [])


@login_required
@never_cache
def add_rate_limit(request):
    if request.method == "GET":
        form = ThenPlainForm()
        return render(
            request,
            'add_rate_limit.html',
            {
                'form': form,
            },
        )
    else:
        form = ThenPlainForm(request.POST)
        if form.is_valid():
            then = form.save(commit=False)
            then.action_value = "%sk" % then.action_value
            then.save()
            response_data = {}
            response_data['pk'] = "%s" % then.pk
            response_data['value'] = "%s:%s" % (then.action, then.action_value)
            return HttpResponse(
                json.dumps(response_data),
                mimetype='application/json'
            )
        else:
            return render(
                request,
                'add_rate_limit.html',
                {
                    'form': form,
                },
            )


@login_required
@never_cache
def add_port(request):
    if request.method == "GET":
        form = PortRangeForm()
        return render(
            request,
            'add_port.html',
            {
                'form': form,
            },
        )
    else:
        form = PortRangeForm(request.POST)
        if form.is_valid():
            port = form.save()
            response_data = {}
            response_data['value'] = "%s" % port.pk
            response_data['text'] = "%s" % port.port
            return HttpResponse(
                json.dumps(response_data),
                mimetype='application/json'
            )
        else:
            return render(
                request,
                'add_port.html',
                {
                    'form': form,
                },
            )


@never_cache
def selectinst(request):
    if request.method == 'POST':
        request_data = request.POST.copy()
        user = request_data['user']
        try:
            UserProfile.objects.get(user=user)
            error = _("Violation warning: User account is already associated with an institution.The event has been logged and our administrators will be notified about it")
            return render(
                request,
                'error.html',
                {
                    'error': error,
                    'inactive': True
                },
            )
        except UserProfile.DoesNotExist:
            pass

        form = UserProfileForm(request_data)
        if form.is_valid():
            userprofile = form.save()
            user_activation_notify(userprofile.user)
            error = _("User account <strong>%s</strong> is pending activation. Administrators have been notified and will activate this account within the next days. <br>If this account has remained inactive for a long time contact your technical coordinator or GEANT Helpdesk") %userprofile.user.username
            return render(
                request,
                'error.html',
                {
                    'error': error,
                    'inactive': True
                },
            )
        else:
            return render(
                request,
                'registration/select_institution.html',
                {
                    'form': form
                }
            )


@never_cache
def overview(request):
    user = request.user
    if user.is_authenticated():
        if user.has_perm('accounts.overview'):
            users = User.objects.all()
            return render(
                request,
                'overview/index.html',
                {
                    'users': users
                },
            )
        else:
            violation = True
            return render(
                request,
                'overview/index.html',
                {
                    'violation': violation
                },
            )
    else:
        return HttpResponseRedirect(reverse("altlogin"))


@login_required
@never_cache
def user_logout(request):
    logout(request)
    return HttpResponseRedirect(settings.SHIB_LOGOUT_URL or reverse('group-routes'))


@never_cache
def load_jscript(request, file):
    long_polling_timeout = int(settings.POLL_SESSION_UPDATE) * 1000 + 10000
    return render_to_response('%s.js' % file, {'timeout': long_polling_timeout}, context_instance=RequestContext(request), mimetype="text/javascript")


def lookupShibAttr(attrmap, requestMeta):
    for attr in attrmap:
        if (attr in requestMeta.keys()):
            if len(requestMeta[attr]) > 0:
                return requestMeta[attr]
    return ''


# show the details of specific route
@login_required
@never_cache
def ruledetails(request, rule_slug):
    rule = get_object_or_404(Rule, name=rule_slug)
    now = datetime.datetime.now()
    last_msrm_delay_time = get_last_msrm_delay_time()
    return render(request, 'flowspy/rule_details.html', {
      'rule': rule,
      'mytime': now,
      'last_msrm_delay_time': last_msrm_delay_time,
      'tz' : settings.TIME_ZONE,
      'route_comments_len' : len(str(rule.comments))
      })

# show the details of specific route
@login_required
@never_cache
def routedetails(request, route_slug):
    route = get_object_or_404(Route, name=route_slug)
    now = datetime.datetime.now()
    last_msrm_delay_time = get_last_msrm_delay_time()
    return render(request, 'flowspy/route_details.html', {
      'route': route, 
      'mytime': now, 
      'last_msrm_delay_time': last_msrm_delay_time,
      'tz' : settings.TIME_ZONE,
      'route_comments_len' : len(str(route.comments))
      })

@login_required
def routestats(request, route_slug):
    route = get_object_or_404(Route, name=route_slug)
    import junos
    import time
    res = {}
    try:
        #with open(settings.SNMP_TEMP_FILE, "r") as f:
        #    res = json.load(f)
        #f.close()
        res = load_history()
        if not res:
            raise Exception("No data stored in the existing file.")
        routename = create_junos_name(route)
        if settings.STATISTICS_PER_RULE==False:
            if routename in res:
              return HttpResponse(json.dumps({"name": routename, "data": res[routename]}), mimetype="application/json")
            else:
              return HttpResponse(json.dumps({"error": "Route '{}' was not found in statistics.".format(routename)}), mimetype="application/json", status=404)
        else:
            route_id = str(route.id)
            if route_id in res['_per_route']:
              return HttpResponse(json.dumps({"name": routename, "data": res['_per_route'][route_id]}), mimetype="application/json")
            else:
              return HttpResponse(json.dumps({"error": "Route '{}' was not found in statistics.".format(route_id)}), mimetype="application/json", status=404)

    except Exception as e:
        logger.error('routestats failed: %s' % e)
        return HttpResponse(json.dumps({"error": "No data available. %s" % e}), mimetype="application/json", status=404)

@login_required
def rulestats(request, route_slug):
    rule = get_object_or_404(Rule, name=route_slug)
    import junos
    import time
    res = {}
    try:
        res = load_history()
        rulename = rule.name
        rule_id = str(rule.id)
        if not res:
            raise Exception("No data stored in the existing file.")
        if rule_id in res['_per_rule']:
          return HttpResponse(json.dumps({"name": rulename, "data": res['_per_rule'][rule_id]}), mimetype="application/json")
        else:
          return HttpResponse(json.dumps({"error": "Rule '{}' was not found in statistics.".format(rule_id)}), mimetype="application/json", status=404)

    except Exception as e:
        logger.error('rulestats failed: %s' % e)
        return HttpResponse(json.dumps({"error": "No data available. %s" % e}), mimetype="application/json", status=404)

