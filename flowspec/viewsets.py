from django.shortcuts import get_object_or_404
from django.conf import settings
from django.http import HttpResponse
from rest_framework.exceptions import PermissionDenied
import json

from rest_framework import viewsets
from flowspec.models import (
    Route,
    Rule,
    User,
    MatchPort,
    ThenAction,
    FragmentType,
    MatchDscp,
    MatchProtocol
)
from peers.models import PeerRange

from flowspec.serializers import (
    RuleSerializer,
    RouteSerializer,
    PortSerializer,
    PeerSerializer,
    ThenActionSerializer,
    FragmentTypeSerializer,
    MatchProtocolSerializer,
    MatchDscpSerializer)

from flowspec.validators import check_if_rule_exists
from rest_framework.response import Response
import os
import logging

from flowspec.helpers import helper_list_unique

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class PeerViewSet(viewsets.ViewSet):
    queryset = User.objects.all()
    def get_queryset(self):
        print(self.request.user)
        if self.request.user.is_authenticated: # and not self.request.user.is_anonymous:
            #pr = PeerRange.objects.filter(peer__user_profile__peers=self.request.user)
            pr = PeerRange.objects.filter(peer__user_profile__user=self.request.user)
            tmp = [str(net) for net in pr] 
            return list(set(tmp)) # setify to remove duplicates
        else:
            raise PermissionDenied('User is not Authenticated')

    def list(self, request):
        return HttpResponse(json.dumps({"networks": self.get_queryset()}), content_type="application/json")

class RuleViewSet(viewsets.ModelViewSet):
    queryset = Rule.objects.all()
    serializer_class = RuleSerializer

    def get_queryset(self):
        if settings.DEBUG:
            if self.request.user.is_anonymous():
                return Rule.objects.all()
            elif self.request.user.is_authenticated():
                logger.info("ruleviewset::get_queryset(): DEBUG on")
                #return Rule.objects.filter(applier=self.request.user)
                return convert_container_to_queryset(self.get_users_rules_all(), Rule)
            else:
                raise PermissionDenied('User is not Authenticated')

        if self.request.user.is_superuser:
            return Rule.objects.all()
        elif self.request.user.is_authenticated and not self.request.user.is_anonymous:
            #return Rule.objects.filter(applier=self.request.user)
            #return global__get_users_rules_all(self.request.user)
            return convert_container_to_queryset(self.get_users_rules_all(), Rule)

##

    def get_users_rules_all(self):
        return global__get_users_rules_all(self.request.user)

    def get_users_rules_by_its_peers(self):
        return global__get_users_rules_by_its_peers(self.request.user)

    def get_users_rules_by_applier_only(self):
        return global__get_users_rules_by_applier_only(self.request.user)

##

    def list(self, request):
        serializer = RuleSerializer(self.get_queryset(), many=True, context={'request': request})
        return Response(serializer.data)

    def create(self, request):
        serializer = RuleSerializer(context={'request': request})
        return super(RuleViewSet, self).create(request)

    def retrieve(self, request, pk=None):
        rule = get_object_or_404(self.get_queryset(), pk=pk)

        #rule.status_orig = rule.status
        #logger.info("RuleViewSet::retrieve(): "+str(self)+", obj="+str(rule) + " status="+str(rule.status))
        #logger.info("RuleViewSet::retrieve(): "+str(self)+", obj="+str(rule) + " status_orig="+str(rule.status_orig))

        serializer = RuleSerializer(rule)
        return Response(serializer.data)

    def pre_save(self, obj):
        # DEBUG
        if settings.DEBUG:
            if self.request.user.is_anonymous():
                from django.contrib.auth.models import User
                obj.applier = User.objects.all()[0]
            elif self.request.user.is_authenticated():
                obj.applier = self.request.user
            else:
                raise PermissionDenied('User is not Authenticated')
        else:
            obj.applier = self.request.user
        #obj.status_orig = obj.status
        #logger.info("RuleViewSet::pre_save(): "+str(self)+", obj="+str(obj) + " status="+str(obj.status))
        #logger.info("RuleViewSet::pre_save(): "+str(self)+", obj="+str(obj) + " status_orig="+str(obj.status_orig))

    def post_save(self, obj, created):
        logger.info("RuleViewSet::post_save(): "+str(self)+", obj="+str(obj) + " created=" + str(created))
        logger.info("RuleViewSet::post_save(): "+str(self)+", obj="+str(obj) + " status="+str(obj.status))
        try:
          status_orig = self.status_orig # should be set in self.update
        except Exception, exc:
          status_orig = None
        logger.info("RuleViewSet::post_save(): "+str(self)+", obj="+str(obj) + " self.status_orig="+str(status_orig))

        if (status_orig=="CREATED" or status_orig==None) and obj.status=="INACTIVE" and not obj.editing:
            logger.info("RuleViewSet::post_save(): rule seems to be newly created INACTIVE")
            obj.response = "Created inactively"
            obj.save()

        if created and obj.editing == False:
            obj.commit_add()
        else:
            logger.info("RuleViewSet::post_save(): "+str(self)+", obj="+str(obj) + " obj.status="+str(obj.status)+" obj.editing="+str(obj.editing))
            if obj.status == "CREATED" and obj.editing == False:
                obj.status = "INACTIVE"
                obj.save()
                logger.info("RuleViewSet::post_save(): sttus overriden from CREATED to INACTIVE "+str(self)+", obj="+str(obj))
                obj.commit_add()
            elif obj.status not in ['EXPIRED', 'INACTIVE', 'ADMININACTIVE'] and obj.editing == False:
                obj.commit_edit()
            elif obj.status in ['INACTIVE'] and obj.editing == False:
                if status_orig == "ACTIVE":
                  logger.info("RuleViewSet::post_save(): status from ACTIVE to INACTIVE, calling delete")
                  #obj.commit_delete()
                  self.delete(obj, delete_really=False)
                else:
                  obj.commit_edit()

    def pre_delete(self, obj):
        logger.info("RuleViewSet::pre_delete(): called "+str(self)+", obj="+str(obj))
        logger.info("RuleViewSet::pre_delete(): called "+str(self)+", obj="+str(obj))
        logger.info("RuleViewSet::pre_delete(): self.request.user.is_superuser="+str(self.request.user.is_superuser))
        logger.info("RuleViewSet::pre_delete(): settings.ALLOW_DELETE_FULL_FOR_NONADMIN="+str(settings.ALLOW_DELETE_FULL_FOR_NONADMIN))
        logger.info("RuleViewSet::pre_delete(): obj.status="+str(obj.status))

        if (not self.request.user.is_superuser) and (not settings.ALLOW_DELETE_FULL_FOR_NONADMIN) and obj.status=="INACTIVE_TODELETE":
            logger.info("RuleViewSet::pre_delete(): non admin full delete forbidden, lowering to normal delete")
            obj.status="INACTIVE"
            #obj.save()

        obj.commit_delete()
        logger.info("RuleViewSet::pre_delete(): returning "+str(self)+", obj="+str(obj))

    def update(self, request, pk=None, partial=False):
        """
        Overriden to handle HTTP_X_METHODOVERRIDE 
        """
        
        # maybe not necsessary:
        obj = get_object_or_404(self.queryset, pk=pk)

        self.status_orig = obj.status
        logger.info("RuleViewSet::update(): "+str(self)+", obj="+str(obj) + " status="+str(obj.status))
        logger.info("RuleViewSet::update(): "+str(self)+", obj="+str(obj) + " self.status_orig="+str(self.status_orig))

        logger.info("RuleViewSet::update(): called request="+str(request))
        if request.META.has_key('HTTP_X_METHODOVERRIDE'):

          serializer = RouteSerializer(
            obj, context={'request': request},
            data=request.DATA, partial=partial)

          if serializer.is_valid():
            new_status = serializer.object.status
            super(RuleViewSet, self).update(request, pk, partial=partial)

          method_overriden = request.META['HTTP_X_METHODOVERRIDE']
          logger.info("RuleViewSet::update(): HTTP_X_METHODOVERRIDE="+str(method_overriden))
          if method_overriden == "DELETE":
            logger.info("RuleViewSet::update(): redirecting to delete with full delete on")
            #obj.status = "INACTIVE_TODELETE"
            return self.delete(obj, delete_really=True)

        return super(RuleViewSet, self).update(request, pk=pk, partial=partial)


class RouteViewSet(viewsets.ModelViewSet):
    queryset = Route.objects.all()
    serializer_class = RouteSerializer

    def get_queryset(self):
        logger.info("RouteViewSet::get_queryset(): called, settings.DEBUG="+str(settings.DEBUG))
        if settings.DEBUG:
            if self.request.user.is_anonymous():
                return Route.objects.all()
            elif self.request.user.is_authenticated():

                logger.info("RouteViewSet::get_queryset(): DEBUG=true, is_authenticated")
                #temp1 = self.get_users_routes_all()
                temp1 = convert_container_to_queryset(self.get_users_routes_all(), Route)
                logger.info("RouteViewSet::get_queryset(): DEBUG=true, is_authenticated => temp="+str(temp1))
                return temp1

            else:
                raise PermissionDenied('User is not Authenticated')

        if self.request.user.is_superuser:
            return Route.objects.all()
        elif (self.request.user.is_authenticated() and not self.request.user.is_anonymous()):
            #return Route.objects.filter(applier=self.request.user)
            return convert_container_to_queryset(self.get_users_routes_all(), Route)

    def get_users_routes_all(self):
        return global__get_users_routes_all(self.request.user)

    def get_users_routes_by_its_peers(self):
        return global__get_users_routes_by_its_peers(self.request.user)

    def get_users_routes_by_applier_only(self):
        return global__get_users_routes_by_applier_only(self.request.user)

    #####

    def list(self, request):
        serializer = RouteSerializer(
            self.get_queryset(), many=True, context={'request': request})
        return Response(serializer.data)

    def create(self, request):
        logger.info("viewsets::route::create(): self="+str(self)+", request="+str(request))
        logger.info("viewsets::route::create(): self="+str(self)+", request.data="+str(request.DATA))
        # request.DATA['status'] may be set and we should honor it somehow ?
        serializer = RouteSerializer(
            context={'request': request}, data=request.DATA, partial=True)
        if serializer.is_valid():
            (exists, message) = check_if_rule_exists(
                {'source': serializer.object.source,
                 'destination': serializer.object.destination},
                self.get_queryset())
            if exists:
                return Response({"non_field_errors": [message]}, status=400)
            else:
                return super(RouteViewSet, self).create(request)
        else:
            return Response(serializer.errors, status=400)

    def retrieve(self, request, pk=None):
        route = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = RouteSerializer(route, context={'request': request})
        return Response(serializer.data)

    def update(self, request, pk=None, partial=False):
        """
        Overriden to customize `status` update behaviour.
        Changes in `status` need to be handled here, since we have to know the
        previous `status` of the object to choose the correct action.
        """

        def set_object_pending(obj):
            """
            Sets an object's status to "PENDING". This reflects that
            the object has not already been commited to the flowspec device,
            and the asynchronous job that will handle the sync will
            update the status accordingly

            :param obj: the object whose status will be changed
            :type obj: `flowspec.models.Route`
            """
            obj.status = "PENDING"
            obj.response = "N/A"
            obj.save()

        def work_on_active_object(obj, new_status):
            """
            Decides which `commit` action to choose depending on the
            requested status

            Cases:
            * `ACTIVE` ~> `INACTIVE`: The `Route` must be deleted from the
                flowspec device (`commit_delete`)
            * `ACTIVE` ~> `ACTIVE`: The `Route` is present, so it must be
                edited (`commit_edit`)

            :param new_status: the newly requested status
            :type new_status: str
            :param obj: the `Route` object
            :type obj: `flowspec.models.Route`
            """
            set_object_pending(obj)
            if new_status == 'INACTIVE':
                obj.commit_delete()
            else:
                obj.commit_edit()

        def work_on_inactive_object(obj, new_status):
            """
            Decides which `commit` action to choose depending on the
            requested status

            Cases:
            * `INACTIVE` ~> `ACTIVE`: The `Route` is not present on the device

            :param new_status: the newly requested status
            :type new_status: str
            :param obj: the `Route` object
            :type obj: `flowspec.models.Route`
            """
            if new_status == 'ACTIVE':
                set_object_pending(obj)
                obj.commit_add()

        obj = get_object_or_404(self.queryset, pk=pk)
        old_status = obj.status

        serializer = RouteSerializer(
            obj, context={'request': request},
            data=request.DATA, partial=partial)

        if serializer.is_valid():
            new_status = serializer.object.status
            super(RouteViewSet, self).update(request, pk, partial=partial)

            logger.info("RouteViewSet::update(): called request="+str(request))
            if request.META.has_key('HTTP_X_METHODOVERRIDE'):
              method_overriden = request.META['HTTP_X_METHODOVERRIDE']
              logger.info("RouteViewSet::update(): HTTP_X_METHODOVERRIDE="+str(method_overriden))
              if method_overriden == "DELETE":
                logger.info("RouteViewSet::update(): redirecting to delete with full delete on")
                #obj.status = "INACTIVE_TODELETE"
                return self.delete(obj)

            if old_status == 'ACTIVE':
                work_on_active_object(obj, new_status)
            elif old_status in ['INACTIVE', 'ERROR']:
                work_on_inactive_object(obj, new_status)
            return Response(
                RouteSerializer(obj,context={'request': request}).data,
                status=200)
        else:
            return Response(serializer.errors, status=400)

    def pre_delete(self, obj):
        logger.info("RouteViewSet::pre_delete(): called "+str(self)+", obj="+str(obj))
        logger.info("RouteViewSet::pre_delete(): self.request.user.is_superuser="+str(self.request.user.is_superuser))
        logger.info("RouteViewSet::pre_delete(): settings.ALLOW_DELETE_FULL_FOR_NONADMIN="+str(settings.ALLOW_DELETE_FULL_FOR_NONADMIN))
        logger.info("RouteViewSet::pre_delete(): obj.status="+str(obj.status))

        if (not self.request.user.is_superuser) and (not settings.ALLOW_DELETE_FULL_FOR_NONADMIN) and obj.status=="INACTIVE_TODELETE":
            logger.info("RouteViewSet::pre_delete(): non admin full delete forbidden, lowering to normal delete")
            obj.status="INACTIVE"
            #obj.save()

        obj.commit_delete()
        logger.info("RouteViewSet::pre_delete(): returning "+str(self)+", obj="+str(obj))

    def pre_save(self, obj):
        # DEBUG
        if settings.DEBUG:
            if self.request.user.is_anonymous():
                from django.contrib.auth.models import User
                obj.applier = User.objects.all()[0]
            elif self.request.user.is_authenticated():
                obj.applier = self.request.user
            else:
                raise PermissionDenied('User is not Authenticated')
        else:
            obj.applier = self.request.user

    #def pre_delete(self, obj):
    #    logger.info("RouteViewSet::pre_delete(): called "+str(self)+", obj="+str(obj))
    #    obj.commit_delete()
    #    logger.info("RouteViewSet::pre_delete(): returning "+str(self)+", obj="+str(obj))

class PortViewSet(viewsets.ModelViewSet):
    queryset = MatchPort.objects.all()
    serializer_class = PortSerializer


class ThenActionViewSet(viewsets.ModelViewSet):
    queryset = ThenAction.objects.all()
    serializer_class = ThenActionSerializer


class FragmentTypeViewSet(viewsets.ModelViewSet):
    queryset = FragmentType.objects.all()
    serializer_class = FragmentTypeSerializer


class MatchProtocolViewSet(viewsets.ModelViewSet):
    queryset = MatchProtocol.objects.all()
    serializer_class = MatchProtocolSerializer


class MatchDscpViewSet(viewsets.ModelViewSet):
    queryset = MatchDscp.objects.all()
    serializer_class = MatchDscpSerializer

##################################
# global helpers 

# class1's attribute 'id' should be existing and by primary key
def convert_container_to_queryset(list1, class1):
         #temp1_ids = [obj.id for obj in list1]
         temp1_ids = [obj.id for obj in list1 if obj != None]
         temp2_ids = set(temp1_ids)
         return class1.objects.filter(id__in=temp2_ids)

# all these following functions return normal containers, not particular query sets
# if needed convert them back to query sets by convert_container_to_queryset
def global__get_users_routes_by_its_peers(user):
        users_peers_set = set(user.userprofile.peers.all())
        #routes_all = list(Route.objects.all())
        #routes_all = [route for route in routes_all if not route.deleted]
        routes_all = list(Route.objects.filter(deleted=False))
        #temp1 = [obj for obj in routes_all]
        temp1 = [obj for obj in routes_all if len(set(obj.containing_peers()).intersection(users_peers_set))>0]
        #temp1_ids = [obj.id for obj in temp1]
        #temp2_ids = set(temp1_ids)
        #return Route.objects.filter(id__in=temp2_ids)
        #return convert_container_to_queryset(temp1, Route)
        return temp1

def global__get_users_routes_by_applier_only(user):
        return Route.objects.filter(rule__applier=user)
        #return list(Route.objects.filter(rule__applier=user))

def global__get_users_routes_all(user):
         routes1=global__get_users_routes_by_its_peers(user)
         routes2=global__get_users_routes_by_applier_only(user)
         routes_all=list(routes1)+list(routes2)
         routes_all=helper_list_unique(routes_all)
         #return routes_all
         #temp1_ids = [obj.id for obj in routes_all]
         #temp2_ids = set(temp1_ids)
         #return Route.objects.filter(id__in=temp2_ids)
         #return convert_container_to_queryset(routes_all, Route)
         return routes_all

def global__get_users_rules_by_its_routes(user):
            users_routes = global__get_users_routes_all(user)
            #logger.info("global__get_users_rules_by_its_routes(): users_routes="+str(users_routes))
            rules = [route.rule for route in users_routes]
            #logger.info("global__get_users_rules_by_its_routes(): rules="+str(rules))
            return rules

def global__get_users_rules_by_applier_only(user):
        return Rule.objects.filter(applier=user)
        #return list(Rule.objects.filter(applier=user))

def global__get_users_rules_all(user):
         rules1=global__get_users_rules_by_its_routes(user)
         rules2=global__get_users_rules_by_applier_only(user)
         rules_all=list(rules1)+list(rules2)
         rules_all=helper_list_unique(rules_all)
         #return convert_container_to_queryset(rules_all, Rule)
         return rules_all

