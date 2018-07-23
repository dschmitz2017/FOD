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

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class PeerViewSet(viewsets.ViewSet):
    queryset = User.objects.all()
    def get_queryset(self):
        print(self.request.user)
        if self.request.user.is_authenticated: # and not self.request.user.is_anonymous:
            pr = PeerRange.objects.filter(peer__user_profile__peers=self.request.user)
            return [str(net) for net in pr]
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
                return Rule.objects.filter(applier=self.request.user)
            else:
                raise PermissionDenied('User is not Authenticated')

        if self.request.user.is_superuser:
            return Rule.objects.all()
        elif self.request.user.is_authenticated and not self.request.user.is_anonymous:
            return Rule.objects.filter(applier=self.request.user)

    def list(self, request):
        serializer = RuleSerializer(self.get_queryset(), many=True, context={'request': request})
        return Response(serializer.data)

    def create(self, request):
        serializer = RuleSerializer(context={'request': request})
        return super(RuleViewSet, self).create(request)

    def retrieve(self, request, pk=None):
        rule = get_object_or_404(self.get_queryset(), pk=pk)
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

    def post_save(self, obj, created):
        if created:
            obj.commit_add()
        else:
            if obj.status not in ['EXPIRED', 'INACTIVE', 'ADMININACTIVE']:
                obj.commit_edit()

    def pre_delete(self, obj):
        obj.commit_delete()

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
                #os.write(4, "debug requesta test\n")

                ##temp1 = Route.objects.filter(containing_peer_ranges__peer__in=self.request.user.userprofile.peers.all())
                ##[obj for obj in Order.objects.all() if obj.expire in days]
                #users_peers_set = set(self.request.user.userprofile.peers.all())
                #routes_all = list(Route.objects.all())
                ##temp1 = [obj for obj in routes_all]
                #temp1 = [obj for obj in routes_all if len(set(obj.containing_peers()).intersection(users_peers_set))>0]
                ##temp1 = [obj for obj in routes_all if len(set(obj.containing_peers()))>0]
                ##os.write(4, "debug requesta test"+str(temp1)+"\n")
                temp1 = self.get_users_routes_by_its_peers()
                logger.info("RouteViewSet::get_queryset(): DEBUG=true, is_authenticated => temp="+str(temp1))
                #logger.info("RouteViewSet::get_queryset(): DEBUG=true, is_authenticated => temp.type="+str(type(temp1)))
                return temp1

                # old code which lists only routes with same applier:
                #ret2 = Route.objects.filter(applier=self.request.user)
                #logger.info("RouteViewSet::get_queryset(): DEBUG=true, is_authenticated => ret2="+str(ret2))
                #logger.info("RouteViewSet::get_queryset(): DEBUG=true, is_authenticated => ret2.type="+str(type(ret2)))

                #return Route.objects.filter(containing_peer_ranges__peer__in=self.request.user.userprofile.peers.all())
  
                #if not user.is_superuser:
                #  networks = PeerRange.objects.filter(peer__in=self.request.user.userprofile.peers.all())
                #else:
                #  networks = PeerRange.objects.filter(peer__in=Peer.objects.all()).distinct()

            else:
                raise PermissionDenied('User is not Authenticated')

        if self.request.user.is_superuser:
            return Route.objects.all()
        elif (self.request.user.is_authenticated() and not self.request.user.is_anonymous()):
            #return Route.objects.filter(applier=self.request.user)
            return self.get_users_routes_by_its_peers()

    def get_users_routes_by_its_peers(self):
        users_peers_set = set(self.request.user.userprofile.peers.all())
        routes_all = list(Route.objects.all())
        #temp1 = [obj for obj in routes_all]
        temp1 = [obj for obj in routes_all if len(set(obj.containing_peers()).intersection(users_peers_set))>0]
        temp1_ids = [obj.id for obj in temp1]
        temp2_ids = set(temp1_ids)
        return Route.objects.filter(id__in=temp2_ids)

    def get_users_routes_by_applier_only(self):
        return Route.objects.filter(applier=self.request.user)

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
                obj.status = "INACTIVE_TODELETE"
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

    def post_save(self, obj, created):
        if created:
            obj.commit_add()

    def pre_delete(self, obj):
        logger.info("RouteViewSet::pre_delete(): called "+str(self)+", obj="+str(obj))
        obj.commit_delete()
        logger.info("RouteViewSet::pre_delete(): returning "+str(self)+", obj="+str(obj))

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
