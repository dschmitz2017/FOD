from django.shortcuts import get_object_or_404
from django.conf import settings
from rest_framework.exceptions import PermissionDenied

from rest_framework import viewsets
from flowspec.models import (
    Route, MatchPort, ThenAction, FragmentType, MatchProtocol,
    MatchDscp)

from flowspec.serializers import (
    RouteSerializer,
    PortSerializer,
    ThenActionSerializer,
    FragmentTypeSerializer,
    MatchProtocolSerializer,
    MatchDscpSerializer)

from flowspec.validators import check_if_rule_exists
from rest_framework.response import Response

#from sys import stderr
#import sys
import os

###

import logging

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

###

class RouteViewSet(viewsets.ModelViewSet):
    queryset = Route.objects.all()
    serializer_class = RouteSerializer

    def get_queryset(self):
        if settings.DEBUG:
            if self.request.user.is_anonymous():
                return Route.objects.all()
            elif self.request.user.is_authenticated():
                return Route.objects.filter(applier=self.request.user)
            else:
                raise PermissionDenied('User is not Authenticated')

        if self.request.user.is_superuser:
            return Route.objects.all()
        elif (self.request.user.is_authenticated() and not
              self.request.user.is_anonymous()):
            return Route.objects.filter(applier=self.request.user)

    def list(self, request):
        serializer = RouteSerializer(
            self.get_queryset(), many=True, context={'request': request})
        return Response(serializer.data)

    def create(self, request):
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
                #obj.applier = self.request.user
                self.helper_override_user(obj)
            else:
                raise PermissionDenied('User is not Authenticated')
        else:
            #obj.applier = self.request.user
            self.helper_override_user(obj)

    def helper_override_user(self, obj):
        #if self.request.user.is_superuser and obj.applier!=None:
        from django.contrib.auth.models import User
        if self.request.user.is_superuser and self.request.POST["applier"]!=None:
          os.write(4, "debug requesta1 "+str(self.request.POST["applier"])+"\n")
          obj.applier = User.objects.get(username=self.request.POST["applier"])
        elif self.request.user.is_superuser:
          os.write(4, "debug requesta2 "+str(self.request.POST["applier"])+"\n")
          #obj.applier = self.request.user
          obj.applier = User.objects.get(username='tomas.jra2t6')
          #raise PermissionDenied('Is superuser')
          #obj.applier = User.objects.get(id='tomas.jra2t6')
          #logger.info("debug request "+str(self.request))
          #logger.info("debug requestt "+str(type(self.request)))
          #logger.info("debug requestd "+str(dir(self.request)))
          ##sys.stderr.write("debug request "+str(self.request)+"\n")
          #os.write(4, "debug request "+str(self.request)+"\n")
          #os.write(4, "debug requestt "+str(type(self.request))+"\n")
          #os.write(4, "debug requestd "+str(dir(self.request))+"\n")
          #os.write(4, "debug requestd "+str(type(self.request.POST))+"\n")
          #os.write(4, "debug requestd "+str(dir(self.request.POST))+"\n")
          #os.write(4, "debug requesta "+str(self.request.POST["applier"])+"\n")
          #obj.comments = obj.comments+" "+str(os.getpid())
        else:
          #raise PermissionDenied('Is not superuser')
          obj.applier = self.request.user

    def post_save(self, obj, created):
        if created:
            obj.commit_add()

    def pre_delete(self, obj):
        obj.commit_delete()


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
