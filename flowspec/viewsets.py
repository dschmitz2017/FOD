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
)

from rest_framework.response import Response

class PeerViewSet(viewsets.ViewSet):
    queryset = User.objects.all()
    def get_queryset(self):
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
        if settings.DEBUG:
            if self.request.user.is_anonymous():
                return Route.objects.all()
            elif self.request.user.is_authenticated():
                return Route.objects.filter(rule__applier=self.request.user)
            else:
                raise PermissionDenied('User is not Authenticated')

        if self.request.user.is_superuser:
            return Route.objects.all()
        elif self.request.user.is_authenticated and not self.request.user.is_anonymous:
            return Route.objects.filter(applier=self.request.user)

    def list(self, request):
        serializer = RouteSerializer(self.get_queryset(), many=True, context={'request': request})
        return Response(serializer.data)

    def create(self, request):
        serializer = RouteSerializer(context={'request': request})
        return super(RouteViewSet, self).create(request)

    def retrieve(self, request, pk=None):
        route = get_object_or_404(self.get_queryset(), pk=pk)
        serializer = RouteSerializer(route)
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

    #def post_save(self, obj, created):
    #    if created:
    #        obj.commit_add()
    #    else:
    #        if obj.status not in ['EXPIRED', 'INACTIVE', 'ADMININACTIVE']:
    #            obj.commit_edit()

    #def pre_delete(self, obj):
    #    obj.commit_delete()


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
