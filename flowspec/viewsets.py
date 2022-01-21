from django.shortcuts import get_object_or_404
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import PermissionDenied

from rest_framework import viewsets
from flowspec.models import Route, ThenAction, FragmentType, MatchProtocol, MatchDscp

from flowspec.serializers import (
    RouteSerializer,
    ThenActionSerializer,
    FragmentTypeSerializer,
    MatchProtocolSerializer,
    MatchDscpSerializer)

from flowspec.validators import check_if_rule_exists
from rest_framework.response import Response

from flowspec.tasks import *

import os
import logging
FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'viewsets.log')
handler = logging.FileHandler(LOG_FILENAME)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class RouteViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = Route.objects.all()
    serializer_class = RouteSerializer

    def get_queryset(self):
        scope=""
        try:
          logger.info("RouteViewSet::get_queryset(): param scope="+str(self.request.query_params['scope']))
          scope=self.request.query_params['scope'] 
        except:
          pass

        user=self.request.user
        try:
          if self.request.user.is_superuser and 'username' in self.request.query_params:
            username=self.request.query_params['username'] 
            logger.info("RouteViewSet::get_queryset(): username="+str(username))
            user=User.objects.get(username=username)
            logger.info("RouteViewSet::get_queryset(): param username="+str(self.request.query_params['username']))
        except Exception as e: 
          logger.info("RouteViewSet::get_queryset(): got exception e="+str(e))
          return convert_container_to_queryset([], Route)
        logger.info("RouteViewSet::get_queryset(): user="+str(user))

        if scope == "applier":
            return convert_container_to_queryset(self.get_users_routes_by_applier_only(user), Route)
        elif scope == "peer":
            return convert_container_to_queryset(self.get_users_routes_by_its_peers(user), Route)
        elif scope == "user":
            return convert_container_to_queryset(self.get_users_routes_all(user), Route)

        if self.request.user.is_superuser:
            return Route.objects.all() # default for admin is all
        else:
            return convert_container_to_queryset(self.get_users_routes_all(user), Route) #default for non-admin is "user"

    def get_users_routes_all(self, user):
        return global__get_users_routes_all(user)

    def get_users_routes_by_its_peers(self, user):
        return global__get_users_routes_by_its_peers(user)

    def get_users_routes_by_applier_only(self, user):
        return global__get_users_routes_by_applier_only(user)


    def list(self, request):
        serializer = RouteSerializer(
            self.get_queryset(), many=True, context={'request': request})
        return Response(serializer.data)

    def create(self, request):
        logger.debug("RouteViewSet::create(): request.data="+str(request.data))
        serializer = RouteSerializer(
            context={'request': request}, data=request.data, partial=True) # is this correct ???
        try:
            #raise test from None 
            if serializer.is_valid():
                (exists, message) = check_if_rule_exists(
                    {
                     #'source': serializer.object.source,
                     'source': request.data["source"],
                     #'destination': serializer.object.destination,
                     'destination': request.data["destination"]},
                    self.get_queryset())
                if exists:
                    return Response({"non_field_errors": [message]}, status=400)
                else:
                    #return super(RouteViewSet, self).create(request)
                    obj = super(RouteViewSet, self).create(request)
                    requested_status = request.data.get("status", "INACTIVE")
                    logger.debug("RouteViewSet::create(): requested_status="+str(requested_status))
                    logger.info("RouteViewSet::create(): obj.type="+str(type(obj)))
                    logger.info("RouteViewSet::create(): obj="+str(obj))
                    logger.info("RouteViewSet::create(): obj.dir="+str(dir(obj)))
                    logger.info("RouteViewSet::create(): obj.items="+str(obj.items))
                    logger.info("RouteViewSet::create(): obj.data="+str(obj.data))
                    logger.info("RouteViewSet::create(): obj.data.id="+str(obj.data["id"]))
                    route = get_object_or_404(self.get_queryset(), pk=obj.data["id"])
                    route.response = "N/A"
                    route.set_no_expire() # REST API created routes should have no expiration date

                    if requested_status == "ACTIVE":
                        route.status = "PENDING"
                        route.save()
                        route.commit_add()
                    elif requested_status == "INACTIVE":
                        route.status = "INACTIVE"
                        route.save()
                    else:
                        route.save()
                    obj.data["status"] = route.status
                    logger.info("RouteViewSet::create(): => route="+str(route))
                    logger.info("RouteViewSet::create(): => route.status="+str(route.status))
                    logger.info("RouteViewSet::create(): => obj="+str(obj))

                    return obj
            else:
                return Response(serializer.errors, status=400)
        except BaseException as e:
            logger.error("RouteViewSet::create(): got exception", exc_info=True)

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
                flowspec device (`commit_deactivate`)
            * `ACTIVE` ~> `ACTIVE`: The `Route` is present, so it must be
                edited (`commit_edit`)

            :param new_status: the newly requested status
            :type new_status: str
            :param obj: the `Route` object
            :type obj: `flowspec.models.Route`
            """
            set_object_pending(obj)
            if new_status == 'INACTIVE':
                deactivate_route.delay(obj.pk)
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
        
        #if not partial:
        #   raise PermissionDenied('Permission Denied')

        obj = get_object_or_404(self.queryset, pk=pk)
        old_status = obj.status

        #

        no_unneeded_redeploy=False
        if 'no_unneeded_redeploy' in request.data:
            logger.info("RouteViewSet::update(): no_unneeded_redeploy")
            request.data['no_unneeded_redeploy']=None
            no_unneeded_redeploy=True

            expires=request.data['expires']
            logger.info("RouteViewSet::update(): no_unneeded_redeploy: ignoring all other attributes except only using expires="+str(expires))
            #request.data.pop('no_unneeded_redeploy', None)
            key_list1 = list(request.data.keys())
            for key1 in key_list1:
              if key1 != 'expires' and key1 != 'status':
                request.data.pop(key1, None)

            partial = True    

        #

        serializer = RouteSerializer(
            obj, context={'request': request},
            #data=request.DATA, partial=partial)
            data=request.data, partial=partial)
        logger.info("RouteViewSet::update(): request.data="+str(request.data))

        if serializer.is_valid():
            #new_status = serializer.object.status
            new_status = serializer.data["status"]
            requested_status = request.data["status"]
            #if requested_status == 'INACTIVE':
            new_status = requested_status
            #logger.info("RouteViewSet::update(): data="+str(request.data))
            logger.info("RouteViewSet::update(): pk="+str(pk))
            logger.info("RouteViewSet::update(): request="+str(requested_status))
            logger.info("RouteViewSet::update(): obj.type="+str(type(obj)))
            logger.info("RouteViewSet::update(): obj="+str(obj))
            logger.info("RouteViewSet::update(): old_status="+str(old_status)+", new_status="+str(new_status))
            super(RouteViewSet, self).update(request, pk, partial=partial)
            if no_unneeded_redeploy:
                logger.info("RouteViewSet::update(): just updating expires")
                obj.expires = expires
                obj.save()
            elif old_status == 'ACTIVE':
                work_on_active_object(obj, new_status)
            elif old_status in ['INACTIVE', 'ERROR']:
                work_on_inactive_object(obj, new_status)
            logger.info("RouteViewSet::update(): obj="+str(obj))
            return Response(
                RouteSerializer(obj,context={'request': request}).data,
                status=200)
        else:
            return Response(serializer.errors, status=400)

    def destroy(self, request, pk=None, partial=False):
        """ HTTTP DELETE Method """
        obj = get_object_or_404(self.queryset, pk=pk)
        logger.info("RouteViewSet::delete(): pk="+str(pk)+" obj="+str(obj))

        username_request = request.user.username
        user_is_admin = request.user.is_superuser
        full_delete_is_allowed = request.user.userprofile.is_delete_allowed()
        logger.info("RouteViewSet::delete(): username_request="+str(username_request)+" user_is_admin="+str(user_is_admin)+" => full_delete_is_allowed="+str(full_delete_is_allowed))
        if obj.status!="INACTIVE":
          obj.status = "PENDING"
          obj.save()

        #if True or not self.request.user.is_superuser():
        if full_delete_is_allowed:
            job = delete_route.delay(obj.pk)
            return Response({"status": "Received task to delete route.", "job_id": str(job)}, 202)
        else:
            if obj.status == "INACTIVE":
                return Response({"status": "Cannot deactivate route that is inactive already."}, 406)
            job = deactivate_route.delay(obj.pk)
            return Response({"status": "Received task to deactivate route.", "job_id": str(job)}, 202)

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

class StatsRoutesViewSet(viewsets.ViewSet):
    """
    A simple Vieset for retrieving statistics of the route by
    an authenticated user.
    """
    permission_classes = (IsAuthenticated,)
    def retrieve(self, request, pk=None):
        logger.info("StatsRoutesViewSet:::retrieve(): pk="+str(pk))
        queryset = Route.objects.all()
        from flowspec.views import routestats
        route = get_object_or_404(queryset, id=pk)
        logger.info("StatsRoutesViewSet:::retrieve(): route.name="+str(route.name))
        return routestats(request, route.name)

#############################################################################
#############################################################################
# global helpers 

# class1's attribute 'id' should be existing and be the primary key, e.g., be a Django model class
def convert_container_to_queryset(list1, class1):
         #temp1_ids = [obj.id for obj in list1]
         temp1_ids = [obj.id for obj in list1 if obj != None]
         temp2_ids = set(temp1_ids)
         return class1.objects.filter(id__in=temp2_ids)

#############################################################################
#############################################################################

def global__get_users_routes_all(user):
         routes1=global__get_users_routes_by_its_peers(user)
         routes2=global__get_users_routes_by_applier_only(user)
         routes_all=list(routes1)+list(routes2)
         routes_all=list(set(routes_all)) # make uniques list
         return routes_all

# all these following functions return normal containers, not particular query sets
# if needed convert them back to query sets by convert_container_to_queryset
def global__get_users_routes_by_its_peers(user):
        users_peers_set = set(user.userprofile.peers.all())
        routes_all = list(Route.objects.filter())
        #routes_all = list(Route.objects)
        #temp1 = [obj for obj in routes_all]
        temp1 = [obj for obj in routes_all if len(set(obj.containing_peers()).intersection(users_peers_set))>0]
        return temp1

def global__get_users_routes_by_applier_only(user):
        #return list(Rule.objects.filter(applier=user))
        return Route.objects.filter(applier=user)

#############################################################################
#############################################################################

