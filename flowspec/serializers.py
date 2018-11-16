# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

from rest_framework import serializers
from flowspec.models import (
    Route,
    Rule,
    MatchPort,
    MatchDscp,
    ThenAction,
    FragmentType,
    MatchProtocol
)
from flowspec.validators import (
    clean_source,
    clean_destination,
    clean_expires,
    clean_status,
    check_if_rule_exists
)


class PeerSerializer(serializers.HyperlinkedModelSerializer):
   pass

class RuleSerializer(serializers.HyperlinkedModelSerializer):
    """
    A serializer for `Rule` objects
    """
    applier = serializers.CharField(source='applier_username', read_only=True)

    def validate_expires(self, attrs, source):
        print("validate expires ")
        value = attrs[source]
        if not value:
            raise serializers.ValidationError('This field is required')
        res = clean_expires(value)
        if res != value:
            raise serializers.ValidationError(res)
        return attrs

    def validate_then(self, attrs, source):
        if not source:
            raise serializers.ValidationError('This field is required')
        return attrs

    def validate(self, data):
        user = self.context.get('request').user
        return data


    class Meta:
        model = Rule
        fields = (
            'name',
            'id',
            'comments',
            'applier',
            'then',
            'routes',
            'filed',
            'last_updated',
            'expires',
            'editing',
            'status',
            'requesters_address',
            'url',
            'response'
        )
        read_only_fields = ('requesters_address', 'response', 'filed', 'last_updated')

class RouteSerializer(serializers.HyperlinkedModelSerializer):
    """
    A serializer for `Route` objects
    """

    def validate_source(self, attrs, source):
        user = self.context.get('request').user
        source_ip = attrs.get('source')
        res = clean_source(user, source_ip)
        if res != source_ip:
            raise serializers.ValidationError(res)
        return attrs

    def validate_destination(self, attrs, source):
        user = self.context.get('request').user
        destination = attrs.get('destination')
        res = clean_destination(user, destination)
        if res != destination:
            raise serializers.ValidationError(res)
        return attrs

    def validate_expires(self, attrs, source):
        expires = attrs.get('expires')
        res = clean_expires(expires)
        if res != expires:
            raise serializers.ValidationError(res)
        return attrs

    def validate_status(self, attrs, source):
        status = attrs.get('status')
        res = clean_status(status)
        if res != status:
            raise serializers.ValidationError(res)
        return attrs

    class Meta:
        model = Route
        fields = (
            'name',
            'id',
            'rule',
            'source',
            'sourceport',
            'destination',
            'destinationport',
            'port',
            'dscp',
            'fragmenttype',
            'icmpcode',
            'packetlength',
            'protocol',
            'tcpflag',
            'response',
            'url',
            'deleted',
        )
        read_only_fields = ('response', 'id')


class PortSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = MatchPort
        fields = ('id', 'port', )
        read_only_fields = ('id', )


class ThenActionSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = ThenAction
        fields = ('id', 'action', 'action_value', 'url')
        read_only_fields = ('id', )


class FragmentTypeSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = FragmentType
        fields = ('id', 'fragmenttype', 'url')
        read_only_fields = ('id', )


class MatchProtocolSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = MatchProtocol
        fields = ('id', 'protocol', 'url')
        read_only_fields = ('id', )


class MatchDscpSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = MatchDscp
        fields = ('id', 'dscp', 'url')
        read_only_fields = ('id', )
