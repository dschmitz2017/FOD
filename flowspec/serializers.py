# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

from rest_framework import serializers
from flowspec.models import (
    Route,
    Rule,
    MatchPort,
    ThenAction,
    FragmentType,
    MatchProtocol
)
from flowspec.validators import (
    clean_source,
    clean_destination,
    clean_expires,
    check_if_rule_exists
)


class PeerSerializer(serializers.HyperlinkedModelSerializer):
   pass

class RuleSerializer(serializers.HyperlinkedModelSerializer):
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
            'status',
            'requesters_address',
            'url'
        )
        read_only_fields = ('requesters_address', )

class RouteSerializer(serializers.HyperlinkedModelSerializer):

    def validate(self, data):
        user = self.context.get('request').user
        # validate source
        source = data.get('source')
        res = clean_source(
            user,
            source
        )
        if res != source:
            raise serializers.ValidationError(res)

        # validate destination
        destination = data.get('destination')
        res = clean_destination(
            user,
            destination
        )
        if res != destination:
            raise serializers.ValidationError(res)

        # check if rule already exists with different name
        fields = {
            'source': data.get('source'),
            'destination': data.get('destination'),
        }
        exists = check_if_rule_exists(fields)
        if exists:
            raise serializers.ValidationError(exists)
        return data

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
        )
        read_only_fields = ('response', 'id')


class PortSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = MatchPort
        fields = ('port', )


class ThenActionSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = ThenAction
        fields = ('action', 'action_value')


class FragmentTypeSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = FragmentType
        fields = ('fragmenttype', )


class MatchProtocolSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = MatchProtocol
        fields = ('protocol', )
