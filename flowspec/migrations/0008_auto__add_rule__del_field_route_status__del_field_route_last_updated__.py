# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Rule'
        db.create_table(u'flowspec_rule', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.SlugField')(max_length=128)),
            ('applier', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True, blank=True)),
            ('filed', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now_add=True, blank=True)),
            ('last_updated', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime.now, auto_now=True, blank=True)),
            ('comments', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('requesters_address', self.gf('django.db.models.fields.CharField')(max_length=255, null=True, blank=True)),
            ('expires', self.gf('django.db.models.fields.DateField')(default=datetime.datetime(2018, 7, 10, 0, 0))),
            ('status', self.gf('django.db.models.fields.CharField')(default='INACTIVE', max_length=20, null=True, blank=True)),
        ))
        db.send_create_signal('flowspec', ['Rule'])

        # Adding M2M table for field then on 'Rule'
        db.create_table(u'flowspec_rule_then', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('rule', models.ForeignKey(orm['flowspec.rule'], null=False)),
            ('thenaction', models.ForeignKey(orm['flowspec.thenaction'], null=False))
        ))
        db.create_unique(u'flowspec_rule_then', ['rule_id', 'thenaction_id'])

        # Deleting field 'Route.status'
        db.delete_column(u'route', 'status')

        # Deleting field 'Route.last_updated'
        db.delete_column(u'route', 'last_updated')

        # Deleting field 'Route.requesters_address'
        db.delete_column(u'route', 'requesters_address')

        # Deleting field 'Route.expires'
        db.delete_column(u'route', 'expires')

        # Deleting field 'Route.filed'
        db.delete_column(u'route', 'filed')

        # Deleting field 'Route.applier'
        db.delete_column(u'route', 'applier_id')

        # Adding field 'Route.rule'
        db.add_column(u'route', 'rule',
                      self.gf('django.db.models.fields.related.ForeignKey')(related_name='routes', null=True, to=orm['flowspec.Rule']),
                      keep_default=False)

        # Removing M2M table for field then on 'Route'
        db.delete_table('route_then')


        # Changing field 'Route.destinationport'
        db.alter_column(u'route', 'destinationport', self.gf('django.db.models.fields.CharField')(max_length=65535, null=True))

        # Changing field 'Route.sourceport'
        db.alter_column(u'route', 'sourceport', self.gf('django.db.models.fields.CharField')(max_length=65535, null=True))

        # Changing field 'Route.port'
        db.alter_column(u'route', 'port', self.gf('django.db.models.fields.CharField')(max_length=65535, null=True))

    def backwards(self, orm):
        # Deleting model 'Rule'
        db.delete_table(u'flowspec_rule')

        # Removing M2M table for field then on 'Rule'
        db.delete_table('flowspec_rule_then')

        # Adding field 'Route.status'
        db.add_column(u'route', 'status',
                      self.gf('django.db.models.fields.CharField')(default='PENDING', max_length=20, null=True, blank=True),
                      keep_default=False)


        # User chose to not deal with backwards NULL issues for 'Route.last_updated'
        raise RuntimeError("Cannot reverse this migration. 'Route.last_updated' and its values cannot be restored.")
        # Adding field 'Route.requesters_address'
        db.add_column(u'route', 'requesters_address',
                      self.gf('django.db.models.fields.CharField')(max_length=255, null=True, blank=True),
                      keep_default=False)

        # Adding field 'Route.expires'
        db.add_column(u'route', 'expires',
                      self.gf('django.db.models.fields.DateField')(default=datetime.datetime(2017, 2, 8, 0, 0)),
                      keep_default=False)


        # User chose to not deal with backwards NULL issues for 'Route.filed'
        raise RuntimeError("Cannot reverse this migration. 'Route.filed' and its values cannot be restored.")
        # Adding field 'Route.applier'
        db.add_column(u'route', 'applier',
                      self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True, blank=True),
                      keep_default=False)

        # Deleting field 'Route.rule'
        db.delete_column(u'route', 'rule_id')

        # Adding M2M table for field then on 'Route'
        db.create_table(u'route_then', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('route', models.ForeignKey(orm['flowspec.route'], null=False)),
            ('thenaction', models.ForeignKey(orm['flowspec.thenaction'], null=False))
        ))
        db.create_unique(u'route_then', ['route_id', 'thenaction_id'])


        # Changing field 'Route.destinationport'
        db.alter_column(u'route', 'destinationport', self.gf('django.db.models.fields.CharField')(max_length=50, null=True))

        # Changing field 'Route.sourceport'
        db.alter_column(u'route', 'sourceport', self.gf('django.db.models.fields.CharField')(max_length=50, null=True))

        # Changing field 'Route.port'
        db.alter_column(u'route', 'port', self.gf('django.db.models.fields.CharField')(max_length=50, null=True))

    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')", 'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '255'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'flowspec.fragmenttype': {
            'Meta': {'object_name': 'FragmentType'},
            'fragmenttype': ('django.db.models.fields.CharField', [], {'max_length': '20'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'})
        },
        'flowspec.matchdscp': {
            'Meta': {'object_name': 'MatchDscp', 'db_table': "u'match_dscp'"},
            'dscp': ('django.db.models.fields.CharField', [], {'max_length': '24'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'})
        },
        'flowspec.matchport': {
            'Meta': {'object_name': 'MatchPort', 'db_table': "u'match_port'"},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'port': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '24'})
        },
        'flowspec.matchprotocol': {
            'Meta': {'object_name': 'MatchProtocol', 'db_table': "u'match_protocol'"},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'protocol': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '24'})
        },
        'flowspec.route': {
            'Meta': {'object_name': 'Route', 'db_table': "u'route'"},
            'comments': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'destination': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'destinationport': ('django.db.models.fields.CharField', [], {'max_length': '65535', 'null': 'True', 'blank': 'True'}),
            'dscp': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['flowspec.MatchDscp']", 'null': 'True', 'blank': 'True'}),
            'fragmenttype': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['flowspec.FragmentType']", 'null': 'True', 'blank': 'True'}),
            'icmpcode': ('django.db.models.fields.CharField', [], {'max_length': '32', 'null': 'True', 'blank': 'True'}),
            'icmptype': ('django.db.models.fields.CharField', [], {'max_length': '32', 'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.SlugField', [], {'max_length': '128'}),
            'packetlength': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            'port': ('django.db.models.fields.CharField', [], {'max_length': '65535', 'null': 'True', 'blank': 'True'}),
            'protocol': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['flowspec.MatchProtocol']", 'null': 'True', 'blank': 'True'}),
            'response': ('django.db.models.fields.CharField', [], {'max_length': '512', 'null': 'True', 'blank': 'True'}),
            'rule': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'routes'", 'null': 'True', 'to': "orm['flowspec.Rule']"}),
            'source': ('django.db.models.fields.CharField', [], {'max_length': '32'}),
            'sourceport': ('django.db.models.fields.CharField', [], {'max_length': '65535', 'null': 'True', 'blank': 'True'}),
            'tcpflag': ('django.db.models.fields.CharField', [], {'max_length': '128', 'null': 'True', 'blank': 'True'})
        },
        'flowspec.rule': {
            'Meta': {'object_name': 'Rule'},
            'applier': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']", 'null': 'True', 'blank': 'True'}),
            'comments': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'expires': ('django.db.models.fields.DateField', [], {'default': 'datetime.datetime(2018, 7, 10, 0, 0)'}),
            'filed': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now_add': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'last_updated': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now', 'auto_now': 'True', 'blank': 'True'}),
            'name': ('django.db.models.fields.SlugField', [], {'max_length': '128'}),
            'requesters_address': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'status': ('django.db.models.fields.CharField', [], {'default': "'INACTIVE'", 'max_length': '20', 'null': 'True', 'blank': 'True'}),
            'then': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['flowspec.ThenAction']", 'symmetrical': 'False'})
        },
        'flowspec.thenaction': {
            'Meta': {'ordering': "['action', 'action_value']", 'unique_together': "(('action', 'action_value'),)", 'object_name': 'ThenAction', 'db_table': "u'then_action'"},
            'action': ('django.db.models.fields.CharField', [], {'max_length': '60'}),
            'action_value': ('django.db.models.fields.CharField', [], {'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'})
        }
    }

    complete_apps = ['flowspec']