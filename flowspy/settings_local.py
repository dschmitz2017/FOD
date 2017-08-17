
##############################################################################
##############################################################################

import sys
print "loaded settings_local.py"

MYSETTING1 = "testsettings1"

#sys.exit

##############################################################################
##############################################################################

DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    ('AdminName', 'evangelos.spatharas@geant.org'),
)

MANAGERS = ADMINS

ALLOWED_HOSTS = ['*']
SITE_ID = 1

SECRET_KEY = '@@5234#$%345345^@#$%*()123^@12!&!()$JMNDF#$@(@#8FRNJWX_'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql', # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'fod',                      # Or path to database file if using sqlite3.
        'USER': 'fod',                      # Not used with sqlite3.
        'PASSWORD':  'asdfghjkl',                  # Not used with sqlite3.
        'HOST': '',                      # Set to empty string for localhost. Not used with sqlite3.
        'PORT': '',                      # Set to empty string for default. Not used with sqlite3.
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'Europe/Athens'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
_ = lambda s: s

LANGUAGES = (
    ('el', _('Greek')),
    ('en', _('English')),
)

STATIC_ROOT = '/srv/flowspy/static'

ROOT_URLCONF = 'flowspy.urls'
WSGI_APPLICATION = 'flowspy.wsgi.application'

# Netconf Device credentials
# The following variables should contain the address of the device with
# flowspec, the username and password of the appliers account and the netconf
# port.
NETCONF_DEVICE = "172.16.113.10"

NETCONF_USER = "fod"
NETCONF_PASS = "1v5CkNzfdEUG0mLTfbLABRfW5yiJTRTD"
NETCONF_PORT = 22

# Notifications
SERVER_EMAIL = "Geant FoD Service (TEST) <test@fod.geant.net>"
EMAIL_SUBJECT_PREFIX = "[FoD] "
EXPIRATION_NOTIFY_DAYS = 4
PREFIX_LENGTH = 29
POLL_SESSION_UPDATE = 60.0

#Shibboleth attribute map
SHIB_AUTH_ENTITLEMENT = ''
SHIB_ADMIN_DOMAIN = 'grnet.gr'
SHIB_LOGOUT_URL = 'https://test-fod.geant.net/Shibboleth.sso/Logout'

# BCC mail addresses
NOTIFY_ADMIN_MAILS = ["evangelos.spatharas@geant.org"]

# Then actions in the ui (dropdown)
UI_USER_THEN_ACTIONS = ['discard', 'rate-limit']
UI_USER_PROTOCOLS = ['icmp', 'tcp', 'udp']
ACCOUNT_ACTIVATION_DAYS = 7

# Define subnets that should not have any rules applied whatsoever
#PROTECTED_SUBNETS = ['10.10.0.0/16']
PROTECTED_SUBNETS = []
MAX_RULE_EXPIRE_DAYS = 10

# Add two whois servers in order to be able to get all the subnets for an AS.
PRIMARY_WHOIS = 'whois.ripe.net'
ALTERNATE_WHOIS = 'whois.ripe.net'
# results in exceptions:
#ALTERNATE_WHOIS = 'whois.example.net'

LOG_FILE_LOCATION = "/var/log/fod"

BRANDING = {
    'name': 'Example',
    'url': 'https://example.com',
    'footer_iframe': 'https://example.com/iframe',
    'facebook': '//facebook.com/',
    'twitter': '//twitter.com/',
    'phone': '800-example-com',
    'email': 'helpdesk@example.com',
    'logo': 'fodlogo2.png',
    'favicon': 'favicon.ico',
}

# Limit of ports in 'ports' / 'SrcPorts' / 'DstPorts' of a rule:
PORTRANGE_LIMIT = 100

SNMP_COMMUNITY = "0pBiFbD"
SNMP_IP = ["172.16.113.10",
            #"172.16.113.12",
            "172.16.113.14",
            "172.16.113.16"]

# currently unused
SNMP_CNTBYTES =     "1.3.6.1.4.1.2636.3.5.2.1.5"
SNMP_CNTPACKETS =   "1.3.6.1.4.1.2636.3.5.2.1.4"

# get only statistics of specified tables
SNMP_RULESFILTER = ["__flowspec_default_inet__", "__flowspec_IAS_inet__"]
# load new data into cache if it is older that a specified number of seconds
SNMP_POLL_INTERVAL = 8 #seconds
# cache file for data
SNMP_TEMP_FILE = "/tmp/snmp_temp_data"

# Number of historical values to store for a route.
# Polling interval must be set for "snmp-stats-poll" celery task in CELERYBEAT_SCHEDULE.
# By default, it is 5 min interval, so SNMP_MAX_SAMPLECOUNT=12 means we have about
# one hour history.
SNMP_MAX_SAMPLECOUNT = 12

# Age of inactive routes that can be already removed (in seconds)
SNMP_REMOVE_RULES_AFTER = 3600



##############################################################################
##############################################################################

