# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

from django.conf import settings

if not hasattr(settings, "PROXY_CLASS") or settings.PROXY_CLASS == "proxy_netconf_junos":
  from utils import proxy_netconf_junos as PR0
elif settings.PROXY_CLASS == "proxy_exabgp":
  from utils import proxy_exabgp as PR0


