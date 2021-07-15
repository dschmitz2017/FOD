+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
| REPORT                                                                       |
| checked 67 packages, using free DB (updated once a month)                    |
+============================+===========+==========================+==========+
| package                    | installed | affected                 | ID       |
+============================+===========+==========================+==========+
| pycrypto                   | 2.6.1     | <=2.6.1                  | 35015    |
+==============================================================================+
| Heap-based buffer overflow in the ALGnew function in block_templace.c in     |
| Python Cryptography Toolkit (aka pycrypto) 2.6.1 allows remote attackers to  |
| execute arbitrary code as demonstrated by a crafted iv parameter to          |
| cryptmsg.py.                                                                 |
+==============================================================================+
| django                     | 2.1.15    | >=2.0.0a1,<2.2.24        | 40637    |
+==============================================================================+
| Django before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4 has a        |
| potential directory traversal via django.contrib.admindocs. Staff members    |
| could use the TemplateDetailView view to check the existence of arbitrary    |
| files. Additionally, if (and only if) the default admindocs templates have   |
| been customized by application developers to also show file contents, then   |
| not only the existence but also the file contents would have been exposed.   |
| In other words, there is directory traversal outside of the template root    |
| directories.                                                                 |
+==============================================================================+
| django                     | 2.1.15    | >=2.0a1,<2.2.9           | 37771    |
+==============================================================================+
| Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account |
| takeover. A suitably crafted email address (that is equal to an existing     |
| user's email address after case transformation of Unicode characters) would  |
| allow an attacker to be sent a password reset token for the matched user     |
| account. (One mitigation in the new releases is to send password reset       |
| tokens only to the registered user email address.) See CVE-2019-19844.       |
+==============================================================================+
| django-registration        | 3.0.1     | <3.1.2                   | 40136    |
+==============================================================================+
| django-registration is a user registration package for Django. The django-   |
| registration package provides tools for implementing user-account            |
| registration flows in the Django web framework. In django-registration prior |
| to 3.1.2, the base user-account registration view did not properly apply     |
| filters to sensitive data, with the result that sensitive data could be      |
| included in error reports rather than removed automatically by Django.       |
| Triggering this requires: A site is using django-registration < 3.1.2, The   |
| site has detailed error reports (such as Django's emailed error reports to   |
| site staff/developers) enabled and a server-side error (HTTP 5xx) occurs     |
| during an attempt by a user to register an account. Under these conditions,  |
| recipients of the detailed error report will see all submitted data from the |
| account-registration attempt, which may include the user's proposed          |
| credentials (such as a password). See CVE-2021-21416.                        |
+==============================================================================+