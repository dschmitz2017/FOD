from django.core.mail.message import EmailMessage
from django.conf import settings

import os
import logging

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def send_new_mail(subject, message, from_email, recipient_list, bcc_list):
  try:
    logger.info("helpers::send_new_mail(): send mail: from_email="+str(from_email)+", recipient_list="+str(recipient_list)+", bcc_list="+str(bcc_list)) 
    return EmailMessage(subject, message, from_email, recipient_list, bcc_list).send()
  except Exception, e:
    #os.write(3, "send_new_mail() failed: exc="+str(e)+"\n") 
    logger.error("helpers::send_new_mail() failed: exc="+str(e)) 

def get_peer_techc_mails(user, peer):
    logger.info("helpers::get_peer_techc_mails(): user="+str(user)+", peer="+str(peer))
    mail = []
    additional_mail = []
    techmails_list = []
    user_mail = '%s' % user.email
    user_mail = user_mail.split(';')
    techmails = []
    if peer:
        techmails = peer.techc_emails.all()
    if techmails:
        for techmail in techmails:
            techmails_list.append(techmail.email)
    if settings.NOTIFY_ADMIN_MAILS:
        additional_mail = settings.NOTIFY_ADMIN_MAILS
    mail.extend(additional_mail)
    mail.extend(techmails_list)
    logger.info("helpers::get_peer_techc_mails(): additional_mail="+str(additional_mail))
    logger.info("helpers::get_peer_techc_mails(): techmails_list="+str(techmails_list))
    return mail

def helper_list_unique(mylist):
  seen = set()
  return [x for x in mylist if not (x in seen or seen.add(x))]

def get_peer_techc_mails__multiple(user, peer_list):
    logger.info("helpers::get_peer_techc_mails__multiple(): user="+str(user)+", peer_list="+str(peer_list))
    mail = []
    additional_mail = []
    techmails_list = []
    user_mail = '%s' % user.email
    user_mail = user_mail.split(';')
    techmails = []
    if peer_list:
        for peer in peer_list:
            techmails = peer.techc_emails.all()
            if techmails:
                for techmail in techmails:
                    techmails_list.append(techmail.email)
    if settings.NOTIFY_ADMIN_MAILS:
        additional_mail = settings.NOTIFY_ADMIN_MAILS
    additional_mail=helper_list_unique(additional_mail)
    techmails_list=helper_list_unique(techmails_list)
    mail.extend(additional_mail)
    mail.extend(techmails_list)
    logger.info("helpers::get_peer_techc_mails__multiple(): additional_mail="+str(additional_mail))
    logger.info("helpers::get_peer_techc_mails__multiple(): techmails_list="+str(techmails_list))
    mail=helper_list_unique(mail)
    return mail

