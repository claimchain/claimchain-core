# Enron Email Dataset parse script
# Builds upon "traces-messages" by Carmela Troncoso https://github.com/carmelatroncoso/traces-messages

import email
import hashlib
import os
import re
import time
import pickle

import logging

logging.basicConfig(level=logging.INFO)  # Set to .DEBUG for gory details

# Regex for emails
email_pattern = re.compile('[^imceanotes][a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


class Message:
    def __init__(self, From, mtime, To, Cc, Bcc):
        self.From = From
        self.mtime = mtime
        self.To = To
        self.Cc = Cc
        self.Bcc = Bcc


def parse_mail(dirpath, filename):
    try:

        f = open(os.path.join(dirpath, filename), 'r')
        full_message = f.read()
        msg_content = email.message_from_string(full_message)
    except:
        raise Exception("Could not decode email, will discard")

    # Ignore duplicate messages
    try:
        aux_string = msg_content['Message-ID']
        mID = int(hashlib.sha1(aux_string.lower().encode('utf-8')).hexdigest(), 16)
    except:
        raise Exception("Found email without mID")

    # time
    try:
        mtime = time.mktime(email.utils.parsedate(msg_content['date']))
    except:
        mtime = 'there is no date'
        logging.info("found email without date, will ignore")
        return

    mail = Message(msg_content['From'], mtime, set(), set(), set())

    # receiversID
    # To and X-to field
    field = "%s %s" % (msg_content['To'], msg_content['X-to'])
    try:
        field = email_pattern.findall(field)
        for e in field:
            mail.To.add(e.lower())
    except:
        pass

    # CC and X-cc field
    field = "%s %s" % (msg_content['Cc'], msg_content['X-cc'])
    try:
        field = email_pattern.findall(field)
        for e in field:
            mail.Cc.add(e.lower())
    except:
        pass

    # Bcc and X-Bcc field
    field = "%s %s" % (msg_content['Bcc'], msg_content['X-bcc'])
    try:
        field = email_pattern.findall(field)
        for e in field:
            mail.Bcc.add(e.lower())
    except:
        pass

    return mail, mID


def process_enron(root_folder="Enron/maildir/", parsed_folder="Enron/parsing/"):
    ####################################################################
    ##        SAMPLE EMAIL FROM ENRON DATASET (fields of interest)
    ##
    ##        Message-ID: <2901330.1075859176788.JavaMail.evans@thyme>
    ##        Date: Tue, 18 Sep 2001 09:24:04 -0700 (PDT)
    ##        From: jaime.gualy@enron.com
    ##        To: w..white@enron.com
    ##        Subject: New NatGas Portfolios/Books
    ##        Cc: robert.stalford@enron.com, harry.arora@enron.com
    ##        Mime-Version: 1.0
    ##        Content-Type: text/plain; charset=us-ascii
    ##        Content-Transfer-Encoding: 7bit
    ##        Bcc: robert.stalford@enron.com, harry.arora@enron.com
    ####################################################################

    # Create/open dir in which logs are to be stored
    if not os.path.exists(parsed_folder):
        os.makedirs(parsed_folder)

    cnt_msgs = 0
    cnt_msgs_no_recipients = 0
    cnt_msgs_invalid = 0
    cnt_msgs_dup = 0

    social = {}
    recipients_per_email = {}

    mail_list = []
    seen_msgs = []  # Create list to detect duplicate messages

    for username in os.listdir(root_folder):
        logging.debug("Parsing user: %s", username)
        # check that this user was not already parsed
        if os.path.exists(parsed_folder + username + '.txt'):
            logging.debug("User %s was already parsed", username)

        rset = set([]) # Create relationship set for user
        from_headers_list = []

        sent_folders = [folder for folder in os.listdir(root_folder + username) if
                       'sent' in folder]  # Only process files with sent messages

        '''
        Uncomment for ignoring users who don't have a Sent directory, or have less than 20 sent messages
        if len(sent_folders) == 0:
            continue
        
        counter = 0
        for folder in sent_folders:
            counter += len(os.listdir(root_folder+'/'+user_folder+'/'+folder))
        if counter < 20:
            logging.info('User %s does not have enough sent messages', user_folder)
            continue
        '''

        for folder in sent_folders:
            for dirpath, _, filenames in os.walk(root_folder + username + '/' + folder):
                for filename in filenames:
                    if cnt_msgs % 1000 == 0:
                        logging.debug('Parsing message %d', cnt_msgs)

                    try:
                        mail, mID = parse_mail(dirpath, filename)
                    except Exception as e:
                        logging.debug("Discard message: " + str(e))
                        continue

                    if mID in seen_msgs:
                        logging.info("Found duplicate email")
                        cnt_msgs_dup += 1
                        continue

                    seen_msgs += [mID]  # Update the list of duplicates
                    cnt_msgs += 1 # Increment the message counter

                    # Compose a unique set with the public recipients of this mail
                    tSet = mail.To | mail.Cc

                    from_headers_list.append(mail.From)

                    if len(tSet) == 0:
                        cnt_msgs_no_recipients += 1
                        logging.debug("found email without public name@domain.xz recipients")
                        continue

                    # Increment the counter of emails with the same number of public recipients
                    if len(tSet) not in recipients_per_email:
                        recipients_per_email[len(tSet)] = 1
                    else:
                        recipients_per_email[len(tSet)] += 1

                    # Add the public recipients of this email to the relationship set of the user
                    rset |= tSet

                    # Append the email to
                    mail_list.append(mail)

        from_headers_set = set(from_headers_list)
        if len(from_headers_set) > 1:
            logging.info("User %s is using multiple From headers:%s" % (username, from_headers_set))

        most_used_from_header = max(from_headers_set, key=from_headers_list.count)

        # Log the social graph of the user
        social[most_used_from_header] = {'user': username, 'friends': rset, 'num_of_friends': len(rset),
                                         'from_headers_set': from_headers_set}

        received_folders = [folder for folder in os.listdir(root_folder + username) if
                       'sent' not in folder]  # Parse emails in other directories
        for folder in received_folders:
            for dirpath, _, filenames in os.walk(root_folder + username + '/' + folder):
                for filename in filenames:
                    if cnt_msgs % 1000 == 0:
                        logging.debug('Parsing message %d', cnt_msgs)

                    try:
                        mail, mID = parse_mail(dirpath, filename)
                    except Exception as e:
                        logging.debug("Discard message: " + str(e))
                        cnt_msgs_invalid += 1
                        continue

                    if mID in seen_msgs:
                        logging.info("Found duplicate email")
                        cnt_msgs_dup += 1
                        continue

                    seen_msgs += [mID]  # Update the list of duplicates
                    cnt_msgs += 1  # Increment the message counter

                    mail_list.append(mail)

    logging.info("Writing pickle files...")

    # Sort by date all parsed emails
    mail_list.sort(key=lambda x: x.mtime)

    pickle.dump(social, open(parsed_folder + "social.pkl", "wb"))
    pickle.dump(recipients_per_email, open(parsed_folder + "recipients.pkl", "wb"))
    pickle.dump(mail_list, open(parsed_folder + "replay_log.pkl", "wb"))

    return social, recipients_per_email, cnt_msgs, cnt_msgs_no_recipients


def main():
    _, _, cnt_msgs, cnt_msgs_no_recipients = process_enron()
    print("Parsed %s messages, discarded %s because they had no valid recipient email address."
           % (cnt_msgs, cnt_msgs_no_recipients))


if __name__ == "__main__":
    main()
