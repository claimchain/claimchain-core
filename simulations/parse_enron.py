# Enron Email Dataset parse script
# Builds upon "traces-messages" by Carmela Troncoso https://github.com/carmelatroncoso/traces-messages

import email
import hashlib
import os
import re
import time
import pickle
import logging

from attr import attrs, attrib


logging.basicConfig(level=logging.INFO)  # Set to .DEBUG for gory details

# Regex for emails
email_pattern = re.compile('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


@attrs
class Message:
    '''Class to keep sender, timestamp, public (To/Cc) and hidden (Bcc) recipients of a message

    Must map the Message class fields in parseMaildir.py for deserialization purposes
    '''
    From = attrib()
    mtime = attrib()
    To = attrib()
    Cc = attrib()
    Bcc = attrib()


def parse_mail(dirpath, filename):
    try:

        f = open(os.path.join(dirpath, filename), 'r')
        full_message = f.read()
        msg_content = email.message_from_string(full_message)
    except:
        raise Exception("Could not decode email, will discard")

    # time
    try:
        mtime = time.mktime(email.utils.parsedate(msg_content['date']))
    except:
        logging.info("Found email without date, will ignore")
        return

    # Ignore duplicate messages
    try:
        #aux_string = msg_content['Message-ID']
        aux_string = str(mtime) + msg_content['From']
        mID = int(hashlib.sha1(aux_string.lower().encode('utf-8')).hexdigest(), 16)
    except:
        raise Exception("Found email without mID")

    try:
        mail = Message(msg_content['From'], mtime, set(), set(), set())
        mail.From = email_pattern.match(mail.From).group(0)
    except:
        raise Exception('Could not parse From header')

    # receiversID
    # To and X-to field
    field = "%s %s" % (msg_content['To'], msg_content['X-to'])
    try:
        field = email_pattern.findall(field)
        for e in field:
            if e.startswith("imceanotes"):
                continue
            mail.To.add(e.strip(' \t\n\r<>').lower())
    except:
        pass

    # CC and X-cc field
    field = "%s %s" % (msg_content['Cc'], msg_content['X-cc'])
    try:
        field = email_pattern.findall(field)
        for e in field:
            if e.startswith("imceanotes"):
                continue
            mail.Cc.add(e.strip(' \t\n\r<>').lower())
    except:
        pass

    # Bcc and X-Bcc field
    field = "%s %s" % (msg_content['Bcc'], msg_content['X-bcc'])
    try:
        field = email_pattern.findall(field)
        for e in field:
            if e.startswith("imceanotes"):
                continue
            mail.Bcc.add(e.strip(' \t\n\r<>').lower())
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
    emails_per_num_of_recipients = {}

    mail_list = []
    seen_msgs = []  # Create list to detect duplicate messages

    for username in os.listdir(root_folder):
        logging.info("Parsing sent folders of user: %s", username)

        r_set = set([]) # Create relationship set for user
        from_headers_list = []

        sent_folders = [folder for folder in os.listdir(root_folder + username) if
                       'sent' in folder]  # Only process files with sent messages

        if len(sent_folders) == 0:
            continue

        '''
        Uncomment for ignoring users who don't have a Sent directory, or have less than 20 sent messages
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
                    cnt_msgs += 1 # Increment the message counter
                    if cnt_msgs % 1000 == 0:
                        logging.info('Parsing message %d', cnt_msgs)

                    try:
                        mail, mID = parse_mail(dirpath, filename)
                    except Exception as e:
                        logging.debug("Discard message: " + str(e))
                        continue

                    if mID in seen_msgs:
                        logging.debug("Found duplicate email")
                        cnt_msgs_dup += 1
                        continue

                    seen_msgs += [mID]  # Update the list of duplicates

                    # Compose a unique set with the public recipients of this mail
                    t_set = mail.To | mail.Cc | mail.Bcc

                    from_headers_list.append(mail.From)

                    if len(t_set) == 0:
                        cnt_msgs_no_recipients += 1
                        logging.debug("Found email without public name@domain.xz recipients")
                        continue

                    # Increment the counter of emails with the same number of public recipients
                    if len(t_set) not in emails_per_num_of_recipients:
                        emails_per_num_of_recipients[len(t_set)] = 1
                    else:
                        emails_per_num_of_recipients[len(t_set)] += 1

                    # Add the public recipients of this email to the relationship set of the user
                    r_set |= t_set

                    # Append the email to
                    mail_list.append(mail)

        from_headers_set = set(from_headers_list)

        if len(from_headers_set) == 0:
            logging.info("User %s had no sent emails" % (username))
            continue;
        if len(from_headers_set) > 1:
            logging.info("User %s is using multiple From headers:%s" % (username, from_headers_set))

        most_used_from_header = max(from_headers_set, key=from_headers_list.count)

        # Log the social graph of the user
        social[most_used_from_header] = {'user': username, 'friends': r_set, 'num_of_friends': len(r_set),
                                         'from_headers_set': from_headers_set}

    for username in os.listdir(root_folder):
        logging.info("Parsing inbox folders of user: %s", username)

        received_folders = [folder for folder in os.listdir(root_folder + username) if
                       'sent' not in folder]  # Parse emails in other directories

        for folder in received_folders:
            for dirpath, _, filenames in os.walk(root_folder + username + '/' + folder):
                for filename in filenames:
                    cnt_msgs += 1  # Increment the message counter
                    if cnt_msgs % 1000 == 0:
                        logging.info('Parsing message %d', cnt_msgs)

                    try:
                        mail, mID = parse_mail(dirpath, filename)
                    except Exception as e:
                        logging.debug("Discard message: " + str(e))
                        cnt_msgs_invalid += 1
                        continue

                    if mID in seen_msgs:
                        logging.debug("Found duplicate email")
                        cnt_msgs_dup += 1
                        continue

                    seen_msgs += [mID]  # Update the list of duplicates

                    mail_list.append(mail)

    logging.info("Writing pickle files...")

    # Sort by date all parsed emails
    mail_list.sort(key=lambda x: x.mtime)

    pickle.dump(social, open(parsed_folder + "social.pkl", "wb"))
    pickle.dump(emails_per_num_of_recipients, open(parsed_folder + "recipients.pkl", "wb"))
    pickle.dump(mail_list, open(parsed_folder + "replay_log.pkl", "wb"))

    return social, emails_per_num_of_recipients, cnt_msgs, cnt_msgs_no_recipients, cnt_msgs_dup, cnt_msgs_invalid


def main():
    _, _, cnt_msgs, cnt_msgs_no_recipients, cnt_msgs_dup, cnt_msgs_invalid = process_enron()
    print("Parsed %s messages, discarded %s because they had no valid recipient email address, %s because they were "
          "duplicate, and %s because they could not be parsed."
          % (cnt_msgs, cnt_msgs_no_recipients, cnt_msgs_dup, cnt_msgs_invalid))


if __name__ == "__main__":
    main()
