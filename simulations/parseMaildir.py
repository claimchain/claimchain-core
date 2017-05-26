# Enron Email Dataset parse script
# Builds upon "traces-messages" by Carmela Troncoso https://github.com/carmelatroncoso/traces-messages

import email
import hashlib
import heapq
import os
import re
import time
import pickle

import logging

logging.basicConfig(level=logging.DEBUG)  # Set to .DEBUG for gory details

# Regex for emails
email_pattern = re.compile('[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


def processEnron(root_folder="Enron/maildir/", parsed_folder="Enron/parsing/"):
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

    social = []
    recipients_per_email = {}

    for username in os.listdir(root_folder):
        logging.info("Parsing user: %s", username)
        # check that this user was not already parsed
        if os.path.exists(parsed_folder + username + '.txt'):
            logging.debug("User %s was already parsed", username)

        seen_msgs = []  # Create list to detect duplicate messages
        rset = set([]) # Create relationship set for user

        sent_folders = [folder for folder in os.listdir(root_folder + '/' + username) if
                       'sent' in folder]  # Only process files with sent messages

        # Ignore users that don't have a sent folder
        if len(sent_folders) == 0:
            continue

        '''
        Uncomment for ignoring users with less than 20 sent messages
        # Only process user if there are more than 20 sent messages
        counter = 0
        for folder in sent_folders:
            counter += len(os.listdir(root_folder+'/'+user_folder+'/'+folder))
        if counter < 20:
            logging.info('User %s does not have enough sent messages', user_folder)
            continue
        '''

        for folder in sent_folders:

            for dirpath, _, filenames in os.walk(root_folder + '/' + username + '/' + folder):
                for filename in filenames:

                    f = open(os.path.join(dirpath, filename), 'r')
                    full_message = f.read()
                    msg_content = email.message_from_string(full_message)

                    # Ignore duplicate messages
                    try:
                        aux_string = msg_content['Message-ID']
                        mID = int(hashlib.sha1(aux_string.lower()).hexdigest(), 16)
                        if mID in seen_msgs:
                            print ('*',)
                            continue
                    except:
                        mID = 'there is no Message-ID'

                    # ReplyTo
                    try:
                        auxstring = msg_content['In-Reply-to']
                        mReplyTo = int(hashlib.sha1(auxstring.lower()).hexdigest(), 16)
                    except:
                        mReplyTo = 'there is no ReplyTo'

                    # time
                    try:
                        mtime = time.mktime(email.utils.parsedate(msg_content['date']))
                    except:
                        mtime = 'there is no date'


                    # receiversID
                    # To and X-to field
                    tListTo = []
                    field = "%s %s" % (msg_content['to'], msg_content['X-to'])
                    try:
                        field = email_pattern.findall(field)
                        for e in field:
                            tListTo += [e.lower()]
                            rset.add(e.lower())
                        mReceiversID = [int(hashlib.sha1(rec).hexdigest(), 16) for rec in tListTo]

                    except:
                        mReceiversID = 'there is no To'

                    # CC and X-cc field
                    tListCc = []
                    try:
                        field = "%s %s" % (msg_content['cc'], msg_content['X-cc'])
                        field = email_pattern.findall(field)
                        for e in field:
                            tListCc += [e.lower()]
                            rset.add(e.lower())
                        mCCID = [int(hashlib.sha1(rec).hexdigest(), 16) for rec in tListCc]
                    except:
                        mCCID = 'there is no CC'

                    if cnt_msgs % 1000 == 0:
                        logging.debug('Parsing message %d', cnt_msgs)

                    seen_msgs += [mID]  # Update the list of duplicates

                    cnt_msgs += 1 # Increment the message counter

                    if msg_content['X-bcc']:
                        logging.debug("found email with bcc")

                    # Compose a unique set with the recipients of this mail
                    tSet = set(tListTo) | set(tListCc)

                    if len(tSet) == 0:
                        cnt_msgs_no_recipients += 1
                        logging.debug("found email without name@domain.xz recipients")
                        continue

                    if len(tSet) not in recipients_per_email:
                        recipients_per_email[len(tSet)] = 1
                    else:
                        recipients_per_email[len(tSet)] += 1

        # When all messages for one user are parsed, store the log
        outputfile = parsed_folder + username

        # Store data in hard drive
        f = open(outputfile + '.txt', 'w')

        f.write('Friends:\n')
        for r in rset:
            f.write(r + ' ')

        s = '\nNum of Friends: %s\n' % (len(rset))
        f.write(s)
        f.close()

        social += [{'user': username, 'friends': rset, 'numOfFriends': len(rset)}]

    pickle.dump(social, open(parsed_folder + "social.pkl", "wb"))
    pickle.dump(recipients_per_email, open(parsed_folder + "recipients.pkl", "wb"))

    return social, recipients_per_email, cnt_msgs, cnt_msgs_no_recipients


def main():
    _, _, cnt_msgs, cnt_msgs_no_recipients = processEnron()
    print "Parsed %s messages, discarded %s" % (cnt_msgs, cnt_msgs_no_recipients)


if __name__ == "__main__":
    main()
