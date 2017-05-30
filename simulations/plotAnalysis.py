import pickle

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

parsedLogsFolder = 'Enron/parsing/'
social = pickle.load(open(parsedLogsFolder + "social.pkl", "rb"))
recipientsPerEmail = pickle.load(open(parsedLogsFolder + "recipients.pkl", "rb"))


def to_percent(y, position):
    # Ignore the passed in position. This has the effect of scaling the default
    # tick locations.
    s = str(100 * y)

    # The percent symbol needs escaping in latex
    if plt.rcParams['text.usetex'] is True:
        return s + r'$\%$'
    else:
        return s + '%'


def plot_friends_histogram():

    data = []
    for user in social:
        data.append(user.get("numOfFriends"))

    # Create the formatter using the function to_percent. This multiplies all the
    # default labels by 100, making them all percentages
    formatter = FuncFormatter(to_percent)

    # Set the formatter
    #plt.gca().yaxis.set_major_formatter(formatter)

    #plt.xscale('log')

    plt.hist(data)
    plt.show()


def plot_recipients_histogram():
    data = []

    for numOfRecipients in recipientsPerEmail:
        data.append(numOfRecipients)

    plt.hist(data)
    plt.show()


def main():
    plot_friends_histogram()
    plot_recipients_histogram()

if __name__ == "__main__":
    main()