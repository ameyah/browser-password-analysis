# Analysis of Passwords stored by Google Chrome

## Purpose
A tool writen in Python to analyze password re-use, the frequency of website accesses, and password sharing
 between frequently and infrequently / rarely used websites. The tool could help users minimize password sharing and
 thus protect them from password attacks.

## How it works?
The tool works by obtaining stored passwords on the user's computer (in an encrypted form), analyzing passwords used by
users in their real life for verbatim re-use and sharing of passwords across websites.

The tool uses the encrypted passwords and browser history stored by Google Chrome browser on the user's computer.
It determines the frequency of access of a particular website using the browser history (stored on the user's computer
from the last 90 days) and then compares the encrypted passwords of frequently and infrequently used websites to
determine the website accounts where the user would benefit from a password reset.

## Features
The tool scans through the Chrome's locally stored encrypted passwords and locally stored history, and creates a summary
 of the following:
* Password re-use occurrences
* Unused Accounts within the past 90 days
* The frequency of use for each website visited within the past 90 days
* Unused and Rarely used accounts that share password with a frequently used website account

## Is the tool safe to use? Does it send my account information or the data it collects to anyone?
The tool doesn't share any information collected to anyone unless the user agrees to share the report for research purposes.
The tool does not have access to the user's plaintext passwords. Instead, it uses the passwords encrypted by Google
Chrome itself for doing all the analysis. It also performs all analysis on the users' machine - encrypted passwords are
never sent in the report.

The report includes counts of reused passwords and counts of sites. It also includes listing of sites in all categories,
 if they are also on Alexa's top 500 domains. Otherwise, just the counts of sites is shown in the report. The report is
 generated automatically by the tool, and users have the choice to see the report before sending it to us. The report
 is sent securely (HTTPS) and stored in a database for research purposes.

The report will contain **no** personally identifiable information or hints to identifying any user.

## How to run?
You can either run the tool from the source code, or by running the standalone distributions.

### Run from Source Code (Ubuntu)
Install Python and other supporting packages:

    $ sudo apt-get install python python-dev python-pip gcc libsqlite3-dev libssl-dev libffi-dev

Install Python modules

    $ sudo pip install -r requirements.txt

Run the tool by the following command:

    $ python analysis.py

### Run from standalone distributions
Standalone distributions are OS dependant. Please follow the instructions below as per your Operating System.

**Ubuntu and OS X**

Open terminal and navigate to dist_ubuntu/analysis (dist_os_x/analysis for OS X). Change the permissions of "analysis" file using the following command:

    $ chmod +x analysis

Then start the tool using the following command:

    $ ./analysis

**Windows**

Navigate to dist_windows/analysis, and run analysis.exe
