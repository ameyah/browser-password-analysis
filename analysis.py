import sqlite3
from subprocess import Popen, PIPE
import platform
import commands
from collections import defaultdict
import os
from hashlib import md5
from tldextract import tldextract
from constants import *
from datetime import datetime


class Passwords:
    def __init__(self):
        self.conn = None
        self.os = None
        self.detect_os()
        self.password_domain_dict = defaultdict(set)
        self.domain_password_dict = defaultdict(set)
        self.domain_visits = defaultdict(list)
        self.domain_access_frequency = dict()
        self.unused_accounts = set()

    def detect_os(self):
        self.os = platform.system()
        if self.os == LINUX:
            self.os = platform.dist()[0]

    @staticmethod
    def get_url_domain(url):
        domain_obj = tldextract.extract(url)
        return "%s.%s" % (domain_obj.domain, domain_obj.suffix)

    def check_chrome_exists(self):
        if self.os == UBUNTU:
            p = Popen(['/usr/bin/which', 'google-chrome'], stdout=PIPE, stderr=PIPE)
            p.communicate()
            return p.returncode == 0

    def get_chrome_sqlite_login_data_path(self):
        # os.path.join(os.path.expandvars("%userprofile%"),"AppData\Local\Google\Chrome\User Data\Default\Login Data")
        '''
         c = conn.execute("SELECT password_value from logins LIMIT 1")
        >>> b = c.fetchall()
        >>> b
        [(<read-write buffer ptr 0x032D5988, size 230 at 0x032D5968>,)]
        >>> b[0]
        (<read-write buffer ptr 0x032D5988, size 230 at 0x032D5968>,)
        >>> b[0][0]
        <read-write buffer ptr 0x032D5988, size 230 at 0x032D5968>
        >>> s = str(b[0][0]).encode("hex")
        '''
        if self.os == UBUNTU:
            username = commands.getoutput("whoami")
            return "/home/" + username + "/.config/google-chrome/Default/Login Data" if self.check_chrome_exists() \
                else False
        elif self.os == WINDOWS:
            # currently not checking if chrome is installed, just return the Login Data path
            return os.path.join(os.path.expandvars("%userprofile%"),
                                "AppData\Local\Google\Chrome\User Data\Default\Login Data")

    def get_chrome_sqlite_history_path(self):
        if self.os == UBUNTU:
            username = commands.getoutput("whoami")
            return "/home/" + username + "/.config/google-chrome/Default/History" if self.check_chrome_exists() \
                else False
        elif self.os == WINDOWS:
            # currently not checking if chrome is installed, just return the Login Data path
            return os.path.join(os.path.expandvars("%userprofile%"),
                                "AppData\Local\Google\Chrome\User Data\Default\History")

    def get_sqlite_connection(self, path):
        self.conn = sqlite3.connect(path)

    def close_sqlite_connection(self):
        self.conn.close() if self.conn else None

    def execute_sqlite(self, sql):
        if self.conn is None:
            self.get_sqlite_connection(self.get_chrome_sqlite_login_data_path())
        try:
            return self.conn.execute(sql)
        except sqlite3.OperationalError:
            print "Please exit Google Chrome before running this script."
            exit()

    def store_passwords_domain(self, domain, password):
        self.password_domain_dict[password].add(domain)
        self.domain_password_dict[domain].add(password)
        # Remove from unused accounts when we find a visit that is within the last 90 days
        self.unused_accounts.add(domain)

    def get_chrome_passwords_sqlite_windows(self, login_data):
        import win32crypt

        for url, user_name, password in login_data:
            password = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
            domain = self.get_url_domain(url)
            password = md5(password).hexdigest()
            self.store_passwords_domain(domain, password)

    def get_chrome_passwords_sqlite(self):
        path = self.get_chrome_sqlite_login_data_path()
        self.get_sqlite_connection(path)
        sql = "SELECT COUNT(*) FROM logins"
        cursor = self.execute_sqlite(sql)
        count = cursor.fetchone()[0]
        if count == 0:
            return False
        sql = '''SELECT origin_url, username_value, password_value FROM logins WHERE origin_url != ""'''
        cursor = self.execute_sqlite(sql)
        login_data = cursor.fetchall()
        if self.os == WINDOWS:
            self.get_chrome_passwords_sqlite_windows(login_data)

    def get_chrome_passwords_keyring(self):
        import gnomekeyring

        for keyring in gnomekeyring.list_keyring_names_sync():
            if keyring != "login":
                continue
            for id in gnomekeyring.list_item_ids_sync(keyring):
                item = gnomekeyring.item_get_info_sync(keyring, id)
                attr = gnomekeyring.item_get_attributes_sync(keyring, id)
                if attr and 'username_value' in attr:
                    domain = self.get_url_domain(attr['origin_url'])
                    password = item.get_secret()
                    self.store_passwords_domain(domain, password)

    def get_chrome_history(self):
        path = self.get_chrome_sqlite_history_path()
        self.get_sqlite_connection(path)
        sql = '''select urls.url, (visit_time / 1000000 + (strftime('%s', '1601-01-01'))) visit_time from visits join
                    urls on visits.url = urls.id where urls.url != "" order by visit_time desc'''
        cursor = self.execute_sqlite(sql)
        history_data = cursor.fetchall()
        for history in history_data:
            domain = self.get_url_domain(history[0])
            if domain in self.domain_password_dict:
                visit_time = history[1]
                if len(self.domain_visits[domain]) == 0:
                    self.domain_visits[domain].append(visit_time)
                else:
                    prev_date = datetime.fromtimestamp(self.domain_visits[domain][-1])
                    prev_date = prev_date.date()
                    log_date = datetime.fromtimestamp(visit_time)
                    log_date = log_date.date()
                    if log_date < prev_date:
                        self.domain_visits[domain].append(visit_time)
                if domain in self.unused_accounts:
                    self.unused_accounts.remove(domain)

    def calculate_account_frequency(self):
        """
            frequency:
                3 => very frequent (at least once a day ~ weekday)
                2 => frequent (at least once a week)
                1 => intermittently
        """
        for domain in self.domain_visits:
            # determine very frequent access - 5 days out of 7 ~ 71% of days
            if len(self.domain_visits[domain]) == 0:
                continue
            start_date = datetime.fromtimestamp(self.domain_visits[domain][-1]).date()
            end_date = datetime.now().date()
            duration_of_access = float((end_date - start_date).days)
            days_accessed = float(len(self.domain_visits[domain]))
            try:
                access_frequency = float(days_accessed / duration_of_access)
            except ZeroDivisionError as _:
                self.domain_access_frequency[domain] = 1
                continue
            if access_frequency >= 0.71:
                self.domain_access_frequency[domain] = 3
                continue

            # determine frequent access
            prev_week_number = None
            frequency_set_flag = False
            for timestamp in reversed(self.domain_visits[domain]):
                week_number = int(datetime.fromtimestamp(timestamp).strftime("%V"))
                if prev_week_number is None:
                    prev_week_number = week_number
                else:
                    if week_number - prev_week_number == 1:
                        prev_week_number = week_number
                    elif week_number - prev_week_number > 1:
                        self.domain_access_frequency[domain] = 1
                        frequency_set_flag = True
                        break
            if not frequency_set_flag:
                self.domain_access_frequency[domain] = 2

    def print_basic_analyses(self):
        print "------------- Basic Analyses -------------"
        print "Reused passwords:"
        for password in self.password_domain_dict:
            print password + " => " + str(len(self.password_domain_dict[password]))
        print "\n\nUnused Accounts:"
        for account in self.unused_accounts:
            print account
        print "\n\nFrequency of access:"
        for domain in self.domain_access_frequency:
            if self.domain_access_frequency[domain] == 1:
                print domain + " => " + "Intermittently"
            elif self.domain_access_frequency[domain] == 2:
                print domain + " => " + "Frequent"
            else:
                print domain + " => " + "Very Frequent"

    def get_chrome_passwords(self):
        # if not self.check_chrome_exists():
        # return False

        self.get_chrome_passwords_sqlite()
        if len(self.password_domain_dict) == 0:
            self.get_chrome_passwords_keyring()
        self.close_sqlite_connection()
        self.get_chrome_history()
        self.calculate_account_frequency()
        self.print_basic_analyses()


if __name__ == '__main__':
    passwords_obj = Passwords()
    passwords_obj.get_chrome_passwords()