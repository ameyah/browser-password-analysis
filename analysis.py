import sqlite3
from subprocess import Popen, PIPE
import platform
import commands
from collections import defaultdict
import os
from hashlib import md5, sha512
from tldextract import tldextract
from constants import *
from datetime import datetime, timedelta, date
from time import time


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
        self.password_change_domains = set()
        self.weighted_avg_days_online_past = 0
        self.weighted_avg_days_online_current = 0
        self.first_online_timestamp = 0
        self.last_online_timestamp = 0
        self.weighted_avg_timestamp_past = int((datetime.now() - timedelta(days=14)).strftime("%s"))
        self.start_year_weeks = 0
        self.total_weeks_history = 0

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
        if self.os == UBUNTU:
            username = commands.getoutput("whoami")
            return "/home/" + username + "/.config/google-chrome/Default/Login Data" if self.check_chrome_exists() \
                else False
        elif self.os == WINDOWS:
            # currently not checking if chrome is installed, just return the Login Data path
            return os.path.join(os.path.expandvars("%userprofile%"),
                                "AppData\Local\Google\Chrome\User Data\Default\Login Data")
        elif self.os == OSX:
            username = commands.getoutput("whoami")
            return "/Users/" + username + "/Library/Application Support/Google/Chrome/Default/Login Data"

    def get_chrome_sqlite_history_path(self):
        if self.os == UBUNTU:
            username = commands.getoutput("whoami")
            return "/home/" + username + "/.config/google-chrome/Default/History" if self.check_chrome_exists() \
                else False
        elif self.os == WINDOWS:
            # currently not checking if chrome is installed, just return the Login Data path
            return os.path.join(os.path.expandvars("%userprofile%"),
                                "AppData\Local\Google\Chrome\User Data\Default\History")
        elif self.os == OSX:
            username = commands.getoutput("whoami")
            return "/Users/" + username + "/Library/Application Support/Google/Chrome/Default/History"

    def get_days_accessed(self, domain, start, end):
        days_accessed = 0
        for timestamp in self.domain_visits[domain]:
            if start <= timestamp <= end:
                days_accessed += 1
        return float(days_accessed)

    def increment_days_online(self, visit_time):
        if visit_time <= self.weighted_avg_timestamp_past:
            self.weighted_avg_days_online_past += 1
        else:
            self.weighted_avg_days_online_current += 1

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
        hashed_password = sha512(password).hexdigest()
        hashed_password = md5(hashed_password).hexdigest()
        self.password_domain_dict[hashed_password].add(domain)
        self.domain_password_dict[domain].add(hashed_password)
        # Remove from unused accounts when we find a visit that is within the last 90 days
        self.unused_accounts.add(domain)

    def get_chrome_passwords_sqlite_windows(self, login_data):
        import win32crypt

        for url, user_name, password in login_data:
            password = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
            domain = self.get_url_domain(url)
            password = md5(password).hexdigest()
            self.store_passwords_domain(domain, password)

    def get_chrome_passwords_sqlite_osx(self, login_data):
        for url, user_name, password in login_data:
            if password == '':
                continue
            domain = self.get_url_domain(url)
            self.store_passwords_domain(domain, password)

    def get_chrome_passwords_sqlite(self):
        path = self.get_chrome_sqlite_login_data_path()
        self.get_sqlite_connection(path)
        sql = "SELECT COUNT(*) FROM logins"
        cursor = self.execute_sqlite(sql)
        count = cursor.fetchone()[0]
        if count == 0:
            return False
        sql = '''SELECT origin_url, username_value, hex(password_value) FROM logins WHERE origin_url != ""'''
        cursor = self.execute_sqlite(sql)
        login_data = cursor.fetchall()
        if self.os == WINDOWS:
            self.get_chrome_passwords_sqlite_windows(login_data)
        elif self.os == OSX:
            self.get_chrome_passwords_sqlite_osx(login_data)

    def get_chrome_passwords_keyring(self):
        if self.os != UBUNTU:
            return
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
        prev_log_date = None
        for history in history_data:
            visit_time = history[1]
            if self.last_online_timestamp == 0:
                self.last_online_timestamp = visit_time
            self.first_online_timestamp = visit_time
            if prev_log_date is None:
                prev_log_date = datetime.fromtimestamp(visit_time)
                prev_log_date = prev_log_date.date()
                self.increment_days_online(visit_time)
                self.total_weeks_history += 1
                print "week" + prev_log_date.strftime("%V")
            log_date = datetime.fromtimestamp(visit_time)
            log_date = log_date.date()
            if log_date < prev_log_date:
                prev_week_number = int(prev_log_date.strftime("%V"))
                current_week_number = int(log_date.strftime("%V"))
                self.increment_days_online(visit_time)
                if current_week_number != prev_week_number:
                    self.total_weeks_history += 1
                    print "week" + prev_log_date.strftime("%V")
                prev_log_date = log_date

            domain = self.get_url_domain(history[0])
            if domain in self.domain_password_dict:
                if len(self.domain_visits[domain]) == 0:
                    self.domain_visits[domain].append(visit_time)
                else:
                    prev_date = datetime.fromtimestamp(self.domain_visits[domain][-1])
                    prev_date = prev_date.date()
                    if log_date < prev_date:
                        self.domain_visits[domain].append(visit_time)
                if domain in self.unused_accounts:
                    self.unused_accounts.remove(domain)
        self.start_year_weeks = date(
            datetime.fromtimestamp(self.first_online_timestamp).year,
            12,
            28).isocalendar()[1]

    def calculate_account_frequency(self):
        """
            frequency:
                3 => very frequent (at least once a day ~ weekday)
                2 => frequent (at least once a week)
                1 => intermittently
        """
        print self.total_weeks_history
        for domain in self.domain_visits:
            # determine very frequent access - 5 days out of 7 ~ 71% of days
            # frequent access - 10 days out of 30 ~ 33.33% of days
            if len(self.domain_visits[domain]) == 0:
                continue
            """
            start_date = datetime.fromtimestamp(self.first_online_timestamp).date()
            end_date = datetime.now().date()
            duration_of_access = float((end_date - start_date).days)
            """
            past_days_accessed = self.get_days_accessed(domain, start=self.first_online_timestamp,
                                                        end=self.weighted_avg_timestamp_past)
            current_days_accessed = self.get_days_accessed(domain, start=self.weighted_avg_timestamp_past + 1,
                                                           end=time())
            try:
                past_access_frequency = float(past_days_accessed / float(self.weighted_avg_days_online_past))
            except ZeroDivisionError as _:
                past_access_frequency = 0
            try:
                current_access_frequency = float(current_days_accessed / float(self.weighted_avg_days_online_current))
            except ZeroDivisionError as _:
                current_access_frequency = 0

            access_frequency = (WEIGHTED_AVG_PAST_WEIGHT * past_access_frequency) + (
                WEIGHTED_AVG_CURRENT_WEIGHT * current_access_frequency)

            if access_frequency >= 0.71:
                self.domain_access_frequency[domain] = 3
                continue

            # determine frequent access
            prev_week_number = None
            weeks_accessed = 0
            for timestamp in reversed(self.domain_visits[domain]):
                current_week_number = int(datetime.fromtimestamp(timestamp).strftime("%V"))
                if prev_week_number != current_week_number:
                    prev_week_number = current_week_number
                    weeks_accessed += 1
            if weeks_accessed >= self.total_weeks_history or access_frequency >= 0.33:
                self.domain_access_frequency[domain] = 2
            else:
                self.domain_access_frequency[domain] = 1

    def determine_password_change(self):
        for domain in self.domain_access_frequency:
            frequency = self.domain_access_frequency[domain]
            if frequency == 2 or frequency == 3:
                passwords = self.domain_password_dict[domain]
                for password in passwords:
                    for temp_domain in self.password_domain_dict[password]:
                        if temp_domain in self.unused_accounts:
                            self.password_change_domains.add(temp_domain)

    def print_basic_analyses(self):
        print "------------- Basic Analyses -------------"
        print "Reused passwords:"
        for password in self.password_domain_dict:
            print password + " => " + str(len(self.password_domain_dict[password]))
        print "\n\nUnused Accounts:"
        print ", ".join(self.unused_accounts)
        print "\n\nFrequency of access:"
        for domain in self.domain_access_frequency:
            if self.domain_access_frequency[domain] == 1:
                print domain + " => " + "Intermittently"
            elif self.domain_access_frequency[domain] == 2:
                print domain + " => " + "Frequent"
            else:
                print domain + " => " + "Very Frequent"
        print "\n\nChange the passwords of these domains:"
        print ", ".join(self.password_change_domains)

    def get_chrome_passwords(self):
        # if not self.check_chrome_exists():
        # return False

        self.get_chrome_passwords_sqlite()
        if len(self.password_domain_dict) == 0:
            self.get_chrome_passwords_keyring()
        if len(self.password_domain_dict) == 0:
            print "No passwords found"
            return
        self.close_sqlite_connection()
        self.get_chrome_history()
        self.calculate_account_frequency()
        self.determine_password_change()
        self.print_basic_analyses()


if __name__ == '__main__':
    passwords_obj = Passwords()
    passwords_obj.get_chrome_passwords()
