import sqlite3
from subprocess import Popen, PIPE
import platform
import commands
from collections import defaultdict
import os
from hashlib import md5, sha512
from tldextract import tldextract
from constants import *
from top_sites import top_sites
from datetime import datetime, timedelta, date
from time import time
from Tkinter import Tk, INSERT, Button, END, LEFT, Label, Toplevel
import tkMessageBox
from ScrolledText import ScrolledText
import operator


class Passwords:
    def __init__(self, tk_interface):
        self.tk = tk_interface
        self.button_frame = None
        self.ui_start_button = None
        self.ui_about_button = None
        self.ui_report_button = None
        self.ui_text_box = None
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
        self.days_online_timestamp = []
        self.days_online_index = 0
        self.start_year_weeks = 0
        self.total_weeks_history = 0
        self.render_ui()

    def render_ui(self):
        self.tk.winfo_toplevel().title("Browser Password Analysis")
        Label(self.tk, text="Chrome Password Analysis", font=("Helvetica", 20)).grid(row=0, columnspan=3)
        Button(self.tk, text="Start", command=self.start_analysis).grid(row=2, column=0)
        Button(self.tk, text="About", command=self.about_click).grid(row=2, column=1)
        Button(self.tk, text="Preview and Send Summary", command=self.report_click).grid(row=2, column=2)
        self.ui_text_box = ScrolledText(self.tk, undo=True)
        self.ui_text_box.grid(row=4, columnspan=3)
        self.tk.mainloop()

    @staticmethod
    def about_click():
        message = "This tool extracts and provides analysis of your passwords stored by Chrome.\n" \
                  "You can choose to share a minimal set of analyses with us.\nThe data will only be " \
                  "used for research purposes, and no personal identifying information will be collected.\n\n" \
                  "For further questions, please contact:\n" \
                  "Jelena Mirkovic <mirkovic@isi.edu>\n" \
                  "Ameya Hanamsagar <ahanamsa@usc.edu>"
        # tkMessageBox.showinfo("About", message)
        dialog = Toplevel()
        dialog.title("About this tool")
        msg = Label(dialog, text=message, justify=LEFT)
        msg.pack(padx=30, pady=30)

    def report_click(self):
        dialog = Toplevel()
        dialog.title("Preview Report")
        Button(dialog, text="Send Report", command=self.send_report).pack()
        label = Label(dialog, width=200, height=200).pack()

    def send_report(self):
        pass

    def detect_os(self):
        self.os = platform.system()
        if self.os == LINUX:
            self.os = platform.dist()[0]

    @staticmethod
    def get_url_domain(url):
        domain_obj = tldextract.extract(url)
        return "%s.%s" % (domain_obj.domain, domain_obj.suffix)

    @staticmethod
    def get_timestamp_past(current_datetime):
        return current_datetime - timedelta(days=14)

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
        self.days_online_timestamp.append(visit_time)
        if visit_time <= self.weighted_avg_timestamp_past:
            self.weighted_avg_days_online_past += 1
        else:
            self.weighted_avg_days_online_current += 1

    def get_days_online_after_timestamp(self, end_timestamp):
        count = 0
        while self.days_online_index < len(self.days_online_timestamp):
            if self.days_online_timestamp[self.days_online_index] >= end_timestamp:
                count += 1
                self.days_online_index += 1
                continue
            return count
        return count

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
            self.ui_text_box.insert(INSERT, "Please exit Google Chrome before running this script.\n")
            raise sqlite3.OperationalError()

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
        try:
            cursor = self.execute_sqlite(sql)
        except sqlite3.OperationalError:
            return False
        count = cursor.fetchone()[0]
        if count == 0:
            return
        sql = '''SELECT origin_url, username_value, hex(password_value) FROM logins WHERE origin_url != ""'''
        try:
            cursor = self.execute_sqlite(sql)
        except sqlite3.OperationalError:
            return
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
        try:
            cursor = self.execute_sqlite(sql)
        except sqlite3.OperationalError:
            return False
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
            log_date = datetime.fromtimestamp(visit_time)
            log_date = log_date.date()
            if log_date < prev_log_date:
                prev_week_number = int(prev_log_date.strftime("%V"))
                current_week_number = int(log_date.strftime("%V"))
                self.increment_days_online(visit_time)
                if current_week_number != prev_week_number:
                    self.total_weeks_history += 1
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
        return True

    def calculate_account_frequency(self):
        """
            frequency:
                3 => very frequent (at least once a day ~ weekday)
                2 => frequent (at least once a week)
                1 => intermittently
        """
        for domain in self.domain_visits:
            # determine very frequent access - 5 days out of 7 ~ 71% of days
            # frequent access - 10 days out of 30 ~ 33.33% of days
            if len(self.domain_visits[domain]) == 0:
                continue

            self.days_online_index = 0

            current_datetime = datetime.now()
            past_datetime_end = self.get_timestamp_past(current_datetime)
            past_datetime_start = self.get_timestamp_past(past_datetime_end)

            past_timestamp_start = int(past_datetime_start.strftime("%s"))
            past_timestamp_end = int(past_datetime_end.strftime("%s"))
            past_days_accessed = self.get_days_accessed(domain, start=past_timestamp_start,
                                                        end=past_timestamp_end)
            current_days_accessed = self.get_days_accessed(domain, start=past_timestamp_end + 1,
                                                           end=time())
            current_days_online = self.get_days_online_after_timestamp(past_timestamp_end + 1)
            past_days_online = self.get_days_online_after_timestamp(past_timestamp_start)
            try:
                past_access_frequency = float(past_days_accessed / float(past_days_online))
            except ZeroDivisionError as _:
                past_access_frequency = 0
            try:
                current_access_frequency = float(current_days_accessed / float(current_days_online))
            except ZeroDivisionError as _:
                current_access_frequency = 0

            access_frequency = (WEIGHTED_AVG_PAST_WEIGHT * past_access_frequency) + (
                WEIGHTED_AVG_CURRENT_WEIGHT * current_access_frequency)

            while past_timestamp_end >= self.first_online_timestamp:
                past_timestamp_end = past_timestamp_start - 1
                past_datetime_start = self.get_timestamp_past(past_datetime_start)
                past_timestamp_start = int(past_datetime_start.strftime("%s"))
                past_days_accessed = self.get_days_accessed(domain, start=past_timestamp_start, end=past_timestamp_end)
                past_days_online = self.get_days_online_after_timestamp(past_timestamp_start)
                try:
                    past_access_frequency = float(past_days_accessed / float(past_days_online))
                except ZeroDivisionError as _:
                    past_access_frequency = 0
                access_frequency = (WEIGHTED_AVG_PAST_WEIGHT * past_access_frequency) + (
                    WEIGHTED_AVG_CURRENT_WEIGHT * access_frequency)
            if access_frequency >= 0.4:
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
            if weeks_accessed >= self.total_weeks_history or access_frequency >= 0.2:
                self.domain_access_frequency[domain] = 2
            else:
                self.domain_access_frequency[domain] = 1

            print domain + " " + str(access_frequency)

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
        self.ui_text_box.delete(1.0, END)
        self.ui_text_box.insert(INSERT, "------------- Basic Analyses -------------\n")
        self.ui_text_box.insert(INSERT, "Reused passwords:\n")
        sorted_passwords = sorted(self.password_domain_dict, key=lambda x: len(self.password_domain_dict[x]),
                                  reverse=True)
        for password in sorted_passwords:
            self.ui_text_box.insert(INSERT, password + " => " + str(len(self.password_domain_dict[password])) + "\n")
        self.ui_text_box.insert(INSERT, "\n\nUnused Accounts:\n")
        unused_accounts = sorted(self.unused_accounts)
        for account in unused_accounts:
            self.ui_text_box.insert(INSERT, account + "\n")
        self.ui_text_box.insert(INSERT, "\n\nFrequency of access:\n")
        domain_frequency_sorted = sorted(self.domain_access_frequency.items(), key=operator.itemgetter(1), reverse=True)
        current_frequency = 4
        for i in xrange(len(domain_frequency_sorted)):
            if current_frequency > domain_frequency_sorted[i][1]:
                current_frequency = domain_frequency_sorted[i][1]
                if current_frequency == 1:
                    self.ui_text_box.insert(INSERT, "\nIntermittently accessed accounts:\n")
                if current_frequency == 2:
                    self.ui_text_box.insert(INSERT, "\nFrequently accessed accounts:\n")
                if current_frequency == 3:
                    self.ui_text_box.insert(INSERT, "\nVery Frequently accessed accounts:\n")
            self.ui_text_box.insert(INSERT, domain_frequency_sorted[i][0] + "\n")
        self.ui_text_box.insert(INSERT, "\n\nChange the passwords of these domains:\n")
        change_password_domains = sorted(self.password_change_domains)
        for domain in change_password_domains:
            self.ui_text_box.insert(INSERT, domain + "\n")

    def get_chrome_passwords(self):
        # if not self.check_chrome_exists():
        # return False

        result = self.get_chrome_passwords_sqlite()
        if result == False:
            return False
        if len(self.password_domain_dict) == 0:
            self.get_chrome_passwords_keyring()
        if len(self.password_domain_dict) == 0:
            self.ui_text_box.insert(INSERT, "No passwords found\n")
            return False
        self.close_sqlite_connection()
        result = self.get_chrome_history()
        if result == False:
            return False
        self.close_sqlite_connection()
        self.calculate_account_frequency()
        self.determine_password_change()

    def start_analysis(self):
        self.ui_text_box.insert(INSERT, "Processing. Please Wait...\n")
        result = self.get_chrome_passwords()
        if result == False:
            return
        self.print_basic_analyses()


if __name__ == '__main__':
    tk = Tk()
    passwords_obj = Passwords(tk)