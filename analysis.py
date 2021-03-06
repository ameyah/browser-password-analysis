import sqlite3
from subprocess import Popen, PIPE
import platform
import commands
from collections import defaultdict
from hashlib import md5, sha512
from tldextract import tldextract
from constants import *
from top_sites import top_sites
from datetime import datetime, timedelta, date
from time import time
from ui_components.ToolUi import ToolUi
import operator
import json
import urllib2


class Passwords:
    def __init__(self, tk_interface):
        self.ui_interface = tk_interface
        self.tool_state = STATE_INITIAL
        self.user_18_older = False
        self.ui_interface.override_x_callback(self.override_x)
        self.conn = None
        self.os = None
        self.detect_os()
        self.password_domain_dict = defaultdict(lambda: defaultdict(list))
        self.domain_password_dict = defaultdict(set)
        self.domain_visits = defaultdict(list)
        self.domain_access_frequency = defaultdict(int)
        self.unused_accounts = set()
        self.password_change_domains = defaultdict(set)
        self.weighted_avg_days_online_past = 0
        self.weighted_avg_days_online_current = 0
        self.first_online_timestamp = 0
        self.last_online_timestamp = 0
        self.weighted_avg_timestamp_past = int(int((datetime.now() - timedelta(days=14)).strftime("%S")))
        self.days_online_timestamp = []
        self.days_online_index = 0
        self.start_year_weeks = 0
        self.total_weeks_history = 0
        self.report = dict()
        self.render_ui()

    def display_initial_info_label(self):
        self.ui_interface.set_info_label_text(
            "You must close your Chrome windows temporarily, so we can access your password manager and history data. "
            "You can reopen the browser in a few seconds.")

    def render_ui(self):
        title = "Chrome Password Analysis"
        self.ui_interface.set_window_title(title)

        buttons = [
            {"title": "Start", "callback": self.start_analysis},
            {"title": "About", "callback": self.about_click},
            {"title": "Preview and Send Summary", "callback": self.report_click}
        ]

        self.ui_interface.render_header(title, buttons)
        self.display_initial_info_label()
        toggled_frames = [
            {"title": "Reused Passwords", "textbox_name": UI_TEXTBOX_REUSED_PASSWORDS},
            {"title": "Unused Accounts", "textbox_name": UI_TEXTBOX_UNUSED_ACCOUNTS},
            {"title": "Account Access Frequency", "textbox_name": UI_TEXTBOX_ACCESS_FREQUENCY},
            {"title": "Accounts needing password reset", "textbox_name": UI_TEXTBOX_CHANGE_PASSWORD},
        ]

        self.ui_interface.render_frames(toggled_frames)

    def override_x(self):
        if self.tool_state == STATE_INITIAL:
            if self.ui_interface.display_messagebox_yesno("Browser Password Analysis",
                                                          "It looks like you haven't seen your password analysis "
                                                          "results. To analyze your passwords, press the 'Start' "
                                                          "button and wait for a few seconds.\n\nAre you sure you "
                                                          "want to exit?"):
                self.ui_interface.destroy_main()
        elif self.tool_state == STATE_ANALYSIS:
            if not self.ui_interface.display_messagebox_yesno("Browser Password Analysis",
                                                              "Would you like to share the summarized results for "
                                                              "research purposes. We only collect minimal information for "
                                                              "research analysis. You can see what data we collect before "
                                                              "sharing your data.\n\nWould you like to preview (and send) "
                                                              "the data?"):
                self.ui_interface.destroy_main()
            else:
                self.report_click()
        else:
            self.ui_interface.destroy_main()

    def about_click(self):
        title = "About this tool"
        message = "This tool extracts and provides analysis of your passwords stored by Chrome.\n" \
                  "You can choose to share a minimal set of analyses with us.\nThe data will only be " \
                  "used for research purposes, and no personal identifying information will be collected.\n\n" \
                  "For further questions, please contact:\n" \
                  "Jelena Mirkovic <mirkovic@isi.edu>\n" \
                  "Ameya Hanamsagar <ahanamsa@usc.edu>"
        self.ui_interface.display_popup(title=title, message=message)

    def report_click(self):
        self.report['text_box'] = UI_TEXTBOX_REPORT_PREVIEW
        self.ui_interface.preview_report(self.report, callback=self.send_report)
        self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW,
                                          "The report data generated and sent is based only on Alexa's top 500 "
                                          "domains.\nNo personal identifying information or information that can expose"
                                          " the personal identity is sent.")
        self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW,
                                          "\n\nReused Passwords: " + ", ".join(
                                              str(x) for x in self.report['reused_passwords']['reuse']))
        self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW,
                                          "\n\nUnused Accounts: \n\tTotal - " + str(self.report['unused_accounts'][
                                              'count']) + "\n\t" + "\n\t".join(
                                              str(x) for x in self.report['unused_accounts']['domains']))
        self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW, "\n\nAccount Access Frequency:\n\t")
        if 3 in self.report['access_frequency']:
            self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW,
                                              "Daily Used Accounts:\n\t\t" + "\n\t\t".join(
                                                  self.report['access_frequency'][3]))
        if 2 in self.report['access_frequency']:
            self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW,
                                              "\n\tWeekly Used Accounts:\n\t\t" + "\n\t\t".join(
                                                  self.report['access_frequency'][2]))
        if 1 in self.report['access_frequency']:
            self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW,
                                              "\n\tQuarterly Used Accounts:\n\t\t" + "\n\t\t".join(
                                                  self.report['access_frequency'][1]))
        self.ui_interface.text_box_insert(UI_TEXTBOX_REPORT_PREVIEW,
                                          "\n\nPassword Reset required domains:\n\tTotal - " + str(
                                              self.report['password_reset']['count']) + "\n\t" + "\n\t".join(
                                              self.report['password_reset']['domains']))

    def send_report(self):
        # url = "http://localhost/browser_tool_dump.php"
        url = "https://steel.isi.edu/Projects/PASS/browser_tool_dump.php"
        if os.path.exists(APP_DATA_PATH):
            with open(APP_DATA_PATH, "r") as fp:
                user_id = fp.read().strip()
                if user_id.strip() != "":
                    url += "?id=" + user_id
        req = urllib2.Request(url)
        req.add_header('Content-Type', 'application/json')
        print json.dumps(self.report)
        response = urllib2.urlopen(req, json.dumps(self.report))
        response_code = response.getcode()
        print "Response - " + str(response_code)
        if response_code == 200:
            user_id = response.read()
            if user_id.strip() != "":
                with open(APP_DATA_PATH, "w") as fp:
                    fp.write(user_id)

            self.ui_interface.display_popup(title="Success",
                                            message="Thank you for sharing the data summary!")
            self.ui_interface.close_report_dialog()
        else:
            self.ui_interface.display_popup(title="Error",
                                            message="There was an issue sending the data summary.")
        self.tool_state = STATE_DONE

    def detect_os(self):
        self.os = platform.system()
        if self.os == LINUX:
            self.os = platform.dist()[0]

    @staticmethod
    def get_url_sub_domain(url):
        domain_obj = tldextract.extract(url)
        return "%s.%s.%s" % (
            domain_obj.subdomain, domain_obj.domain, domain_obj.suffix) if domain_obj.subdomain else "%s.%s" % (
            domain_obj.domain, domain_obj.suffix)

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
            self.display_initial_info_label()
            self.ui_interface.display_popup(title="Error",
                                            message="You must close your Chrome windows temporarily so we can access "
                                                    "your password manager and history data. You can reopen the browser"
                                                    " when the analysis succeeds.")
            raise sqlite3.OperationalError()

    def store_passwords_domain(self, domain, username, password):
        hashed_password = sha512(password).hexdigest()
        hashed_password = md5(hashed_password).hexdigest()
        self.password_domain_dict[hashed_password][domain].append(username)
        self.domain_password_dict[domain].add(hashed_password)
        # Remove from unused accounts when we find a visit that is within the last 90 days
        self.unused_accounts.add(domain)

    @staticmethod
    def repair_passwords_windows(login_data):
        import win32crypt

        repaired_login_data = []
        for url, user_name, password, date_created in login_data:
            repair_password = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
            repair_password = md5(repair_password).hexdigest()
            repaired_login_data.append((url, user_name, repair_password, date_created,))
        return repaired_login_data

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
        if self.os == WINDOWS:
            sql = '''SELECT origin_url, username_value, password_value, date_created FROM logins
              WHERE origin_url != ""'''
        else:
            sql = '''SELECT origin_url, username_value, hex(password_value), date_created FROM logins
                  WHERE origin_url != ""'''
        try:
            cursor = self.execute_sqlite(sql)
        except sqlite3.OperationalError:
            return
        login_data = cursor.fetchall()
        if self.os == WINDOWS:
            login_data = self.repair_passwords_windows(login_data)
        domain_username_password_timestamp = dict()
        for url, username, password, date_created in login_data:
            if password.strip() == "":
                continue
            domain = self.get_url_sub_domain(url)
            key = (domain, username,)
            value = (password, date_created,)
            if key in domain_username_password_timestamp:
                if date_created >= domain_username_password_timestamp[key][1]:
                    domain_username_password_timestamp[key] = value
            else:
                domain_username_password_timestamp[key] = value

        for domain_username in domain_username_password_timestamp:
            self.store_passwords_domain(domain_username[0], domain_username[1],
                                        domain_username_password_timestamp[domain_username][0])

    def get_chrome_passwords_keyring(self):
        if self.os != UBUNTU:
            return
        import gnomekeyring

        for keyring in gnomekeyring.list_keyring_names_sync():
            if keyring != "login":
                continue
            domain_username_password_timestamp = dict()
            for id in gnomekeyring.list_item_ids_sync(keyring):
                item = gnomekeyring.item_get_info_sync(keyring, id)
                attr = gnomekeyring.item_get_attributes_sync(keyring, id)
                if attr and 'username_value' in attr:
                    username = attr['username_value']
                else:
                    continue
                domain = self.get_url_sub_domain(attr['origin_url'])
                password = item.get_secret()
                if password.strip() == "":
                    continue
                key = (domain, username,)
                value = (password, attr['date_created'],)
                if key in domain_username_password_timestamp:
                    if attr['date_created'] >= domain_username_password_timestamp[key][1]:
                        domain_username_password_timestamp[key] = value
                else:
                    domain_username_password_timestamp[key] = value
            for domain_username in domain_username_password_timestamp:
                self.store_passwords_domain(domain_username[0], domain_username[1],
                                            domain_username_password_timestamp[domain_username][0])

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
                prev_week_number = int(prev_log_date.isocalendar()[1])
                current_week_number = int(log_date.isocalendar()[1])
                self.increment_days_online(visit_time)
                if current_week_number != prev_week_number:
                    self.total_weeks_history += 1
                prev_log_date = log_date

            domain = self.get_url_sub_domain(history[0])
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

            past_timestamp_start = int(int(past_datetime_start.strftime("%S")))
            past_timestamp_end = int(int(past_datetime_end.strftime("%S")))
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
                past_timestamp_start = int(int(past_datetime_start.strftime("%S")))
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
                current_week_number = int(datetime.fromtimestamp(timestamp).isocalendar()[1])
                if prev_week_number != current_week_number:
                    prev_week_number = current_week_number
                    weeks_accessed += 1
            if weeks_accessed >= self.total_weeks_history or access_frequency >= 0.2:
                self.domain_access_frequency[domain] = 2
            else:
                self.domain_access_frequency[domain] = 1

    def determine_password_change(self):
        for password in self.password_domain_dict:
            frequent_domains = ()
            password_change = set()
            for domain in self.password_domain_dict[password]:
                frequency = self.domain_access_frequency[domain]
                usernames = self.password_domain_dict[password][domain]
                if frequency == 2 or frequency == 3:
                    frequent_domains += (domain + " (Username - " + ", ".join(usernames) + ")", )
                    continue
                if domain in self.unused_accounts:
                    password_change.add((domain, ", ".join(usernames),))
            if len(frequent_domains) > 0 and len(password_change) > 0:
                self.password_change_domains[frequent_domains] = sorted(password_change)

    def print_basic_analyses(self):
        self.ui_interface.clear_text_boxes()
        sorted_passwords = sorted(self.password_domain_dict, key=lambda x: len(self.password_domain_dict[x]),
                                  reverse=True)
        self.report['reused_passwords'] = {
            'count': len(sorted_passwords),
            'reuse': []
        }
        frequently_reused_count = 0
        for password in sorted_passwords:
            if len(self.password_domain_dict[password]) >= 3:
                frequently_reused_count += 1
        if frequently_reused_count > 0:
            self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_REUSED_PASSWORDS, message="You have " + str(
                frequently_reused_count) + " passwords you are heavily reusing. See the top " + str(
                frequently_reused_count) + " entries for the hash of the password and the number of accounts "
                                           "where it is used.\n\n", text_style=TEXTBOX_STYLE_INFO)
        for password_i in xrange(len(sorted_passwords)):
            self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_REUSED_PASSWORDS,
                                              message="Password " + str(password_i + 1) + " => " + str(
                                                  len(self.password_domain_dict[sorted_passwords[password_i]])) + "\n")
            self.report['reused_passwords']['reuse'].append(
                len(self.password_domain_dict[sorted_passwords[password_i]]))

        unused_accounts = sorted(self.unused_accounts)
        self.report['unused_accounts'] = {
            'count': len(unused_accounts),
            'domains': []
        }
        self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_UNUSED_ACCOUNTS,
                                          message="The accounts on the following websites haven't been used in the past"
                                                  " 3 months. If you don't use these accounts, please close the "
                                                  "accounts, or reset their passwords.\n\n",
                                          text_style=TEXTBOX_STYLE_INFO)
        for account in unused_accounts:
            self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_UNUSED_ACCOUNTS, message=account + "\n")
            if self.get_url_domain(account) in top_sites:
                self.report['unused_accounts']['domains'].append(account)

        domain_frequency_sorted = sorted(self.domain_access_frequency.items(), key=operator.itemgetter(1), reverse=True)
        current_frequency = 4

        self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_ACCESS_FREQUENCY,
                                          message="Accounts as per frequency of use:\n\nAccounts accessed daily\n"
                                                  "Accounts accessed weekly\n"
                                                  "Accounts accessed quarterly (within the last 90 days)\n\n",
                                          text_style=TEXTBOX_STYLE_INFO)

        self.report['access_frequency'] = dict()
        for i in xrange(len(domain_frequency_sorted)):
            if current_frequency > domain_frequency_sorted[i][1]:
                current_frequency = domain_frequency_sorted[i][1]
                if current_frequency == 1:
                    self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_ACCESS_FREQUENCY,
                                                      message="\nAccounts accessed quarterly:\n",
                                                      text_style=TEXTBOX_STYLE_HEADING)
                if current_frequency == 2:
                    self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_ACCESS_FREQUENCY,
                                                      message="\nAccounts accessed weekly:\n",
                                                      text_style=TEXTBOX_STYLE_HEADING)
                if current_frequency == 3:
                    self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_ACCESS_FREQUENCY,
                                                      message="\nAccounts accessed daily:\n",
                                                      text_style=TEXTBOX_STYLE_HEADING)
                self.report['access_frequency'][current_frequency] = []
            self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_ACCESS_FREQUENCY,
                                              message=domain_frequency_sorted[i][0] + "\n")
            if self.get_url_domain(domain_frequency_sorted[i][0]) in top_sites:
                self.report['access_frequency'][current_frequency].append(domain_frequency_sorted[i][0])

        self.report['password_reset'] = {
            'count': 0,
            'domains': set()
        }
        """
        frequent_domain_same_password_flag = False
        for frequent_domains in self.password_change_domains:
            if len(frequent_domains) > 1:
                if not frequent_domain_same_password_flag:
                    self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_CHANGE_PASSWORD,
                                                      message="Reset the passwords of these accounts to unique passwords:\n")
                    frequent_domain_same_password_flag = True
                self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_CHANGE_PASSWORD,
                                                  message="\n".join(list(frequent_domains)))
        """

        self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_CHANGE_PASSWORD,
                                          message="Accounts that haven't been used in the past 3 months, but share a "
                                                  "password with a frequently used account.\n\n",
                                          text_style=TEXTBOX_STYLE_INFO)
        password_change_domains = set()
        for frequent_domains in self.password_change_domains:
            self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_CHANGE_PASSWORD,
                                              message="\nSame password as \n   " + "\n   ".join(
                                                  frequent_domains) + "\n",
                                              text_style=TEXTBOX_STYLE_HEADING)
            self.report['password_reset']['count'] += len(self.password_change_domains[frequent_domains])
            for domain_info in self.password_change_domains[frequent_domains]:
                domain = domain_info[0]
                usernames = domain_info[1:]
                usernames = [username for username in usernames if username != ""]
                if domain not in password_change_domains:
                    domain_username = domain
                    if len(usernames) > 0:
                        domain_username += " (Username - " + ", ".join(usernames) + ")\n"
                    else:
                        domain_username += "\n"
                    self.ui_interface.text_box_insert(text_box=UI_TEXTBOX_CHANGE_PASSWORD, message=domain_username)
                    password_change_domains.add(domain)
                if self.get_url_domain(domain) in top_sites:
                    self.report['password_reset']['domains'].add(domain)
        self.report['password_reset']['domains'] = list(self.report['password_reset']['domains'])
        self.ui_interface.set_info_label_text("Password Analysis complete. Please expand the below sections.")

    def get_chrome_passwords(self):
        # if not self.check_chrome_exists():
        # return False

        result = self.get_chrome_passwords_sqlite()
        if result == False:
            return False
        if len(self.password_domain_dict) == 0:
            self.get_chrome_passwords_keyring()
        if len(self.password_domain_dict) == 0:
            self.ui_interface.display_popup(title="", message="No passwords found.")
            return False
        self.close_sqlite_connection()
        result = self.get_chrome_history()
        if result == False:
            return False
        self.close_sqlite_connection()
        self.calculate_account_frequency()
        self.determine_password_change()

    def start_analysis(self):
        if not self.user_18_older:
            if not self.ui_interface.display_messagebox_yesno("Consent", "Are you 18 years old or older?"):
                self.ui_interface.destroy_main()
                return

        self.user_18_older = True
        result = self.get_chrome_passwords()
        if result == False:
            return
        self.print_basic_analyses()
        self.tool_state = STATE_ANALYSIS


if __name__ == '__main__':
    if not os.path.exists(APP_PATH):
        os.makedirs(APP_PATH)
    tool_ui = ToolUi()
    passwords_obj = Passwords(tool_ui)
