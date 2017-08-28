import sqlite3
from subprocess import Popen, PIPE
import platform
import commands
from collections import defaultdict
import os
from hashlib import md5
import datetime
from tldextract import tldextract
from constants import *


class Passwords:
    def __init__(self):
        self.conn = None
        self.os = None
        self.detect_os()
        self.password_domain_dict = defaultdict(set)
        self.domain_password_dict = defaultdict(set)
        self.domain_last_visit = dict()

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
        return self.conn.execute(sql)

    def get_chrome_passwords_sqlite_windows(self, login_data):
        import win32crypt

        for url, user_name, password in login_data:
            password = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
            domain = self.get_url_domain(url)
            password = md5(password).hexdigest()
            self.password_domain_dict[password].add(domain)
            self.domain_password_dict[domain].add(password)

    def get_chrome_passwords_sqlite(self):
        path = self.get_chrome_sqlite_login_data_path()
        self.get_sqlite_connection(path)
        sql = "SELECT COUNT(*) FROM logins"
        cursor = self.execute_sqlite(sql)
        count = cursor.fetchone()[0]
        if count == 0:
            return False
        sql = "SELECT origin_url, username_value, password_value FROM logins"
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
                    self.password_domain_dict[password].add(domain)
                    self.domain_password_dict[domain].add(password)

    def get_chrome_history(self):
        path = self.get_chrome_sqlite_history_path()
        self.get_sqlite_connection(path)
        sql = "select url, (last_visit_time / 1000000 + (strftime('%s', '1601-01-01'))) last_visit_time from urls " \
              "order by last_visit_time desc"
        cursor = self.execute_sqlite(sql)
        history_data = cursor.fetchall()
        print len(history_data)
        for history in history_data:
            domain = self.get_url_domain(history[0])
            if domain not in self.domain_last_visit and domain in self.domain_password_dict:
                self.domain_last_visit[domain] = history[1]

    def get_chrome_passwords(self):
        # if not self.check_chrome_exists():
        # return False

        self.get_chrome_passwords_sqlite()
        if len(self.password_domain_dict) == 0:
            self.get_chrome_passwords_keyring()
        self.close_sqlite_connection()
        self.get_chrome_history()
        print self.domain_last_visit


if __name__ == '__main__':
    passwords_obj = Passwords()
    passwords_obj.get_chrome_passwords()