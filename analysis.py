import sqlite3
from subprocess import Popen, PIPE
import platform
import commands
from collections import defaultdict
import os
import win32crypt
from hashlib import md5


class Passwords:
    def __init__(self):
        self.conn = None
        self.os = None
        self.detect_os()
        self.password_dict = defaultdict(int)

    def detect_os(self):
        self.os = platform.system()
        if self.os == "Linux":
            self.os = platform.dist()[0]

    def check_chrome_exists(self):
        if self.os == "Ubuntu":
            p = Popen(['/usr/bin/which', 'google-chrome'], stdout=PIPE, stderr=PIPE)
            p.communicate()
            return p.returncode == 0

    def get_chrome_sqlite(self):
        #  os.path.join(os.path.expandvars("%userprofile%"),"AppData\Local\Google\Chrome\User Data\Default\Login Data")
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
        if self.os == "Ubuntu":
            username = commands.getoutput("whoami")
            return "/home/" + username + "/.config/google-chrome/Default/Login Data" if self.check_chrome_exists() \
                else False
        elif self.os == "Windows":
            # currently not checking if chrome is installed, just return the Login Data path
            return os.path.join(os.path.expandvars("%userprofile%"),"AppData\Local\Google\Chrome\User Data\Default\Login Data")

    def get_sqlite_connection(self, path):
        self.conn = sqlite3.connect(path)

    def execute_sqlite(self, sql):
        if self.conn is None:
            self.get_sqlite_connection(self.get_chrome_sqlite())
        return self.conn.execute(sql)

    def get_chrome_passwords_sqlite(self):
        path = self.get_chrome_sqlite()
        self.get_sqlite_connection(path)
        sql = "SELECT COUNT(*) FROM logins"
        cursor = self.execute_sqlite(sql)
        count = cursor.fetchone()[0]
        if count == 0:
            return False
        sql = "SELECT origin_url, username_value, password_value FROM logins"
        cursor = self.execute_sqlite(sql)
        login_data = cursor.fetchall()
        for url, user_name, password in login_data:
            password = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
            self.password_dict[md5(password).hexdigest()] += 1
        print self.password_dict

    def get_chrome_passwords_keyring(self):
        import gnomekeyring
        for keyring in gnomekeyring.list_keyring_names_sync():
            if keyring != "login":
                continue
            for id in gnomekeyring.list_item_ids_sync(keyring):
                item = gnomekeyring.item_get_info_sync(keyring, id)
                attr = gnomekeyring.item_get_attributes_sync(keyring, id)
                if attr and 'username_value' in attr:
                    self.password_dict[item.get_secret()] += 1
        print len(self.password_dict)

    def get_chrome_passwords(self):
        # if not self.check_chrome_exists():
        #    return False

        self.get_chrome_passwords_sqlite()
        if len(self.password_dict) == 0:
            self.get_chrome_passwords_keyring()


if __name__ == '__main__':
    passwords_obj = Passwords()
    passwords_obj.get_chrome_passwords()