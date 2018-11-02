import sqlite3
import random
import os
from math import ceil
import string

from passthing import PassCrypto
from cryptography.fernet import InvalidToken
import base64

class NotConfigured(Exception):
    pass

class InvalidPassword(Exception):
    pass

class EntryNotFound(Exception):
    pass


class PassDatabase():
    def __init__(self, filename):
        self.database = sqlite3.connect(filename)
        self.database.row_factory = sqlite3.Row
        self.cursor = self.database.cursor()
        self.configured = False
        try:
            self.cursor.execute(
                '''
                CREATE TABLE config(
                    key TEXT NOT NULL PRIMARY KEY,
                    value TEXT)
                '''
            )
        except sqlite3.OperationalError:
            pass

        try:
            self.cursor.execute(
                '''
                CREATE TABLE passwords(
                    entry_name TEXT NOT NULL PRIMARY KEY,
                    username TEXT,
                    password BLOB NOT NULL,
                    salt BLOB NOT NULL
                )
                '''
            )
        except sqlite3.OperationalError:
            pass

        self.cursor.execute('SELECT key FROM config')
        if len(self.cursor.fetchall()) > 0:
            self.configured = True

    def is_configured(self):
        return self.configured

    def get_config(self, key):
        try:
            self.cursor.execute('SELECT value FROM config WHERE key = :key', {'key': key})
            return self.cursor.fetchone()['value']
        except TypeError:
            raise NotConfigured('No configuration for key = "{}"'.format(key))

    def set_config(self, key, value):
        try:
            self.cursor.execute(
                'INSERT INTO config(key, value) VALUES(:key, :value)',
                {'key': key, 'value': value}
            )
            self.database.commit()
        except sqlite3.IntegrityError:
            self.cursor.execute(
                'UPDATE config SET value = :value where key = :key',
                {'key': key, 'value': value}
            )
            self.database.commit()

    def verify_master_password(self, password):
        master_password = self.get_config('master_password')
        master_salt = base64.urlsafe_b64decode(
            self.get_config('master_salt')
        )
        try:
            PassCrypto.decrypt(bytes(password, 'utf-8'), master_password, master_salt)
            return True
        except InvalidToken:
            raise InvalidPassword() from None

    def get_username(self, entry_name):
        self.cursor.execute(
            'SELECT username from passwords WHERE entry_name = :entry_name',
            {'entry_name': entry_name}
        )
        result = self.cursor.fetchone()
        return result['username']

    def set_username(self, entry_name, username):
        self.cursor.execute(
            '''
                UPDATE passwords
                SET username = :username
                WHERE entry_name = :entry_name
            ''',
            {
                'entry_name': entry_name,
                'username': username
            }
        )
        self.database.commit()

    def set_password(self, entry_name, master_password, password):
        self.verify_master_password(master_password)
        encrypted_password, salt = PassCrypto.encrypt(
            bytes(master_password, 'utf-8'),
            bytes(password, 'utf-8')
        )
        self.cursor.execute(
            '''
                UPDATE passwords
                SET password = :password, salt = :salt
                WHERE entry_name = :entry_name
            ''',
            {
                'entry_name': entry_name,
                'password': encrypted_password,
                'salt': salt
            }
        )
        self.database.commit()


    def get_entry_names(self):
        self.cursor.execute(
            'SELECT entry_name FROM passwords ORDER BY entry_name'
        )
        return [k['entry_name'] for k in self.cursor.fetchall()]

    def get_entry(self, entry_name, master_password):
        try:
            self.cursor.execute(
                '''
                    SELECT username, password, salt
                    FROM passwords
                    WHERE entry_name = :entry_name
                ''',
                {'entry_name': entry_name}
            )
            result = self.cursor.fetchone()
            return result['username'], PassCrypto.decrypt(
                    bytes(master_password, 'utf-8'),
                    result['password'],
                    result['salt']
            )
        except TypeError:
            raise EntryNotFound()
        except InvalidToken:
            raise InvalidPassword() from None

    def remove_entry(self, entry_name):
        self.cursor.execute(
            '''
                DELETE FROM passwords
                WHERE entry_name = :entry_name
            ''',
            {'entry_name': entry_name}
        )
        self.database.commit()

    def set_entry(self, entry_name, master_password, username, password):
        self.verify_master_password(master_password)
        encrypted_password, salt = PassCrypto.encrypt(
            bytes(master_password, 'utf-8'),
            bytes(password, 'utf-8')
        )

        data = {
            'entry_name':entry_name,
            'username': username,
            'password': encrypted_password,
            'salt': salt
        }

        try:
            self.cursor.execute(
                '''
                    INSERT INTO passwords(entry_name, username, password, salt)
                    VALUES(:entry_name, :username, :password, :salt)
                ''',
                data
            )
            self.database.commit()
        except sqlite3.IntegrityError:
            self.cursor.execute(
                '''
                    UPDATE passwords SET
                        username = :username,
                        password = :password,
                        salt = :salt
                    WHERE entry_name = :entry_name

                ''',
                data
            )
            self.database.commit()

    def initialize(self, master_password):
        encrypted_master_password, master_salt = PassCrypto.encrypt(
            bytes(master_password, 'utf-8'),
            bytes(master_password, 'utf-8'),
        )
        self.set_config('master_password', encrypted_master_password)
        self.set_config('master_salt', base64.urlsafe_b64encode(master_salt))

    def generate_password(self, length=32):
        random.seed(os.urandom(1024))
        chars = [random.choice(string.ascii_letters) for i in range(int(ceil(length/3.0)))]
        random.seed(os.urandom(1024))
        chars.extend([random.choice(string.digits) for i in range(int(ceil(length/3.0)))])
        random.seed(os.urandom(1024))
        chars.extend([random.choice('!@#$%^&*()') for i in range(int(ceil(length/3.0)))])
        random.seed(os.urandom(1024))
        random.shuffle(chars)
        return "".join(chars)


if __name__ == '__main__':
    pass_db = PassDatabase('test.db')
    master_password, master_salt = PassCrypto.encrypt(
        bytes('foobar', 'utf-8'),
        bytes('foobar', 'utf-8'),
    )
    print(master_password)
    print(master_salt)
    print(PassCrypto.decrypt(bytes('foobar', 'utf-8'), master_password, master_salt))
    pass_db.set_config('master_password', master_password)
    pass_db.set_config('master_salt', base64.urlsafe_b64encode(master_salt))
    pass_db.verify_master_password('foobar')
    pass_db.set_entry('test', 'foobar', 'someUser', 'somePassword')
    print(pass_db.get_entry_names())
    print(pass_db.get_entry('test', 'foobar'))
    pass_db.remove_entry('test')
    print(pass_db.get_entry('test', 'foobar'))
