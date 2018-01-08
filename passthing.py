#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import readline
import getpass
import argparse
import pickle
import base64
import os
import time
import subprocess
import string
import random
from math import ceil

from colored import fg, bg, attr

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken

class DatabaseStructure(object):
        def __init__(self, master_password="", master_salt="", passwords={}):
            self.master_password = master_password
            self.master_salt = master_salt
            self.passwords = passwords

class Database():

    def __init__(self, database, filename):
        self.database = database
	self.filename = filename

    def verify_master_password(self, password):
        try:
            if password != Database.decrypt(password, self.database.master_password, self.database.master_salt):
                return False
        except InvalidToken:
                return False
        return True

    def get_entry_names(self):
        return self.database.passwords.keys()

    def get_entry(self, entry_name, master_password):
        entry = self.database.passwords[entry_name]
        username = entry["username"]
        password = Database.decrypt(master_password, entry["password"], entry["salt"])
        return username, password

    def remove_entry(self, entry_name):
        self.database.passwords.pop(entry_name)

    def set_entry(self, entry_name, master_password, username, password, salt):
        self.database.passwords[entry_name] = {
            "username" : username,
            "password" : Database.encrypt(master_password, password, salt),
            "salt" : salt
        }


    def generate_password(self, length=32):
        # chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        random.seed(os.urandom(1024))
        chars = [random.choice(string.ascii_letters) for i in range(int(ceil(length/3.0)))]
        random.seed(os.urandom(1024))
        chars.extend([random.choice(string.digits) for i in range(int(ceil(length/3.0)))])
        random.seed(os.urandom(1024))
        chars.extend([random.choice("!@#$%^&*()") for i in range(int(ceil(length/3.0)))])
        random.seed(os.urandom(1024))
        random.shuffle(chars)
        return "".join(chars)

    def save(self):
        pickle.dump(self.database, open(self.filename, "wb"), protocol=2)

    @staticmethod
    def encrypt(master_password, text, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(master_password))
        fernet = Fernet(key)
        return fernet.encrypt(text)

    @staticmethod
    def decrypt(master_password, text, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
            )
        key = base64.urlsafe_b64encode(kdf.derive(master_password))
        fernet = Fernet(key)
        return fernet.decrypt(text)



class Output():
    def __init__(self, timeout=10, xclip=False):
        self.timeout = timeout
        self.xclip = xclip

    def copy_clipboard(self, text):
        xclip_process = subprocess.Popen(['xclip', '-i'], stdin=subprocess.PIPE)
        xclip_process.communicate(text)
        xclip_process = subprocess.Popen(['xclip', '-i', '-selection', 'clipboard'], stdin=subprocess.PIPE)
        xclip_process.communicate(text)

    def write(self, password):
        max_length = 0
        if self.xclip:
            self.copy_clipboard(password)
        for i in reversed(range(self.timeout)):
            out_string = "\rPassword(%d): %s%s%s%s"%(i, fg(0), bg(0), password, attr(0))
            max_length = max([max_length, len(out_string)])
            sys.stdout.write(out_string)
            sys.stdout.flush()
            time.sleep(1)
        if self.xclip:
            self.copy_clipboard("")
        sys.stdout.write("\r%s%s"%(" "*max_length, "\n"))
        sys.stdout.flush()

class Completion:
    def __init__(self, database, commands):
        self.database = database
        self.commands = commands

    def completer(self, text, state):
        part = text.split()[-1]
        if len(text.split()) > 1:
            options = [i for i in self.database.get_entry_names() if part in i]
        else:
            options = [i for i in self.commands if i.startswith(part)]
            options += [i for i in self.database.get_entry_names() if part in i]
        if state < len(options):
            return options[state]
        else:
            return None


def modify_command(entry_name, database, output, from_new=False):
    generated = False
    if not from_new and entry_name not in database.get_entry_names():
        print "Entry not found: %s"%entry_name
        return
    readline.parse_and_bind('set disable-completion on')
    username = raw_input("Username: ")
    password = getpass.getpass(prompt="Password[generate](or .): ")
    if len(password) == 0:
        generated = True
        password = database.generate_password()
    elif password == ".":
        lines = []
        print "Type in your lines, terminate with a line having . on its own:"
        while True:
            new_line = raw_input()
            if new_line == ".":
                break
            lines.append(new_line)
        password = "\n".join(lines)
    salt = os.urandom(32)
    master_password = getpass.getpass("Master-password: ")
    if not database.verify_master_password(master_password):
        print "Invalid master-password. Entry NOT saved."
        return
    database.set_entry(entry_name, master_password, username, password, salt)
    database.save()
    if generated:
        output.write(password)
    readline.parse_and_bind('set disable-completion off')

def remove_command(entry_name, database, output):
    try:
        database.remove_entry(entry_name)
        database.save()
    except KeyError:
        print "No such entry: %s"%entry_name

def new_command(entry_name, database, output):
    if len(entry_name) == 0:
        readline.parse_and_bind('set disable-completion on')
        while True:
            entry_name = raw_input("Entry name: ")
            if len(entry_name.split()) > 1:
                print "Invalid entry name (no spaces, please)."
                continue
            break
        # we have entry_name now
    modify_command(entry_name, database, output, True)

def list_command(entry_name, database, output):
    for item in database.get_entry_names():
        print " %s"%item

def exit_command(entry_key, database, output):
    sys.exit(0)

commands = {
    "new" : [new_command, "Create new entry"],
    "remove" : [remove_command, "Remove entry"],
    "modify" : [modify_command, "Modify entry"],
    "list" : [list_command, "List entries"],
    "exit" : [exit_command, "Exit passthing"],
    "quit" : [exit_command, "Exit passthing"]
}

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
            prog=sys.argv[0],
            description="passthing",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
            )

    parser.add_argument(
            "database",
            help="Specify database file",
            nargs="?",
            default="passthing.pt"
            )

    parser.add_argument(
            "-t",
            "--timeout",
            help="How long password should remain on screen",
            nargs="?",
            type=int,
            default=10
            )

    parser.add_argument(
            "-c",
            "--clipboard",
            help="Store password to X11 clipboard (requires xclip)",
            action="store_true",
            default=False
            )

    args = parser.parse_args(sys.argv[1:])
    database_filename = args.database

    database = None

    try:
        saved_database = pickle.load(open(args.database, "rb"))
        database = Database(saved_database, database_filename)
    except IOError:
        print "Creating a new database."
        password = getpass.getpass(prompt="New master-password: ")
        salt = os.urandom(32)
        database = Database(DatabaseStructure(Database.encrypt(password, password, salt), salt), database_filename)
        database.save()



    completion = Completion(database, commands.keys())
    readline.parse_and_bind("tab: complete")
    readline.set_completer(completion.completer)

    output = Output(args.timeout, args.clipboard)

    while True:
        try:
            line = raw_input("PassThing> ")
        except EOFError:
            print ""
            break

        if len(line.split()) == 1 and line in database.get_entry_names():
            master_password = getpass.getpass("Master-password: ")
            try:
                username, password = database.get_entry(line, master_password)
                print "Username: %s"%username
                if len(password.split("\n")) > 1:
                    print password
                else:
                    output.write(password)
            except InvalidToken:
                print "Invalid password!"

        else:
            try:
                command = line.split()[0]
            except IndexError:
                continue

            if command in commands.keys():
                commands[command][0](" ".join(line.split()[1:]), database, output)
            elif command == "help":
                for cmd in commands.keys():
                    print "%s\t- %s"%(cmd, commands[cmd][1])
            else:
                print "No such command: %s"%command


