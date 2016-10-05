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

from colored import fg, bg, attr

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken

class Database(object):
    def __init__(self, master_password="", master_salt="", passwords={}):
        self.master_password = master_password
        self.master_salt = master_salt
        self.passwords = passwords

database = None
database_filename = "passthing.pt"
crypto_unit = None

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

def verify_master_password(master_password):
    try:
        if master_password != decrypt(master_password, database.master_password, database.master_salt):
            return False
    except InvalidToken:
            return False
    return True


def save_database():
    pickle.dump(database, open(database_filename, "wb"), protocol=2)

def modifyCommand(entry_name, from_new=False):
    if not from_new and not database.passwords.has_key(entry_name):
        print "Entry not found: %s"%entry_name
        return
    readline.parse_and_bind('set disable-completion on')
    username = raw_input("Username: ")
    password = getpass.getpass()
    salt = os.urandom(16)
    master_password = getpass.getpass("Master-password: ")
    if not verify_master_password(master_password):
        print "Invalid master-password."
        return
    database.passwords[entry_name] = {
        "username" : username,
        "password" : encrypt(master_password, password, salt),
        "salt" : salt
    }
    save_database()
    readline.parse_and_bind('set disable-completion off')

def removeCommand(entry_name):
    if database.passwords.has_key(entry_name):
        database.passwords.pop(entry_name)
        save_database()

def newCommand(entry_name):
    readline.parse_and_bind('set disable-completion on')
    while True:
        entry_name = raw_input("Entry name: ")
        if len(entry_name.split()) > 1:
            print "Invalid entry name (no spaces, please)."
            continue
        break
    modifyCommand(entry_name, True)

def listCommand(entry_name):
    for i in database.passwords.keys():
        print i

def exitCommand(entry_key):
    sys.exit(0)

commands = {
    "new" : [newCommand, "Create new entry"],
    "remove" : [removeCommand, "Remove entry"],
    "modify" : [modifyCommand, "Modify entry"],
    "list" : [listCommand, "List entries"],
    "exit" : [exitCommand, "Exit from %s"%sys.argv[0]]
}

def completer(text, state):
    part = text.split()[-1]
    if len(text.split()) > 1:
        options = [i for i in database.passwords if part in i]
    else:
        options = [i for i in commands.keys() if i.startswith(part)]
        options += [i for i in database.passwords if part in i]
    if state < len(options):
        return options[state]
    else:
        return None

def copyClipboard(text):
    xclip_process = subprocess.Popen(['xclip', '-i'], stdin=subprocess.PIPE)
    xclip_process.communicate(text)
    xclip_process = subprocess.Popen(['xclip', '-i', '-selection', 'clipboard'], stdin=subprocess.PIPE)
    xclip_process.communicate(text)



if __name__ == "__main__":

    parser = argparse.ArgumentParser(
            prog=sys.argv[0],
            description="PassThingee",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
            )

    parser.add_argument(
            "database",
            help="Specify database file",
            nargs="?",
            default=database_filename
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

    new_database = False

    if args.clipboard:
        try:
            fnull = open(os.devnull, "w")
            subprocess.Popen(['xclip', '-version'], stdin=subprocess.PIPE, stderr=fnull)
        except OSError:
            sys.stderr.write("xclip not installed. Clipboard support not available.\n")
            sys.exit(1)

    try:
        database = pickle.load(open(args.database, "rb"))
        master_password = getpass.getpass("Master-password: ")
        try:
            if not verify_master_password(master_password):
                # This code actually never gets called .. but lets keep it here.
                sys.stderr.write("Invalid password\n")
                sys.exit(1)
        except InvalidToken:
            sys.stderr.write("Invalid password\n")
            sys.exit(1)
    except IOError:
        new_database = True
        print "Creating new database."
        master_password = getpass.getpass("Master-password: ")
        salt = os.urandom(16)

        database = Database()
        database.master_password = encrypt(master_password, master_password, salt)
        database.master_salt = salt
        save_database()

    readline.parse_and_bind("tab: complete")
    readline.set_completer(completer)

    while True:
        try:
            line = raw_input("PassThing> ")
        except EOFError:
            print ""
            break
        if line == "exit":
            break

        if len(line.split()) == 1 and line in database.passwords.keys():
            master_password = getpass.getpass("Master-password: ")
            password = decrypt(master_password, database.passwords[line]["password"], database.passwords[line]["salt"])
            print "Username: %s"%database.passwords[line]["username"]
            max_length = 0
            if args.clipboard:
                copyClipboard(password)
            for i in reversed(range(args.timeout)):
                out_string = "\rPassword(%d): %s%s%s%s"%(i, fg(0), bg(0), password, attr(0))
                max_length = max([max_length, len(out_string)])
                sys.stdout.write(out_string)
                sys.stdout.flush()
                time.sleep(1)
            if args.clipboard:
                copyClipboard("")
            sys.stdout.write("\r%s%s"%(" "*max_length, "\n"))
            sys.stdout.flush()

        else:
            try:
                command = line.split()[0]
            except IndexError:
                continue
            if command == "help":
                for cmd in commands.keys():
                    print "%s\t- %s"%(cmd, commands[cmd][1])
                continue
            if command in commands.keys():
                commands[command][0](" ".join(line.split()[1:]))
            else:
                print "No such command: %s"%command
