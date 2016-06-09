#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import readline
import getpass
import argparse
import pickle
import base64
import os
from colored import fg, bg, attr

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken

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
        if master_password != decrypt(master_password, database["MasterPassword"]["password"], database["MasterPassword"]["salt"]):
            return False
    except InvalidToken:
            return False
    return True


def save_database():
    pickle.dump(database, open(database_filename, "wb"))

def modifyCommand(entry_name, from_new=False):
    if not from_new and not database.has_key(entry_name):
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
    database[entry_name] = {
        "username" : username,
        "password" : encrypt(master_password, password, salt),
        "salt" : salt
    }
    save_database()

    readline.parse_and_bind('set disable-completion off')

def removeCommand(entry_name):
    if database.has_key(entry_name):
        database.pop(entry_name)
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

def exitCommand(entry_key):
    sys.exit(0)

commands = {
    "new" : newCommand,
    "remove" : removeCommand,
    "modify" : modifyCommand,
    "exit" : exitCommand
}

def completer(text, state):
    part = text.split()[-1]
    if len(text.split()) > 1:
        options = [i for i in [j for j in database.keys() if j != "MasterPassword"] if part in i]
    else:
        options = [i for i in commands.keys() if i.startswith(part)]
        options += [i for i in [j for j in database.keys() if j != "MasterPassword"] if part in i]
    if state < len(options):
        return options[state]
    else:
        return None




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

    args = parser.parse_args(sys.argv[1:])
    database_filename = args.database

    new_database = False
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

        database = {}
        database["MasterPassword"] = {
            "password" : encrypt(master_password, master_password, salt),
            "salt" : salt
        }
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

        # The check for "MasterPassword" is just so we don't get a KeyError because it has no username.
        if len(line.split()) == 1 and line in database.keys() and line != "MasterPassword":
            master_password = getpass.getpass("Master-password: ")
            password = decrypt(master_password, database[line]["password"], database[line]["salt"])
            print "Username: %s"%database[line]["username"]
            print "Password: %s%s%s%s"%(fg(0), bg(0), password, attr(0))
        else:
            command = line.split()[0]
            if command in commands.keys():
                commands[command](" ".join(line.split()[1:]))
