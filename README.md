PassThing
=========

Introduction
------------

This is a command-line password manager. That you could store on your server and get to wherever you are. Because reasons.

Requirements
------------
Python cryptography package (which has requirements of its own). Assuming Debian/Ubuntu compatible:
```bash
$ sudo apt-get install build-essential libssl-dev libffi-dev python-dev python-pip
$ sudo pip install cryptography
```

If you want clipboard support, install xclip as well:

```bash
$ sudo apt-get install xclip
```

If running on a remote server, like I do, you will need to enable X11 forwarding over SSH if you want xclip to work (-X).

Status
------

This was hacked together over a period of a few hours.

### Commands

 * new - Create a new entry.
 * remove - Remove the specified entry
 * modify - Modify the specified entry
 * list - List the names of all entries
 * exit - ...

[![asciicast](https://asciinema.org/a/9bvevukal5e7xb02fwvk4z56y.png)](https://asciinema.org/a/9bvevukal5e7xb02fwvk4z56y) 

