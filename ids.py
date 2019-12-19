#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
An intrusion detection system for J1939 networks.

Usage:
  ids.py [-d | --daemon] <configuration>
  ids.py -h | --help

Options:
  -d --daemon   Run in daemon mode.
  -h --help     Show this screen.
"""
from docopt import docopt

if __name__ == '__main__':
    arguments = docopt(__doc__)
