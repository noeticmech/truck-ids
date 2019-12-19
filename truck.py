# -*- coding: utf-8 -*-
"""
This module contains common values, classes, and functions used for extracting
and manipulating SAE J1939 network data.

Constants:

- FRAME_FORMAT      CAN frame format string
- PDU_FORMAT        PDU Format field location as a slice
- PDU_SPECIFIC      PDU Specific field location as a slice
- PRIORITY          Priority field location as a slice
- SRC               Source Address field location as a slice

Named Tuples:

- Event         An attack instance
- Parameter     A specific J1939 parameter
- Record        A single J1939 frame

Classes:

- Capturer          Base class for capture components
- Analyzer          Base class for analysis components
- QuantumAnalyzer   Base class for analysis components using time quanta
- Responder         Base class for response components

Functions:

- extractFeature()  Given payload data, and the start location and length of a
                    J1939 parameter, return the value of that parameter
- writeFeature()    Given payload data, and the start location, length, and
                    value for a J1939 parameter, return the payload data with
                    that value included in the correct location
- buildFrame()      Given priority, PGN, src, dest, and payload data, return
                    a valid frame ready for transmission
- parse_header()    Given the extended CAN identifier for a J1939 frame, return
                    the J1939 header fields
- parse_logfile()   Given a csv J1939 network traffic log, return a list of
                    frames as Records
"""
from collections import namedtuple
import threading
import queue

FRAME_FORMAT = "<IB3x8s"
"""The CAN frame format for use with struct."""

PDU_FORMAT = slice(-6, -4)
"""The PDU Format field location in the J1939/CAN extended identifier"""

PDU_SPECIFIC = slice(-4, -2)
"""The PDU Specific field location in the J1939/CAN extended identifier"""

PRIORITY = slice(-8, -6)
"""The Priority field location in the J1939/CAN extended identifier"""

SRC = slice(-2, None)
"""The Source Address field location in the J1939/CAN extended identifier"""

Event = namedtuple('Event', ['type', 'start_time', 'end_time'])
"""Information about an attack instance"""

Parameter = namedtuple('Parameter', ['PGN', 'byte', 'bit', 'length', 'discrete'])
"""Information about a specific J1939 parameter."""

Record = namedtuple('Record', ['timestamp', 'src', 'dest', 'priority', 'PGN', 'data'])
"""Information about a single J1939 frame"""


class Capturer(threading.Thread):
    def __init__(self, record_queues):
        threading.Thread.__init__(self)
        self.record_queues = record_queues


class Analyzer(threading.Thread):
    def __init__(self, work_queue, report_queue):
        threading.Thread.__init__(self)
        self.work_queue = work_queue
        self.report_queue = report_queue


class Responder(threading.Thread):
    def __init__(self, report_queue):
        threading.Thread.__init__(self)
        self.report_queue = report_queue

    def run(self):
        while True:
            try:
                report = self.report_queue.get(timeout=20)
                self.respond(report)
                self.report_queue.task_done()
            except queue.Empty:
                print('Responder shutdown')
                break

    def respond(self, reports):
        print(reports)


def extractFeature(hex_string, start_addr, length):
    pass


def writeFeature(data, value, start_addr, length):
    pass


def buildFrame(priority, PGN, src, dest, data):
    pass


def parse_header(header):
    pass


def parse_logfile(filename):
    pass
