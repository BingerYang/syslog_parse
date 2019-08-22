# -*- coding: utf-8 -*-
# @Author  : binger
# @Created : 2018/6/26 10:53
# @Software: PyCharm

"""
.. _RFC 3164: http://tools.ietf.org/html/rfc3164
.. _RFC 5424: http://tools.ietf.org/html/rfc5424
"""

from collections import namedtuple
from datetime import datetime
from .facility import Facility
from .message import Message
from .severity import Severity
import re

MAX_MESSAGE_LENGTH = 1024


def parse_cycle(data, parse=None, is_parse_all=True):
    if is_parse_all:
        parse = parse or Parser.parse
    pat = re.compile("(?P<pri><\d+>)(?P<other>.+)")
    pri_part = None
    while True:

        if not data:
            raise StopIteration
        res = re.search(pat, data)
        if res:
            if pri_part:
                if parse:
                    yield parse(data[:res.start("pri")], pri_part)
                else:
                    yield data[:res.start("pri")], pri_part
            pri_part = res.group("pri")
            data = res.group("other")
        else:
            if pri_part:
                if parse:
                    yield parse(data, pri_part)
                else:
                    yield data, pri_part
                pri_part = None
                data = None


class Parser(object):
    """Parse syslog messages."""
    _DATA_TIME_FORMAT = [
        "%b %d %Y %H:%M:%S",
        "%b %d %H:%M:%S"
    ]
    _DATA_FORMAT_PAT = "<(?P<pri>\d+)>"
    # _DATA_TIME_FORMAT_PAT_LIST = [
    #     "(?P<mon>[A-Za-z]+)\s+(?P<day>\d+)\s+(?P<year>\d+)\s+(?P<time>([0-9]{2}:){2}\d+)",
    #     "(?P<mon>[A-Za-z]+)\s+(?P<day>\d+)\s+(?P<time>([0-9]{2}:){2}\d+)"
    # ]
    _DATA_TIME_FORMAT_PAT_LIST = [
        "(?P<temptime>[A-Za-z]+\s+\d+\s+\d+\s+([0-9]{2}:){2}\d+)[\.\d]*",
        "(?P<temptime>[A-Za-z]+\s+\d+\s+([0-9]{2}:){2}\d+)[\.\d]*"
    ]

    @classmethod
    def when_parse_prival(cls, prival):
        pass

    @classmethod
    def parse(cls, data, pri=None):
        parser = cls(data, pri)

        priority_value = parser._parse_pri_part()
        cls.when_parse_prival(priority_value)
        timestamp, hostname = parser._parse_header_part()
        module, digest = parser._parse_event()
        content = parser._parse_msg_part()

        return Message(priority_value.facility, priority_value.severity,
                       timestamp, hostname, module=module, digest=digest, content=content)

    def _parse_pri_part(self):
        return PriorityValue.from_pri_part(self._pri_part)

    def __init__(self, data, pri=None):
        ensure(isinstance(data, str), 'Data must be a byte string.')
        ensure(len(data) <= MAX_MESSAGE_LENGTH,
               'Message must not be longer than 1024 bytes.')
        if pri:
            self._pri_part = pri
            self._data = data
        else:
            pat = re.compile(self._DATA_FORMAT_PAT)
            res = re.search(pat, data)
            if res:
                self._pri_part = res.group("pri")
            else:
                self._data = data[:res.start("pri")]

    def _parse_header_part(self):
        """Extract timestamp and hostname from the HEADER part."""
        timestamp = self._parse_timestamp()
        hostname = self._parse_hostname()
        return timestamp, hostname

    def _parse_timestamp(self):
        """Parse timestamp into a `datetime` instance."""

        for index, pat in enumerate(self._DATA_TIME_FORMAT_PAT_LIST):
            res = re.search(pat, self._data)
            if res:
                self._time_part = res.group("temptime")

                try:
                    timestamp = datetime.strptime(self._time_part,
                                                  self._DATA_TIME_FORMAT[index])

                    self._data = self._data[res.end():]
                    if index == 1:
                        timestamp = timestamp.replace(year=datetime.today().year)

                    break
                except ValueError as e:
                    import traceback
                    print(traceback.format_exc())
                    pass
        else:
            raise MessageFormatError(
                "Can't match time format at {} by {}".format(self._data, ",".join(self._DATA_TIME_FORMAT)))

        return timestamp

    def _parse_hostname(self):
        # self._data = " " + self._data
        res = re.search("(?P<hostname>[\S]+)\s", self._data)

        if res:
            hostname = res.group("hostname")
            self._data = self._data[res.end():]
            if ":" in hostname:
                hostname = None
        else:
            # 思考
            raise MessageFormatError("Can't match hostname")
        # print("self._data =", self._data)
        return hostname

    def _parse_event(self):
        res = ParseEvent.parse(self._data)
        self._data = res["other"]
        return res["module"], res["digest"]

    def _parse_msg_part(self):
        return self._data


class ParseEvent(object):
    """
    " %SFF8472-5-THRESHOLD_VIOLATION: Te1/50: Rx power low alarm; Operating value: -40.0 dBm, Threshold value: -13.9 dBm."
    " rpd[2097]: Decode ifd xe-0/0/3 index 693: ifdm_flags 0xc000"
    " mgd[12377]: UI_WRITE_LOSTCONN: Lost connection to peer 'app-engine-management-service'"
    "<189>167463: *Apr 13 07:10:56.768: %SFF8472-5-THRESHOLD_VIOLATION: Te1/50: Rx power low alarm; Operating value: -40.0 dBm, Threshold value: -13.9 dBm."
    "rpd[1694]: bgp_recv: read from peer 208.76.14.223 (Internal AS 21859) failed: Connection reset by peer"
    "%%01SRM/2/NODEFAULT(l)[1640107]:"
    " IFNET/1/CRCERRORRESUME:Slot=2,Vcpu=0;OID 1.3.6.1.4.1.2011.5.25.41.4.2 The CRC error resume."
    """
    FORMAT_LIST = ["(?P<module>[a-zA-Z]\w*)(/\d+/|-\d+-)(?P<digest>[\w_]+)[^:]+:\s*",
                   "(?P<module>[a-zA-Z]\w*)[^:]*:\s*(?P<digest>[^:]+):\s*"]

    @classmethod
    def parse(self, data):
        response = None
        for pat in self.FORMAT_LIST:
            try:
                res = re.search(pat, data)
                response = {"module": res.group("module"), "digest": res.group("digest"), "other": data[res.end():]}
                break
            except:
                pass
        if response:
            return response
        else:
            raise MessageFormatError("Can't match event")


class PriorityValue(namedtuple('PriorityValue', 'facility severity')):

    @classmethod
    def from_pri_part(cls, pri_part):
        """Create instance from PRI part."""
        ensure(len(pri_part) in {3, 4, 5},
               'PRI part must have 3, 4, or 5 bytes.')

        ensure(pri_part.startswith('<'),
               'PRI part must start with an opening angle bracket (`<`).')

        ensure(pri_part.endswith('>'),
               'PRI part must end with a closing angle bracket (`>`).')

        priority_value = pri_part[1:-1]

        try:
            priority_value_number = int(priority_value)
        except ValueError:
            raise MessageFormatError(
                "Priority value must be a number, but is '{}'."
                    .format(priority_value))

        facility_id, severity_id = divmod(priority_value_number, 8)

        facility = Facility(facility_id)
        severity = Severity(severity_id)

        return cls(facility, severity)


def ensure(expression, error_message):
    """Raise exception if the expression evaluates to `False`."""
    if not expression:
        raise MessageFormatError(error_message)


class MessageFormatError(ValueError):
    """Raised when data does not match the expected message structure."""

    def __init__(self, message):
        self.message = message
