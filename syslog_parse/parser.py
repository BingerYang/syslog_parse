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
from copy import copy

MAX_MESSAGE_LENGTH = 1024


def collect_traceback_cb(msg, e, traceback_cb=None):
    try:
        return traceback_cb(msg, e)
    except Exception as e:
        return None


class Parser(object):
    """Parse syslog messages."""
    _DATA_TIME_FORMAT = [
        "%b %d %Y %H:%M:%S",
        "%b %d %H:%M:%S"
    ]
    _DATA_FORMAT_PAT = "(?P<pri><\d+>)(?P<other>.+)"
    # _DATA_TIME_FORMAT_PAT_LIST = [
    #     "(?P<mon>[A-Za-z]+)\s+(?P<day>\d+)\s+(?P<year>\d+)\s+(?P<time>([0-9]{2}:){2}\d+)",
    #     "(?P<mon>[A-Za-z]+)\s+(?P<day>\d+)\s+(?P<time>([0-9]{2}:){2}\d+)"
    # ]
    _DATA_TIME_FORMAT_PAT_LIST = [
        "(?P<temptime>[A-Za-z]+\s+\d+\s+\d+\s+([0-9]{2}:){2}\d+)[\.\d]*",
        "(?P<temptime>[A-Za-z]+\s+\d+\s+([0-9]{2}:){2}\d+)[\.\d]*"
    ]
    rule = re.compile(_DATA_FORMAT_PAT)

    @classmethod
    def when_parse_prival(cls, prival):
        pass

    @classmethod
    def parse(cls, data, priority=None):
        """
        data 和 priority 均为解析的数据，如果priority存在，则 data 中开头不包含priority信息，否则包含
        :param data:
        :param priority:
        :return:
        """
        obj = cls(data)
        if priority:
            obj._pri_part = priority
            priority_value = obj._parse_pri_part()
        else:
            priority_value = obj.parse_priority()

        cls.when_parse_prival(priority_value)
        timestamp, hostname = obj._parse_header_part()
        module, digest = obj._parse_event()
        content = obj._parse_msg_part()
        return Message(priority_value.facility, priority_value.severity,
                       timestamp, hostname, module=module, digest=digest, content=content)

    @classmethod
    def cycle_parse(cls, data, traceback_cb=None, ignore_error=False):
        """
        循环解析 data 数据
        :param data:
        :param traceback_cb: 异常处理回调
        :param ignore_error: 默认不忽略异常
        :return:
        """

        def run_parse(data, priority):
            try:
                obj = cls.parse(data, priority)
            except MessageFormatError as e:
                error_record = "{}{}".format(property, data)
                if ignore_error:
                    collect_traceback_cb(error_record, e, traceback_cb)
                    obj = None
                else:
                    raise
            return obj

        find_pri_part = None
        while True:

            if not data:
                break

            res = re.search(cls.rule, data)
            if res:
                if find_pri_part:
                    yield run_parse(data[:res.start("pri")], priority=find_pri_part)

                find_pri_part = res.group("pri")
                data = res.group("other")
            else:
                if find_pri_part:
                    yield run_parse(data, find_pri_part)
                    find_pri_part = None
                    data = None

    def __init__(self, data):
        ensure(isinstance(data, str), 'Data must be a byte string.')
        ensure(len(data) <= MAX_MESSAGE_LENGTH,
               'Message must not be longer than 1024 bytes.')
        self._data = data

    @staticmethod
    def to_dict(msg):
        return dict(msg._asdict())

    @classmethod
    def to_json(cls, msg):
        info = cls.to_dict(msg)
        info["facility"] = info["facility"].value
        info["severity"] = info["severity"].value
        return info

    @staticmethod
    def to_list(msg):
        resp = list(copy(msg()))
        resp[0] = resp[0].value
        resp[1] = resp[1].value
        return resp

    def parse_priority(self):
        pat = re.compile(self._DATA_FORMAT_PAT)
        res = re.search(pat, self._data)
        if res:
            self._pri_part = res.group("pri")
            pri_obj = self._parse_pri_part()
            self._data = self._data[res.end("pri"):]
        else:
            raise MessageFormatError("Can't match priority")
        return pri_obj

    def _parse_pri_part(self):
        return PriorityValue.from_pri_part(self._pri_part)

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
    _DATA_FORMAT_PAT = "<(?P<pri>\d+)>"

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
