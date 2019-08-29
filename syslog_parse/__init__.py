# -*- coding: utf-8 -*-
name = "syslog_parse"
version_info = (0, 2, 0, 1908271656)
__version__ = ".".join([str(v) for v in version_info])
__description__ = u'syslog解析工具'

from .facility import Facility
from .message import Message
from .parser import Parser
from .severity import Severity


def parse(data):
    """Parse data and return syslog message."""
    return Parser.parse(data)


def cycle_parse(data):
    """Parse data and return syslog message."""
    return Parser.cycle_parse(data)
