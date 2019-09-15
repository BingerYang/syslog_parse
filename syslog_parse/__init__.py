# -*- coding: utf-8 -*-
name = "syslog_parse"
version_info = (0, 2, 1, 1909162205)
__version__ = ".".join([str(v) for v in version_info])
__description__ = 'syslog parser'

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
