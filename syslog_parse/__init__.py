# -*- coding: utf-8 -*-
name = "syslog_parse"
version_info = (0, 2, 1, 9161139)
__version__ = ".".join([str(v) for v in version_info])
__description__ = 'syslog parser'

from .facility import Facility
from .message import Message
from .parser import Parser
from .severity import Severity


def parse(data):
    """Parse data and return syslog message."""
    return Parser.parse(data)


def cycle_parse(data, traceback_cb=None, ignore_error=False):
    """
    Parse data and return syslog message.
    :param data:
    :param traceback_cb: 异常处理回调
    :param ignore_error: 默认不忽略异常
    :return: Message 对象
    """
    return Parser.cycle_parse(data, traceback_cb, ignore_error)
