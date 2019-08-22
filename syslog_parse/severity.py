# -*- coding: utf-8 -*-

from enum import Enum, unique


@unique
class Severity(Enum):
    emergency = 0
    alert = 1
    critical = 2
    error = 3
    warning = 4
    notice = 5
    informational = 6
    debug = 7

    def __str__(self):
        return "{}".format(self.value)
