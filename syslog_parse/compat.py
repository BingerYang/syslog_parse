# -*- coding: utf-8 -*-

"""
Python 2/3 compatibility
"""

from sys import version_info


PYTHON3 = version_info[0] == 3


if PYTHON3:
    binary_type = bytes
else:
    binary_type = str
