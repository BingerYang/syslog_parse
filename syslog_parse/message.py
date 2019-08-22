# -*- coding: utf-8 -*-

from collections import namedtuple

Message = namedtuple('Message',
                     ['facility', 'severity', 'timestamp', 'hostname', 'module', 'digest', 'content'])
