# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os
from setuptools import setup, find_packages
from syslog_parse import name, __description__, __version__

# read dev requirements
fname = os.path.join(os.path.dirname(__file__), 'requirements.txt')
with open(fname) as f:
    install_requires = [l.strip() for l in f.readlines()]

with open("MAINTAINERS") as f:
    lines = [l.strip() for l in f.readlines()]
    author, author_email = lines[0].split(sep=" ")
    maintainer, maintainer_email = lines[1].split(sep=" ")

root = os.path.basename(os.path.dirname(os.path.abspath(__file__)))
setup(
    name=name,
    version=__version__,
    description=__description__,

    long_description=open('README.rst').read(),
    author=author,
    author_email=author_email,
    maintainer=maintainer,
    maintainer_email=maintainer_email,
    license=open('LICENSE').read(),
    url='git@github.com:BingerYang/{}.git'.format(root),

    python_requires='>=3.4',
    packages=find_packages(exclude=['examples', 'tests']),
    install_requires=install_requires,
    platforms=['all'],
    include_package_data=True,
)
