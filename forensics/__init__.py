# -*- coding: utf-8 -*-
#
# forensics/__init__.py
#
from __future__ import absolute_import
import sys
import os
import logging
from .walker_utils import WalkerUtilities
from .network import ContainerBase, TCPContainer, UDPContainer, IPContainer


def setupLogger(fullpath=None, level=logging.INFO):
    FORMAT = ("%(asctime)s %(levelname)s %(module)s %(funcName)s "
              "[line:%(lineno)d] %(message)s")
    logging.basicConfig(filename=fullpath, format=FORMAT, level=level)
    return logging.getLogger()


def validatePath(path, file=False, csv=False, dir=False, sqlite=False):
    result = False

    if file and os.path.isfile(path):
        if os.access(path, os.R_OK):
            result = True
        else:
            logging.getLogger().critical("File '%s' is not readable.", path)
    elif csv:
        head, tail = os.path.split(path)
        root, ext = os.path.splitext(tail)
        head = head == '' and '.' or head

        if os.path.isdir(head) and ext.lower() == '.csv':
            result = True
    elif dir and os.path.isdir(path):
        result = True
    elif sqlite:
        head, tail = os.path.split(path)
        result = validatePath(head, dir=True)
    else:
        logging.getLogger().critical("Must set either file, csv, dir, or "
                                     "sqlite to True")

    return result
