#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This code is a complete rewrite of parts of Chet Hosmer's code from his
# book "Python Forensics".
#
# Publisher: Elsevier
# ISBN: 978-0-12-418676-7
#
# My work is just an exercise in understanding the concepts of Forensics
# with regard to its use in computer sicence.
#
# by: Carl J.Nobile
#

import os
import sys
import logging
import traceback
import argparse
import datetime

from forensics import setupLogger, WalkerUtilities


__version__ = '1.0.0'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=("Forensic Directory Tree Walker"))
    parser.add_argument(
        '-n', '--noop', action='store_true', default=False, dest='noop',
        help="Run as if doing something, but do nothing.")
    parser.add_argument(
        '-q', '--quite', action='store_false', dest='quite',
        help="Turn off all console logging.")
    parser.add_argument(
        '-D', '--debug', action='store_true', dest='debug',
        help="Turn on DEBUG logging mode, can be very verbose.")
    parser.add_argument(
        '-d', '--dir-path', type=str, default='', dest='dir_path',
        required=True, help="Directory path to walk.")
    parser.add_argument(
        '-r', '--report-path', type=str, default='', dest='report_path',
        required=True, help="Outgoing CSV file path and filename.")
    parser.add_argument(
        '-l', '--log-file', type=str, default='', dest='log_file',
        help="Log file path and filename.")
    parser.add_argument(
        '--md5', action='store_true', dest='md5', default=False,
        help="Use the MD5 algorithm (default).")
    parser.add_argument(
        '--sha256', action='store_true', dest='sha256', default=False,
        help="Use the SHA256 algorithm.")
    parser.add_argument(
        '--sha512', action='store_true', dest='sha512', default=False,
        help="Use the SHA512 algorithm.")

    options = parser.parse_args()

    if not options.quite and options.log_file == u'':
        level = 1000 # Turns off console logging if a file is not defined.
    elif options.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    log = setupLogger(fullpath=options.log_file, level=level)
    log.info("Options: %s", options)

    if not os.path.exists(options.dir_path):
        msg = (u"The walking path seems to not exist, "
               u"please check: {}").format(options.dir_path)
        log.critical(msg)
        if options.quite: print msg
        sys.exit(1)

    # Test that the report file has a valid path and a CSV file is indicated.
    head, tail = os.path.split(options.report_path)
    root, ext = os.path.splitext(tail)
    head = head == u'' and u'.' or head
    #print head, tail, root, ext

    if not os.path.isdir(head) or not ext.lower() == u'.csv':
        msg = (u"The report path '{}' must include a valid path and "
               u"CSV file.").format(options.report_path)
        log.critical(msg)
        if options.quite: print msg
        sys.exit(1)

    # Make MD5 the default if nothing is chosen.
    if not options.md5 and not options.sha256 and not options.sha512:
        options.md5 = True

    # If more than one hash algorithm is found fail.
    if (options.md5, options.sha256, options.sha512).count(True) != 1:
        msg = u"Can only set one of --md5, --sha256, or --sha512."
        log.critical(msg)
        if options.quite: print msg
        sys.exit(1)

    startTime = datetime.datetime.now()

    try:
        log.info("Walking path %s started at %s", options.dir_path, startTime)
        wu = WalkerUtilities(log, options)
        pCount = wu.walkPath()
        endTime = datetime.datetime.now()
        log.info("Walking path %s finished, %s files processed at %s, "
                 "elapsed time %s", options.dir_path, pCount, endTime,
                 endTime - startTime)
    except Exception as e:
        if options.quite:
            tb = sys.exc_info()[2]
            traceback.print_tb(tb)
            print "%s: %s\n" % (sys.exc_info()[0], sys.exc_info()[1])

        sys.exit(1)

    sys.exit(0)
