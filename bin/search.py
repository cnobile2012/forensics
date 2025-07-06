#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# by: Carl J. Nobile
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#

import os
import sys
import logging
import traceback
import argparse
import datetime

PWD = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(PWD)
sys.path.append(BASE_DIR)

from forensics import setupLogger, validatePath


__version__ = '2.0.0'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=("Forensic Document Search"))
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
        '-l', '--log-file', type=str, default='', dest='log_file',
        help="Log file path and filename.")
    parser.add_argument(
        '-k', '--keyword-path', type=str, default='', dest='keyword_path',
        required=True, help="File that contains keywords.")
    parser.add_argument(
        '-s', '--search-path', type=str, default='', dest='search_path',
        required=True, help="File or path of files to search.")
    parser.add_argument(
        '-m', '--matrix-path', type=str, default='', dest='matrix_path',
        required=True, help="Weighted matrix filename.")

    options = parser.parse_args()

    if not options.quite and options.log_file == '':
        level = 1000  # Turns off console logging if a file is not defined.
    elif options.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    log = setupLogger(fullpath=options.log_file, level=level)
    log.info("Options: %s", options)

    if (not validatePath(options.search_path, dir=True) or not
        validatePath(options.search_path, file=True)):
        msg = ("The search path can be either a file or a path of files, "
               f"please check: {options.dir_path}")
        log.critical(msg)
        if options.quite: print(msg)
        sys.exit(1)

    if not validatePath(options.keyword_path, file=True):
        msg = (f"The keyword path '{options.keyword_path}' must include a "
               "valid path and file.")
        log.critical(msg)
        if options.quite: print(msg)
        sys.exit(1)

    if not validatePath(options.matrix_path, file=True):
        msg = (f"The matrix path '{options.matrix_path}' must include a "
               "valid path and file.")
        log.critical(msg)
        if options.quite: print(msg)
        sys.exit(1)

    startTime = datetime.datetime.now()

    try:
        log.info("Search path %s started at %s", options.dir_path, startTime)
        #su = SearchUtilities(log, options)
        #pCount = su.start()
        endTime = datetime.datetime.now()
        log.info("Search path %s finished, %s files processed at %s, "
                 "elapsed time %s", options.dir_path, pCount, endTime,
                 endTime - startTime)
    except Exception as e:
        if options.quite:
            tb = sys.exc_info()[2]
            traceback.print_tb(tb)
            print(f"{sys.exc_info()[0]}: {sys.exc_info()[1]}\n")

        sys.exit(1)

    sys.exit(0)
