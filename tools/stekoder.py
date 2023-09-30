#!/usr/bin/env python3

import argparse
import datetime
import logging
import stektools


def stek_generate():
    pass


def main():
    """
    Make this callable from the command line for testing purposes.
    """
    parser = argparse.ArgumentParser(description='STEK file generator')
    parser.add_argument('-v', '--verbose', help='verbose output', action='store_true')
    parser.add_argument('-N', '--service-name', help='service name to attach to STEK files', default='Service')
    parser.add_argument('-L', '--valid-length', help='Number of days the STEK should be valid for', default=7,
                        type=int)
    parser.add_argument('-V', '--valid-from', help='Date/Time the STEK should be valid from, in ISO 8601 form',
                        default=datetime.datetime.now(), type=datetime.datetime.fromisoformat)
    parser.add_argument('output', help='STEK file to output')
    args = parser.parse_args()

    # Set verbosity, globally.
    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    pass

    logging.basicConfig(level=log_level, format='%(asctime)s - %(name)s:%(levelname)s:%(message)s',
            datefmt='%m/%d/%Y %H:%M:%S')

    logging.debug('Writing STEK to {} - this file is super secret, be smart with it'.format(
        args.output))
    logging.debug('Generating STEK file for "{}" - STEK is valid from {} for {} day(s).'.format(
        args.service_name, args.valid_from, args.valid_length))

    valid_to = args.valid_from + datetime.timedelta(days=args.valid_length)

    with open(args.output, 'wb+') as fp:
        fp.write(stektools.stek_generate(args.service_name, args.valid_from, valid_to))

if __name__ == '__main__':
    main()
