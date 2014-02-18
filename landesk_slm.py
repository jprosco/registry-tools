#!/usr/bin/env python

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

""" Utility to parse LANDesk software licensing monitor registry keys from SOFTWARE registry hive """

__author__ = 'Justin Prosco <justin.prosco@mandiant.com>'

import sys
import struct
from datetime import datetime
from Registry import Registry


def runtime_to_seconds(data):
    """ convert run time to seconds, return -1 if invalid """
    try:
        runtime = struct.unpack('<Q', data)[0] / 10000000.00
        return runtime
    except:
        return -1

def decode_filetime(data):
    """ decode Windows FILETIME object stored as binary data """
    try:
        t = (struct.unpack('<Q', data)[0] - 116444736000000000) / 10000000
        return datetime.utcfromtimestamp(t)
    except:
        return None

def main():
    reg = Registry.Registry(sys.argv[1])

    try:
        path = reg.open('LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring\\MonitorLog')

    except Registry.RegistryKeyNotFoundException:
        try:
            path = reg.open('Wow6432Node\\LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring\\MonitorLog')
        except Registry.RegistryKeyNotFoundException:
            print 'LANDesk software licensing monitor registry keys not found'
            sys.exit(0)

    for subkey in path.subkeys():
        print subkey.name()
        for val in subkey.values():
            decoded_value = val.value()

            if 'Started' in val.name():
                decoded_value = decode_filetime(val.value())
            elif 'Duration' in val.name():
                decoded_value = runtime_to_seconds(val.value())

            #print "\t%s:\t\t%s" % (str(val.name()), decoded_value)
            print '\t{0:17}: {1:}'.format(val.name(), decoded_value)

if __name__ == "__main__":
    main()