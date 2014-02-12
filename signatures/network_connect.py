# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder)
#
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

from lib.cuckoo.common.abstracts import Signature

class NetworkCONNECT(Signature):
    name = "network_connect"
    description = "Connect to a remote server (winsock)"
    severity = 1
    categories = ["network"]
    authors = ["0x00"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.binds = []
        self.lastprocess = None

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.lastprocess = process
            self.seq = 0
            self.handle = 0

        if call["api"] == "connect":
            return True
        if call["api"] == "ZwCreateFile" and self.seq == 0:
            if self.get_argument(call, "FileName") == "\\Device\\Afd\\Endpoint":
                self.seq = 1
                self.handle = self.get_argument(call, "FileHandle")
        if call["api"] == "ZwDeviceIoControlFile" and self.seq == 1:
            if self.get_argument(call, "FileHandle") == self.handle:
                if self.get_argument(call, "IoControlCode") == "0x00012007" :
                    return True
