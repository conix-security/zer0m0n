# Copyright (C) 2012 JoseMi "h0rm1" Holguin (@j0sm1)
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

class WriteMemory(Signature):
    name = "write_memory"
    description = "Write remote process memory"
    severity = 1
    categories = ["injection"]
    authors = ["0x00"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.sequence = 0
            self.process_handle = 0
            self.lastprocess = process

        if call["api"] == "ZwWriteVirtualMemory":
            if self.get_argument(call, "PID") != process["process_id"]:
               return True
        
        if call["api"]  == "OpenProcess" and self.sequence == 0:
            if self.get_argument(call, "ProcessId") != process["process_id"]:
                self.sequence = 1
                self.process_handle = call["return"]
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "WriteProcessMemory") and self.sequence == 1:
            if self.get_argument(call, "ProcessHandle") == self.process_handle:
                return True
