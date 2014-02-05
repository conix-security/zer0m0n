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

class InjectionCRT(Signature):
    name = "injection_createremotethread"
    description = "Code injection with CreateRemoteThread in a remote process"
    severity = 2
    categories = ["injection"]
    authors = ["JoseMi Holguin", "nex"]
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
            self.ksequence = 0
            self.kPID = 0
            self.klastprocess = process

        if call["api"] == "ZwOpenProcess" and self.ksequence == 0:
            if self.get_argument(call, "PID") != process["process_id"]:
                self.ksequence = 1
                self.kPID = self.get_argument(call, "PID")
        elif call["api"] == "ZwWriteVirtualMemory" and self.ksequence == 1:
            if self.get_argument(call, "PID") == self.kPID:
                self.ksequence = 2
        elif call["api"] == "ZwCreateThread" and self.ksequence == 2:
            if self.get_argument(call, "PID") == self.kPID:
               return True


        if call["api"]  == "OpenProcess" and self.sequence == 0:
            if self.get_argument(call, "ProcessId") != process["process_id"]:
                self.sequence = 1
                self.process_handle = call["return"]
        elif call["api"] == "VirtualAllocEx" and self.sequence == 1:
            if self.get_argument(call, "ProcessHandle") == self.process_handle:
                self.sequence = 2
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "WriteProcessMemory") and self.sequence == 2:
            if self.get_argument(call, "ProcessHandle") == self.process_handle:
                self.sequence = 3
        elif call["api"].startswith("CreateRemoteThread") and self.sequence == 3:
            if self.get_argument(call, "ProcessHandle") == self.process_handle:
                return True
