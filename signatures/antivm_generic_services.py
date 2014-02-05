# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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
import string
from lib.cuckoo.common.abstracts import Signature

class AntiVMServices(Signature):
    name = "antivm_generic_services"
    description = "Enumerates services, possibly for anti-virtualization"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handle = None
            self.lastprocess = process
        
        if call["api"] == "REGISTRY_ENUMERATE_KEY":
             if string.find(self.get_argument(call,"SubKey").lower(),"system\\controlset001\\services") != -1:
                return True
        
        if not self.handle:
            if call["api"].startswith("RegOpenKeyEx"):
                correct = False
                if self.get_argument(call,"SubKey") == "SYSTEM\\ControlSet001\\Services":
                    correct = True
                else:
                    self.handle = self.get_argument(call,"Handle")

                if not correct:
                    self.handle = None
        else:
            if call["api"].startswith("RegEnumKeyEx"):
                if self.get_argument(call,"Handle") == self.handle:
                    return True
