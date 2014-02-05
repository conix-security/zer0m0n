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

class NetworkBIND(Signature):
    name = "network_bind"
    description = "Starts servers listening on {0}"
    severity = 2
    categories = ["bind"]
    authors = ["nex"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.binds = []

    def on_call(self, call, process):
        if call["api"] != "bind":
            return

        bind = "{0}:{1}".format(self.get_argument(call, "ip"), self.get_argument(call, "port"))
        if bind not in self.binds:
            self.binds.append(bind)

    def on_complete(self):
        if self.binds:
            self.description = self.description.format(", ".join(self.binds))
            return True
