/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2012 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

struct {
    // name of the pipe to communicate with cuckoo
    char pipe_name[MAX_PATH];

    // results directory, has to be hidden
    char results[MAX_PATH];

    // analyzer directory, has to be hidden
    char analyzer[MAX_PATH];

    // is this the first process or not?
    int first_process;

    // how many milliseconds since startup
    unsigned int startup_time;

    // do we want to enable the retaddr check?
    int retaddr_check;

    // server ip and port
    unsigned int host_ip;
    unsigned short host_port;
} g_config;

void read_config(int pid);
