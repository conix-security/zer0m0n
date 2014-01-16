#include "main.h"

/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2013 Cuckoo Sandbox Developers

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


#define MAX_PROTECTED_PIDS 32


void add_protected_pid(unsigned long pid);
int is_protected_pid(unsigned long pid);

int is_ignored_file_ascii(const char *fname, int length);
int is_ignored_file_unicode(const wchar_t *fname, int length);
int is_ignored_file_objattr(const OBJECT_ATTRIBUTES *obj);

void ignore_file_prepend_stuff(const OBJECT_ATTRIBUTES *obj,
        wchar_t **str, unsigned int *length);

int is_ignored_process();

int is_ignored_retaddr(unsigned int addr);
