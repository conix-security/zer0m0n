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

#include <windows.h>

typedef struct _lookup_internal_t {
    CRITICAL_SECTION cs;
    void *root;
} lookup_t;

void lookup_init(lookup_t *d);
void *lookup_add(lookup_t *d, unsigned int id, unsigned int size);
void *lookup_get(lookup_t *d, unsigned int id, unsigned int *size);
void lookup_del(lookup_t *d, unsigned int id);
