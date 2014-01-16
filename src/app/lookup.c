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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include "lookup.h"

#define ENTER() EnterCriticalSection(&d->cs)
#define LEAVE() LeaveCriticalSection(&d->cs)

typedef struct _entry_t {
    struct _entry_t *next;
    unsigned int id;
    unsigned int size;
    unsigned char data[0];
} entry_t;

void lookup_init(lookup_t *d)
{
    d->root = NULL;
    InitializeCriticalSection(&d->cs);
}

void lookup_free(lookup_t *d)
{
    // TODO
}

void *lookup_add(lookup_t *d, unsigned int id, unsigned int size)
{
    entry_t *t = (entry_t *) malloc(sizeof(entry_t) + size);
    ENTER();
	t->next = d->root;
	t->id = id;
	t->size = size;
	d->root = t;
    LEAVE();
    return t->data;
}

void *lookup_get(lookup_t *d, unsigned int id, unsigned int *size)
{
	void *data;
	entry_t *p = d->root;
	printf("lookup_get()\n");
	ENTER();
	for (p; p != NULL; p = p->next) {
        if(p->id == id) {
            if(size != NULL) {
                *size = p->size;
            }
            data = p->data;
            LEAVE();
            return data;
        }
    }
    LEAVE();
    return NULL;
}

void lookup_del(lookup_t *d, unsigned int id)
{
	entry_t *last;
	entry_t *p = d->root;
	ENTER();
    // edge case; we want to delete the first entry
    if(p != NULL && p->id == id) {
        entry_t *t = p->next;
        free(d->root);
        d->root = t;
        LEAVE();
        return;
    }
    for (last = NULL; p != NULL; last = p, p = p->next) {
        if(p->id == id) {
            last->next = p->next;
            free(p);
            break;
        }
    }
    LEAVE();
}
