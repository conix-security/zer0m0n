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
#include <windows.h>
#include "utf8.h"

int utf8_encode(unsigned short c, unsigned char *out)
{
    if(c < 0x80) {
        *out = c & 0x7f;
        return 1;
    }
    else if(c < 0x800) {
        *out = 0xc0 + ((c >> 8) << 2) + (c >> 6);
        out[1] = 0x80 + (c & 0x3f);
        return 2;
    }
    else {
        *out = 0xe0 + (c >> 12);
        out[1] = 0x80 + (((c >> 8) & 0x1f) << 2) + ((c >> 6) & 0x3);
        out[2] = 0x80 + (c & 0x3f);
        return 3;
    }
}

int utf8_length(unsigned short x)
{
    unsigned char buf[3];
    return utf8_encode(x, buf);
}

int utf8_strlen_ascii(const char *s, int len)
{
	int ret = 0;    
	if(len < 0) len = strlen(s);

    while (len-- != 0) {
        ret += utf8_length(*s++);
    }
    return ret;
}

int utf8_strlen_unicode(const wchar_t *s, int len)
{
	int ret = 0;
	if(len < 0) len = lstrlenW(s);

    while (len-- != 0) {
        ret += utf8_length(*s++);
    }
    return ret;
}

char * utf8_string(const char *str, int length)
{
    int encoded_length;
	char * utf8string;
	int pos = 4;

	if (length == -1) length = strlen(str);
	encoded_length = utf8_strlen_ascii(str, length);
    utf8string = (char *) malloc(encoded_length+4);
    *((int *) utf8string) = encoded_length;
    

    while (length-- != 0) {
        pos += utf8_encode(*str++, (unsigned char *) &utf8string[pos]);
    }
    return utf8string;
}

char * utf8_wstring(const wchar_t *str, int length)
{
    int encoded_length;
	char * utf8string;
	int pos = 4;

	if (length == -1) length = lstrlenW(str);
    
	encoded_length = utf8_strlen_unicode(str, length);
    utf8string = (char *) malloc(encoded_length+4);
    *((int *) utf8string) = encoded_length;

    while (length-- != 0) {
        pos += utf8_encode(*str++, (unsigned char *) &utf8string[pos]);
    }
    return utf8string;
}