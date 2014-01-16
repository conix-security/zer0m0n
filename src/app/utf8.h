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

int utf8_encode(unsigned short x, unsigned char *out);
int utf8_length(unsigned short x);

// name is a bit weird.. but it calculates the length of the utf8 encoded
// ascii/unicode string "s" in bytes
int utf8_strlen_ascii(const char *s, int len);
int utf8_strlen_unicode(const wchar_t *s, int len);

char * utf8_string(const char *str, int length);
char * utf8_wstring(const wchar_t *str, int length);
