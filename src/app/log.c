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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>
#include <winsock.h>
#include "utf8.h"
#include "log.h"
#include "bson.h"

// the size of the logging buffer
#define BUFFERSIZE 1024 * 1024
#define BUFFER_LOG_MAX 256

static CRITICAL_SECTION g_mutex;
static unsigned int g_starttick;

static char g_buffer[BUFFERSIZE];
static int g_idx;

// current to-be-logged API call
static bson g_bson[1];
static char g_istr[4];

static char logtbl_explained[256] = {0};

//
// Log API
//

DWORD get_ppid(DWORD pid)
{
	LONG (WINAPI *NtQueryInformationProcess)(HANDLE ProcessHandle,
        ULONG ProcessInformationClass, PVOID ProcessInformation,
        ULONG ProcessInformationLength, PULONG ReturnLength);

	HANDLE hProc;
	ULONG_PTR pbi[6]; ULONG ulSize = 0;

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if(!hProc)
		return -1;

    *(FARPROC *) &NtQueryInformationProcess = GetProcAddress(
        LoadLibrary("ntdll"), "NtQueryInformationProcess");

    if(NtQueryInformationProcess != NULL && NtQueryInformationProcess(
            hProc, 0, &pbi, sizeof(pbi), &ulSize) >= 0 &&
            ulSize == sizeof(pbi)) {
        return pbi[5];
    }
	return -1;
}

void log_raw_direct(const char *buf, size_t length, int g_sock) {
   
	unsigned int sent = 0;
    int r;
    while (sent < length) {
        r = send(g_sock, buf+sent, length-sent, 0);
        if (r == -1) {
			fprintf(stderr, "send() error : %x\n", WSAGetLastError());
            return;
        }
        sent += r;
    }
}



static void log_int8(char value)
{
    bson_append_int( g_bson, g_istr, value );
}

static void log_int16(short value)
{
    bson_append_int( g_bson, g_istr, value );
}


static void log_int32(int value)
{
    bson_append_int( g_bson, g_istr, value );
}

static void log_string(const char *str, int length)
{
    int ret;
    char *utf8s;
	int utf8len;

	if (str == NULL) {
        bson_append_string_n( g_bson, g_istr, "", 0 );
        return;
    }
    utf8s = utf8_string(str, length);
    utf8len = * (int *) utf8s;
    ret = bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, utf8s+4, utf8len );
    if (ret == BSON_ERROR) {
        char tmp[64];
        _snprintf(tmp, 64, "dbg bson err string %x utf8len %d", g_bson->err, utf8len);
    }
    free(utf8s);
}

static void log_wstring(const wchar_t *str, int length)
{
	int ret;
	char *utf8s;
	int utf8len;

    if (str == NULL) {
        bson_append_string_n( g_bson, g_istr, "", 0 );
        return;
    }
    utf8s = utf8_wstring(str, length);
    utf8len = * (int *) utf8s;
    ret = bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, utf8s+4, utf8len );
    if (ret == BSON_ERROR) {
        char tmp[64];
        _snprintf(tmp, 64, "dbg bson err wstring %x utf8len %d", g_bson->err, utf8len);
    }
    free(utf8s);
}

static void log_argv(int argc, const char ** argv) {
    int i;
    bson_append_start_array( g_bson, g_istr );

	for (i=0; i<argc; i++) {
        _snprintf(g_istr, 4, "%u", i);
        log_string(argv[i], -1);
    }
    bson_append_finish_array( g_bson );
}

static void log_wargv(int argc, const wchar_t ** argv) {

	int i;
	bson_append_start_array( g_bson, g_istr );

    for (i=0; i<argc; i++) {
        _snprintf(g_istr, 4, "%u", i);
        log_wstring(argv[i], -1);
    }

    bson_append_finish_array( g_bson );
}

static void log_buffer(const char *buf, size_t length) {
    size_t trunclength = min(length, BUFFER_LOG_MAX);

    if (buf == NULL) {
        trunclength = 0;
    }

    bson_append_binary( g_bson, g_istr, BSON_BIN_BINARY, buf, trunclength );
}

void loq(int g_sock, int index, const char *name,
    int is_success, int return_value, const char *fmt, ...)
{
	const char *fmtbak;
	int argnum = 2;
    int count = 1; char key = 0;
	const char * pname;
    bson b[1];

    va_list args;
    va_start(args, fmt);
	fmtbak = fmt;

	if(1==1)
	{
        bson_init( b );
        bson_append_int( b, "I", index );
        bson_append_string( b, "name", name );
        bson_append_string( b, "type", "info" );

        bson_append_start_array( b, "args" );
        bson_append_string( b, "0", "is_success" );
        bson_append_string( b, "1", "retval" );

        while (--count != 0 || *fmt != 0) {
            // we have to find the next format specifier
            if(count == 0) {
                // end of format
                if(*fmt == 0) break;

                // set the count, possibly with a repeated format specifier
                count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

                // the next format specifier
                key = *fmt++;
            }

            pname = va_arg(args, const char *);
            _snprintf(g_istr, 4, "%u", argnum);
            argnum++;

            //on certain formats, we need to tell cuckoo about them for nicer display / matching
            if (key == 'p' || key == 'P') {
                bson_append_start_array( b, g_istr );
                bson_append_string( b, "0", pname );
                bson_append_string( b, "1", "p" );
                bson_append_finish_array( b );
            } else {
                bson_append_string( b, g_istr, pname );
            }

            //now ignore the values
            if(key == 's') {
                (void) va_arg(args, const char *);
            }
            else if(key == 'S') {
                (void) va_arg(args, int);
                (void) va_arg(args, const char *);
            }
            else if(key == 'u') {
                (void) va_arg(args, const wchar_t *);
            }
            else if(key == 'U') {
                (void) va_arg(args, int);
                (void) va_arg(args, const wchar_t *);
            }
            else if(key == 'b') {
                (void) va_arg(args, size_t);
                (void) va_arg(args, const char *);
            }
            else if(key == 'B') {
                (void) va_arg(args, size_t *);
                (void) va_arg(args, const char *);
            }
            else if(key == 'i') {
                (void) va_arg(args, int);
            }
            else if(key == 'l' || key == 'p') {
                (void) va_arg(args, long);
            }
            else if(key == 'L' || key == 'P') {
                (void) va_arg(args, long *);
            }
            else if(key == 'o') {
                (void) va_arg(args, UNICODE_STRING *);
            }
            else if(key == 'O') {
                (void) va_arg(args, OBJECT_ATTRIBUTES *);
            }
            else if(key == 'a') {
                (void) va_arg(args, int);
                (void) va_arg(args, const char **);
            }
            else if(key == 'A') {
                (void) va_arg(args, int);
                (void) va_arg(args, const wchar_t **);
            }
            else if(key == 'r' || key == 'R') {
                (void) va_arg(args, unsigned long);
                (void) va_arg(args, unsigned long);
                (void) va_arg(args, unsigned char *);
            }

        }
        bson_append_finish_array( b );
        bson_finish( b );
        log_raw_direct(bson_data( b ), bson_size( b ), g_sock);
        bson_destroy( b );
    }

    va_end(args);
    fmt = fmtbak;
    va_start(args, fmt);
    count = 1; key = 0; argnum = 2;

    bson_init( g_bson );
    bson_append_int( g_bson, "I", index );
    bson_append_int( g_bson, "T", GetCurrentThreadId() );
    bson_append_int( g_bson, "t", GetTickCount() - g_starttick );
    bson_append_start_array( g_bson, "args" );
    bson_append_int( g_bson, "0", is_success );
    bson_append_int( g_bson, "1", return_value );

    while (--count != 0 || *fmt != 0) {

        // we have to find the next format specifier
        if(count == 0) {
            // end of format
            if(*fmt == 0) break;

            // set the count, possibly with a repeated format specifier
            count = *fmt >= '2' && *fmt <= '9' ? *fmt++ - '0' : 1;

            // the next format specifier
            key = *fmt++;
        }

        // pop the key and omit it
        (void) va_arg(args, const char *);
        _snprintf(g_istr, 4, "%u", argnum);
        argnum++;

        // log the value
        if(key == 's') {
            const char *s = va_arg(args, const char *);
            if(s == NULL) s = "";
            log_string(s, -1);
        }
        else if(key == 'S') {
            int len = va_arg(args, int);
            const char *s = va_arg(args, const char *);
            if(s == NULL) { s = ""; len = 0; }
            log_string(s, len);
        }
        else if(key == 'u') {
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) s = L"";
            log_wstring(s, -1);
        }
        else if(key == 'U') {
            int len = va_arg(args, int);
            const wchar_t *s = va_arg(args, const wchar_t *);
            if(s == NULL) { s = L""; len = 0; }
            log_wstring(s, len);
        }
        else if(key == 'b') {
            size_t len = va_arg(args, size_t);
            const char *s = va_arg(args, const char *);
            log_buffer(s, len);
        }
        else if(key == 'B') {
            size_t *len = va_arg(args, size_t *);
            const char *s = va_arg(args, const char *);
            log_buffer(s, *len);
        }
        else if(key == 'i') {
            int value = va_arg(args, int);
            log_int32(value);
        }
        else if(key == 'l' || key == 'p') {
            long value = va_arg(args, long);
            log_int32(value);
        }
        else if(key == 'L' || key == 'P') {
            long *ptr = va_arg(args, long *);
            log_int32(ptr != NULL ? *ptr : 0);
        }
        else if(key == 'o') {
            UNICODE_STRING *str = va_arg(args, UNICODE_STRING *);
            if(str == NULL) {
                log_string("", 0);
            }
            else {
                log_wstring(str->Buffer, str->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'O') {
            OBJECT_ATTRIBUTES *obj = va_arg(args, OBJECT_ATTRIBUTES *);
            if(obj == NULL || obj->ObjectName == NULL) {
                log_string("", 0);
            }
            else {
                log_wstring(obj->ObjectName->Buffer,
                    obj->ObjectName->Length / sizeof(wchar_t));
            }
        }
        else if(key == 'a') {
            int argc = va_arg(args, int);
            const char **argv = va_arg(args, const char **);
            log_argv(argc, argv);
        }
        else if(key == 'A') {
            int argc = va_arg(args, int);
            const wchar_t **argv = va_arg(args, const wchar_t **);
            log_wargv(argc, argv);
        }
        else if(key == 'r' || key == 'R') {
            unsigned long type = va_arg(args, unsigned long);
            unsigned long size = va_arg(args, unsigned long);
            unsigned char *data = va_arg(args, unsigned char *);

		   if(type == REG_NONE) {
                log_string("", 0);
            }
            else if(type == REG_DWORD || type == REG_DWORD_LITTLE_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(value);
            }
            else if(type == REG_DWORD_BIG_ENDIAN) {
                unsigned int value = *(unsigned int *) data;
                log_int32(htonl(value));
            }
            else if(type == REG_EXPAND_SZ || type == REG_SZ) {

                if(data == NULL) {
                    bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                        (const char *) data, 0);
                }
                // ascii strings
                else if(key == 'r') {
                    bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                        (const char *) data, size);
                }
                // unicode strings
                else {
                    bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                        (const char *) data, size);
                }
            } else {
                bson_append_binary(g_bson, g_istr, BSON_BIN_BINARY,
                    (const char *) data, 0);
            }

        }
    }

    va_end(args);

    bson_append_finish_array( g_bson );
    bson_finish( g_bson );
    
	log_raw_direct(bson_data( g_bson ), bson_size( g_bson ), g_sock);

    bson_destroy( g_bson );
    LeaveCriticalSection(&g_mutex);
}

void announce_netlog(DWORD pid, int g_sock)
{
    char protoname[32];
    strcpy(protoname, "BSON\n");
    log_raw_direct(protoname, strlen(protoname), g_sock);
}

void log_new_process(DWORD pid, char* filename, int g_sock)
{
	FILETIME st;

    g_starttick = GetTickCount();

    GetSystemTimeAsFileTime(&st);

    loq(g_sock, 0, "__process__", 1, 0, "lllls", "TimeLow", st.dwLowDateTime,
        "TimeHigh", st.dwHighDateTime,
        "ProcessIdentifier", pid,
        "ParentProcessIdentifier", get_ppid(pid),
        "ModulePath", filename);
}

void log_new_thread(DWORD pid, int g_sock)
{
    loq(g_sock, 1, "__thread__", 1, 0, "l", "ProcessIdentifier", pid);
}

int log_init(unsigned int ip, unsigned short port, int debug)
{
	int g_sock;

	InitializeCriticalSection(&g_mutex);

    if(debug != 0) {
        g_sock = INVALID_SOCKET;
		return -1;
    }
    else {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        g_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		addr.sin_addr.S_un.S_addr = ip;

		return g_sock;
    }
}

int log_resolve_index(const char *funcname, int index)
{
	unsigned int i;

    for (i = 0; logtbl[i] != NULL; i++) {
        if(!strcmp(funcname, logtbl[i])) {
            if(index != 0) {
                index--;
            }
            else {
                return i;
            }
        }
    }
    return -1;
}


