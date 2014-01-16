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

//
// Log API
//
// The Log takes a format string and parses the extra arguments accordingly
//
// The following Format Specifiers are available:
// s  -> (char *) -> zero-terminated string
// S  -> (int, char *) -> string with length
// u  -> (wchar_t *) -> zero-terminated unicode string
// U  -> (int, wchar_t *) -> unicode string with length
// b  -> (int, void *) -> memory with a given size (alias for S)
// B  -> (int *, void *) -> memory with a given size (value at integer)
// i  -> (int) -> integer
// l  -> (long) -> long integer
// L  -> (long *) -> pointer to a long integer
// p  -> (void *) -> pointer (alias for l)
// P  -> (void **) -> pointer to a handle (alias for L)
// o  -> (UNICODE_STRING *) -> unicode string
// O  -> (OBJECT_ATTRIBUTES *) -> wrapper around a unicode string
// a  -> (int, char **) -> array of string
// A  -> (int, wchar_t **) -> array of unicode strings
// r  -> (Type, int, char *) type as defined for Registry operations
// R  -> (Type, int, wchar_t *) type as defined for Registry operations
//       type r is for ascii functions, R for unicode (Nt* are unicode)
//
// Each of these format specifiers are prefixed with a zero-terminated key
// value, e.g.
//
// log("s", "key", "value");
//
// A format specifier can also be repeated for n times (with n in the range
// 2..9), e.g.
//
// loq("sss", "key1", "value", "key2", "value2", "key3", "value3");
// loq("3s", "key1", "value", "key2", "value2", "key3", "value3");
//

#include "main.h"

DWORD getppid(DWORD pid);

void loq(int g_sock, int index, const char *name, int is_success, int return_value, const char *fmt, ...);
void log_new_process(DWORD pid, char* filename, int g_sock);
void log_new_thread(DWORD pid, int g_sock);

void announce_netlog(DWORD pid, int g_sock);
int log_init(unsigned int ip, unsigned short port, int debug);
void log_flush();
void log_free();
void log_raw_direct(const char *buf, size_t length, int g_sock);

int log_resolve_index(const char *funcname, int index);
extern const char *logtbl[];

HANDLE hFile;
struct sockaddr_in addr;

/*#define LOQ(fmt, ...) { static int _index; if(_index == 0) \
    _index = log_resolve_index(&__FUNCTION__[4], 0); loq(_index, \
    &__FUNCTION__[4], is_success(ret), (int) ret, fmt, ##__VA_ARGS__); }
*/

#define LOQ(function, success, ret, fmt, ...) { static int _index; if(_index == 0) \
    _index = log_resolve_index(function, 0); loq(_index, \
    function, success, ret, fmt, ##__VA_ARGS__); }

#define LOQ2(fmt, ...) { static int _index; if(_index == 0) \
    _index = log_resolve_index(&__FUNCTION__[4], 1); loq(_index, \
    &__FUNCTION__[4], is_success(ret), (int) ret, fmt, ##__VA_ARGS__); }

#define LOQ3(fmt, ...) { static int _index; if(_index == 0) \
    _index = log_resolve_index(&__FUNCTION__[4], 2); loq(_index, \
    &__FUNCTION__[4], is_success(ret), (int) ret, fmt, ##__VA_ARGS__); }

#define LOQspecial(fmt, ...) { static int _index; if(_index == 0) \
    _index = log_resolve_index(&__FUNCTION__[5], 0); loq(_index, \
    &__FUNCTION__[5], is_success(ret), (int) ret, fmt, ##__VA_ARGS__); }


#define IS_SUCCESS_NTSTATUS() int is_success(NTSTATUS ret) { \
    return NT_SUCCESS(ret); }
#define IS_SUCCESS_BOOL() int is_success(BOOL ret) { \
    return ret != FALSE; }
#define IS_SUCCESS_HHOOK() int is_success(HHOOK ret) { \
    return ret != NULL; }
#define IS_SUCCESS_HINTERNET() int is_success(HINTERNET ret) { \
    return ret != NULL; }
#define IS_SUCCESS_HRESULT() int is_success(HRESULT ret) { \
    return ret == S_OK; }
#define IS_SUCCESS_HANDLE() int is_success(HANDLE ret) { \
    return ret != NULL; }
#define IS_SUCCESS_HANDLE2() int is_success(HANDLE ret) { \
    return ret != NULL && ret != INVALID_HANDLE_VALUE; }
#define IS_SUCCESS_VOID() int is_success(int ret) { return TRUE; }
#define IS_SUCCESS_LONGREG() int is_success(LONG ret) { \
    return ret == ERROR_SUCCESS; }
#define IS_SUCCESS_SCHANDLE() int is_success(SC_HANDLE ret) { \
    return ret != NULL; }
#define IS_SUCCESS_DWORDTHREAD() int is_success(DWORD ret) { \
    return ret != (DWORD) -1; }
#define IS_SUCCESS_HWND() int is_success(HWND ret) { \
    return ret != NULL; }
#define IS_SUCCESS_ZERO() int is_success(int ret) { \
    return ret == 0; }
#define IS_SUCCESS_INTM1() int is_success(int ret) { \
    return ret != -1; }

#define ENSURE_DWORD(param) \
    DWORD _##param = 0; if(param == NULL) param = &_##param

#define ENSURE_ULONG(param) \
    ULONG _##param = 0; if(param == NULL) param = &_##param
#define ENSURE_ULONG_ZERO(param) \
    ENSURE_ULONG(param); else *param = 0

#define ENSURE_SIZET(param) \
    ULONG _##param = 0; if(param == NULL) param = &_##param
#define ENSURE_SIZET_ZERO(param) \
    ENSURE_ULONG(param); else *param = 0

#define ENSURE_CLIENT_ID(param) \
    CLIENT_ID _##param = {}; if(param == NULL) param = &_##param
