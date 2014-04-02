#include <windows.h>
#include <stdio.h>

#define FILE_DELETE_ON_CLOSE 0x00001000

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}
typedef VOID(WINAPI *RTLINITUNICODESTRING)(PUNICODE_STRING,PCWSTR);
typedef NTSTATUS(WINAPI *NTCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PVOID, PVOID, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(WINAPI *NTCLOSE)(HANDLE);
typedef NTSTATUS(WINAPI *NTDELETEFILE)(POBJECT_ATTRIBUTES);
NTCREATEFILE NtCreateFile;
NTCLOSE NtClose;
NTDELETEFILE NtDeleteFile;
RTLINITUNICODESTRING RtlInitUnicodeString;

main()
{	
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr;
	ULONG iosb[2];
	UNICODE_STRING pathfile;
	
	// import all the functions we need
	NtCreateFile = (NTCREATEFILE)GetProcAddress(LoadLibrary("ntdll.dll"), "NtCreateFile");
	NtClose = (NTCLOSE)GetProcAddress(LoadLibrary("ntdll.dll"), "NtClose");
	NtDeleteFile = (NTDELETEFILE)GetProcAddress(LoadLibrary("ntdll.dll"), "NtDeleteFile");
	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(LoadLibrary("ntdll.dll"), "RtlInitUnicodeString"); 

	// delete file using file_delete_on_close trick
	RtlInitUnicodeString(&pathfile, L"\\??\\C:\\Program Files\\Internet Explorer\\HMMAPI.DLL");
	InitializeObjectAttributes(&objAttr, &pathfile, 0x40, NULL, NULL);
	NtCreateFile(&hFile, DELETE, &objAttr, iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0, 1, FILE_DELETE_ON_CLOSE, 0, 0);
	NtClose(hFile);

	// delete file using DeleteFile() which is SetInformationFile() in kernel
	DeleteFileA("C:\\Program Files\\Internet Explorer\\iedw.exe");
	
	// delete file using NtDeleteFile()
	RtlInitUnicodeString(&pathfile, L"\\??\\C:\\Program Files\\Internet Explorer\\iexplore.exe");
	InitializeObjectAttributes(&objAttr, &pathfile, 0x40, NULL, NULL);
	NtDeleteFile(&objAttr);
}
