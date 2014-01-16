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

#ifndef __NTAPI_H__
#define __NTAPI_H__

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// for now..
typedef void *PIO_APC_ROUTINE;

typedef void *HINTERNET;

typedef struct addrinfo {
  int             ai_flags;
  int             ai_family;
  int             ai_socktype;
  int             ai_protocol;
  size_t          ai_addrlen;
  char            *ai_canonname;
  struct sockaddr  *ai_addr;
  struct addrinfo  *ai_next;
} ADDRINFOA, *PADDRINFOA;

typedef struct addrinfoW {
  int              ai_flags;
  int              ai_family;
  int              ai_socktype;
  int              ai_protocol;
  size_t           ai_addrlen;
  PWSTR            ai_canonname;
  struct sockaddr  *ai_addr;
  struct addrinfoW  *ai_next;
} ADDRINFOW, *PADDRINFOW;

typedef enum _KEY_INFORMATION_CLASS {
  KeyBasicInformation            = 0,
  KeyNodeInformation             = 1,
  KeyFullInformation             = 2,
  KeyNameInformation             = 3,
  KeyCachedInformation           = 4,
  KeyFlagsInformation            = 5,
  KeyVirtualizationInformation   = 6,
  KeyHandleTagsInformation       = 7,
  MaxKeyInfoClass                = 8
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
  KeyValueBasicInformation            = 0,
  KeyValueFullInformation             = 1,
  KeyValuePartialInformation          = 2,
  KeyValueFullInformationAlign64      = 3,
  KeyValuePartialInformationAlign64   = 4,
  MaxKeyValueInfoClass                = 5
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataOffset;
  ULONG DataLength;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
  ULONG TitleIndex;
  ULONG Type;
  ULONG DataLength;
  UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _KEY_VALUE_ENTRY {
    PUNICODE_STRING    ValueName;
    ULONG        DataLength;
    ULONG        DataOffset;
    ULONG        Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    void *PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef ULONG_PTR KAFFINITY;
typedef LONG KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _INITIAL_TEB {
  PVOID StackBase;
  PVOID StackLimit;
  PVOID StackCommit;
  PVOID StackCommitMax;
  PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef enum _FILE_INFORMATION_CLASS {
  FileDirectoryInformation = 1,
  FileFullDirectoryInformation,
  FileBothDirectoryInformation,
  FileBasicInformation,
  FileStandardInformation,
  FileInternalInformation,
  FileEaInformation,
  FileAccessInformation,
  FileNameInformation,
  FileRenameInformation,
  FileLinkInformation,
  FileNamesInformation,
  FileDispositionInformation,
  FilePositionInformation,
  FileFullEaInformation,
  FileModeInformation,
  FileAlignmentInformation,
  FileAllInformation,
  FileAllocationInformation,
  FileEndOfFileInformation,
  FileAlternateNameInformation,
  FileStreamInformation,
  FilePipeInformation,
  FilePipeLocalInformation,
  FilePipeRemoteInformation,
  FileMailslotQueryInformation,
  FileMailslotSetInformation,
  FileCompressionInformation,
  FileObjectIdInformation,
  FileCompletionInformation,
  FileMoveClusterInformation,
  FileQuotaInformation,
  FileReparsePointInformation,
  FileNetworkOpenInformation,
  FileAttributeTagInformation,
  FileTrackingInformation,
  FileIdBothDirectoryInformation,
  FileIdFullDirectoryInformation,
  FileValidDataLengthInformation,
  FileShortNameInformation,
  FileIoCompletionNotificationInformation,
  FileIoStatusBlockRangeInformation,
  FileIoPriorityHintInformation,
  FileSfioReserveInformation,
  FileSfioVolumeInformation,
  FileHardLinkInformation,
  FileProcessIdsUsingFileInformation,
  FileNormalizedNameInformation,
  FileNetworkPhysicalNameInformation,
  FileIdGlobalTxDirectoryInformation,
  FileIsRemoteDeviceInformation,
  FileAttributeCacheInformation,
  FileNumaNodeInformation,
  FileStandardLinkInformation,
  FileRemoteProtocolInformation,
  FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

#define STATUS_ACCESS_DENIED ((NTSTATUS) 0xc0000022)

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG                   MaximumLength;
    ULONG                   Length;
    ULONG                   Flags;
    ULONG                   DebugFlags;
    PVOID                   ConsoleHandle;
    ULONG                   ConsoleFlags;
    HANDLE                  StdInputHandle;
    HANDLE                  StdOutputHandle;
    HANDLE                  StdErrorHandle;
    UNICODE_STRING          CurrentDirectoryPath;
    HANDLE                  CurrentDirectoryHandle;
    UNICODE_STRING          DllPath;
    UNICODE_STRING          ImagePathName;
    UNICODE_STRING          CommandLine;
    PVOID                   Environment;
    ULONG                   StartingPositionLeft;
    ULONG                   StartingPositionTop;
    ULONG                   Width;
    ULONG                   Height;
    ULONG                   CharWidth;
    ULONG                   CharHeight;
    ULONG                   ConsoleTextAttributes;
    ULONG                   WindowFlags;
    ULONG                   ShowWindowFlags;
    UNICODE_STRING          WindowTitle;
    UNICODE_STRING          DesktopName;
    UNICODE_STRING          ShellInfo;
    UNICODE_STRING          RuntimeData;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void *PPS_CREATE_INFO, *PPS_ATTRIBUTE_LIST;

typedef void *PVOID, **PPVOID;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE {
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID BaseAddress;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE  Mutant;
    PVOID   ImageBaseAddress;
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID   SubSystemData;
    PVOID   ProcessHeap;
    PVOID   FastPebLock;
    void   *FastPebLockRoutine;
    void   *FastPebUnlockRoutine;
    ULONG   EnvironmentUpdateCount;
    PPVOID  KernelCallbackTable;
    PVOID   EventLogSection;
    PVOID   EventLog;
    void   *FreeList;
    ULONG   TlsExpansionCounter;
    PVOID   TlsBitmap;
    ULONG   TlsBitmapBits[0x2];
    PVOID   ReadOnlySharedMemoryBase;
    PVOID   ReadOnlySharedMemoryHeap;
    PPVOID  ReadOnlyStaticServerData;
    PVOID   AnsiCodePageData;
    PVOID   OemCodePageData;
    PVOID   UnicodeCaseTableData;
    ULONG   NumberOfProcessors;
    ULONG   NtGlobalFlag;
    BYTE    Spare2[0x4];
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG   HeapSegmentReserve;
    ULONG   HeapSegmentCommit;
    ULONG   HeapDeCommitTotalFreeThreshold;
    ULONG   HeapDeCommitFreeBlockThreshold;
    ULONG   NumberOfHeaps;
    ULONG   MaximumNumberOfHeaps;
    PPVOID *ProcessHeaps;
    PVOID   GdiSharedHandleTable;
    PVOID   ProcessStarterHelper;
    PVOID   GdiDCAttributeList;
    PVOID   LoaderLock;
    ULONG   OSMajorVersion;
    ULONG   OSMinorVersion;
    ULONG   OSBuildNumber;
    ULONG   OSPlatformId;
    ULONG   ImageSubSystem;
    ULONG   ImageSubSystemMajorVersion;
    ULONG   ImageSubSystemMinorVersion;
    ULONG   GdiHandleBuffer[0x22];
    ULONG   PostProcessInitRoutine;
    ULONG   TlsExpansionBitmap;
    BYTE    TlsExpansionBitmapBits[0x80];
    ULONG   SessionId;
} PEB, *PPEB;

typedef struct _SECTION_IMAGE_INFORMATION {
    VOID*        TransferAddress;
    ULONG32      ZeroBits;
    UINT8        _PADDING0_[0x4];
    UINT64       MaximumStackSize;
    UINT64       CommittedStackSize;
    ULONG32      SubSystemType;
    union {
        struct {
            UINT16       SubSystemMinorVersion;
            UINT16       SubSystemMajorVersion;
        };
        ULONG32      SubSystemVersion;
    };
    ULONG32      GpValue;
    UINT16       ImageCharacteristics;
    UINT16       DllCharacteristics;
    UINT16       Machine;
    UINT8        ImageContainsCode;
    union {
        UINT8        ImageFlags;
        struct {
            UINT8        ComPlusNativeReady : 1;
            UINT8        ComPlusILOnly : 1;
            UINT8        ImageDynamicallyRelocated : 1;
            UINT8        ImageMappedFlat : 1;
            UINT8        Reserved : 4;
        };
    };
    ULONG32      LoaderFlags;
    ULONG32      ImageFileSize;
    ULONG32      CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Size;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

#define FILE_NAME_INFORMATION_REQUIRED_SIZE \
    sizeof(FILE_NAME_INFORMATION) + sizeof(wchar_t) * MAX_PATH

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef enum  {
    FileFsVolumeInformation       = 1,
    FileFsLabelInformation        = 2,
    FileFsSizeInformation         = 3,
    FileFsDeviceInformation       = 4,
    FileFsAttributeInformation    = 5,
    FileFsControlInformation      = 6,
    FileFsFullSizeInformation     = 7,
    FileFsObjectIdInformation     = 8,
    FileFsDriverPathInformation   = 9,
    FileFsVolumeFlagsInformation  = 10,
    FileFsSectorSizeInformation   = 11
} FS_INFORMATION_CLASS;

typedef struct _FILE_FS_VOLUME_INFORMATION {
    LARGE_INTEGER VolumeCreationTime;
    ULONG         VolumeSerialNumber;
    ULONG         VolumeLabelLength;
    BOOLEAN       SupportsObjects;
    WCHAR         VolumeLabel[1];
} FILE_FS_VOLUME_INFORMATION, *PFILE_FS_VOLUME_INFORMATION;

#endif
