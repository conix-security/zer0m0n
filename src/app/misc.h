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

#include "main.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)


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

typedef struct _FILE_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

#define FILE_NAME_INFORMATION_REQUIRED_SIZE \
    sizeof(FILE_NAME_INFORMATION) + sizeof(wchar_t) * MAX_PATH

typedef struct _CLIENT_ID {
  HANDLE UniqueProcess;
  HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS                ExitStatus;
  PVOID                   TebBaseAddress;
  CLIENT_ID               ClientId;
  ULONG 	              AffinityMask;
  ULONG		              Priority;
  ULONG					  BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

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

typedef struct _PROCESS_BASIC_INFORMATION {
      NTSTATUS ExitStatus;
      PVOID PebBaseAddress;
      ULONG AffinityMask;
      ULONG BasePriority;
      ULONG UniqueProcessId;
      ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

ULONG_PTR parent_process_id(); // By Napalm @ NetCore2K (rohitab.com)
DWORD pid_from_process_handle(HANDLE process_handle);
DWORD pid_from_thread_handle(HANDLE thread_handle);
DWORD random();
DWORD randint(DWORD min, DWORD max);
BOOL is_directory_objattr(const OBJECT_ATTRIBUTES *obj);
//void hide_module_from_peb(HMODULE module_handle);

int path_from_handle(HANDLE handle, wchar_t *path);
int path_from_object_attributes(const OBJECT_ATTRIBUTES *obj, wchar_t *path);
int ensure_absolute_path(wchar_t *out, const wchar_t *in, int length);

// imported but for some doesn't show up when #including string.h etc
/*int wcsnicmp(const wchar_t *a, const wchar_t *b, int len);
int wcsicmp(const wchar_t *a, const wchar_t *b);
*/