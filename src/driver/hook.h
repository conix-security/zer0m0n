////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n DRIVER
//
//  Copyright 2013 Conix Security, Nicolas Correia, Adrien Chevalier
//
//  This file is part of zer0m0n.
//
//  Zer0m0n is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Zer0m0n is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Zer0m0n.  If not, see <http://www.gnu.org/licenses/>.
//
//
//	File :		hook.h
//	Abstract :	SSDT hooks handling
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 
//		TODO : add rootkit features to block / hide vbox / cuckoo
//		-> only known techniques (TBD)
//		TODO : log handles
//		TODO : handle hidden threads
/////////////////////////////////////////////////////////////////////////////

#ifndef __HOOK_H
#define __HOOK_H

#include <fltkernel.h>

/////////////////////////////////////////////////////////////////////////////
// DEFINES
/////////////////////////////////////////////////////////////////////////////

// SSDT entry access macro
#define SYSTEMSERVICE(_syscall) KeServiceDescriptorTable.ServiceTableBase[_syscall]

// Syscalls numbers (XP SP3)
#define CREATETHREAD_INDEX 0x35
#define SETCONTEXTTHREAD_INDEX 0xD5
#define QUEUEAPCTHREAD_INDEX 0xB4
#define SYSTEMDEBUGCONTROL_INDEX 0xFF
#define CREATEPROCESS_INDEX 0x2F
#define CREATEPROCESSEX_INDEX 0x30
#define MAPVIEWOFSECTION_INDEX 0x6C
#define WRITEVIRTUALMEMORY_INDEX 0x115
#define DEBUGACTIVEPROCESS_INDEX 0x39
#define OPENPROCESS_INDEX 0x7A
#define OPENTHREAD_INDEX 0x80
#define QUERYSYSTEMINFORMATION_INDEX 0xAD
#define CREATEFILE_INDEX 0x25
#define READFILE_INDEX 0xb7
#define WRITEFILE_INDEX 0x112
#define DELETEFILE_INDEX 0x3e
#define SETINFORMATIONFILE_INDEX 0xe0
#define QUERYINFORMATIONFILE_INDEX 0x97

/////////////////////////////////////////////////////////////////////////////		
// STRUCTS
/////////////////////////////////////////////////////////////////////////////

// SSDT entry struct
#pragma pack(1)
typedef struct _ServiceDescriptorEntry {
     unsigned int *ServiceTableBase;
     unsigned int *ServiceCounterTableBase;
     unsigned int NumberOfServices;
     unsigned char *ParamTableBase;
 } ServiceDescriptorTableEntry, *pServiceDescriptorTableEntry;
#pragma pack()


/////////////////////////////////////////////////////////////////////////////		
// HOOKED FUNCTIONS RELATED STRUCTS
/////////////////////////////////////////////////////////////////////////////		
typedef struct _INITIAL_TEB {
        PVOID StackBase;
        PVOID StackLimit;
        PVOID StackCommit;
        PVOID StackCommitMax;
        PVOID StackReserved;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset; 
	ULONG NumberOfThreads; 
	LARGE_INTEGER Reserved[3]; 
	LARGE_INTEGER CreateTime; 
	LARGE_INTEGER UserTime; 
	LARGE_INTEGER KernelTime; 
	UNICODE_STRING ImageName; 
	KPRIORITY BasePriority; 
	HANDLE ProcessId; 
	HANDLE InheritedFromProcessId; 
	ULONG HandleCount; 
	ULONG Reserved2[2];
	ULONG PrivatePageCount; 
	VM_COUNTERS VirtualMemoryCounters; 
	IO_COUNTERS IoCounters; 
	PVOID Threads[0];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;	

typedef enum _SYSDBG_COMMAND {
    SysDbgQueryModuleInformation=1,
    SysDbgQueryTraceInformation,
    SysDbgSetTracepoint,
    SysDbgSetSpecialCall,
    SysDbgClearSpecialCalls,
    SysDbgQuerySpecialCalls
} SYSDBG_COMMAND, *PSYSDBG_COMMAND;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,	
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemWhatTheFuckInformation,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS	ExitStatus;
    PVOID	TebBaseAddress;
    CLIENT_ID	ClientId;
    ULONG	AffinityMask;
    ULONG	Priority;
    ULONG	BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// Functions schemes definition
typedef NTSTATUS(*ZWSETCONTEXTTHREAD)(HANDLE, PCONTEXT); 
typedef NTSTATUS(*ZWMAPVIEWOFSECTION)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(*ZWCREATETHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PINITIAL_TEB, BOOLEAN);
typedef NTSTATUS(*ZWQUEUEAPCTHREAD)(HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG);
typedef NTSTATUS(*ZWSYSTEMDEBUGCONTROL)(SYSDBG_COMMAND, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(*ZWCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(*ZWCREATEPROCESSEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(*ZWWRITEVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(*ZWDEBUGACTIVEPROCESS)(HANDLE, HANDLE);
typedef NTSTATUS(*ZWOPENPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(*ZWOPENTHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*ZWCREATEFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(*ZWREADFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(*ZWWRITEFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(*ZWDELETEFILE)(POBJECT_ATTRIBUTES);
typedef NTSTATUS(*ZWSETINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(*ZWQUERYINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS(*ZWUNLOADDRIVER)(PUNICODE_STRING DriverServiceName);

/////////////////////////////////////////////////////////////////////////////		
// GLOBALS
/////////////////////////////////////////////////////////////////////////////

// original functions addresses
ZWMAPVIEWOFSECTION oldZwMapViewOfSection;
ZWSETCONTEXTTHREAD oldZwSetContextThread;
ZWCREATETHREAD oldZwCreateThread;
ZWQUEUEAPCTHREAD oldZwQueueApcThread;
ZWCREATEPROCESS oldZwCreateProcess;
ZWSYSTEMDEBUGCONTROL oldZwSystemDebugControl;
ZWCREATEPROCESSEX oldZwCreateProcessEx;
ZWWRITEVIRTUALMEMORY oldZwWriteVirtualMemory;
ZWDEBUGACTIVEPROCESS oldZwDebugActiveProcess;
ZWOPENPROCESS oldZwOpenProcess;
ZWOPENTHREAD oldZwOpenThread;
ZWQUERYSYSTEMINFORMATION oldZwQuerySystemInformation;
ZWCREATEFILE oldZwCreateFile;
ZWREADFILE oldZwReadFile;
ZWWRITEFILE oldZwWriteFile;
ZWDELETEFILE oldZwDeleteFile;
ZWSETINFORMATIONFILE oldZwSetInformationFile;
ZWQUERYINFORMATIONFILE oldZwQueryInformationFile;
ZWUNLOADDRIVER oldZwUnloadDriver;

// SSDT import
__declspec(dllimport) ServiceDescriptorTableEntry KeServiceDescriptorTable;


/////////////////////////////////////////////////////////////////////////////		
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs SSDT hooks.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt_entries();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Removes SSDT hooks.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID unhook_ssdt_entries();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsets WP bit of CR0 register (allows writing into SSDT).
//		See http://en.wikipedia.org/wiki/Control_register#CR0
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void disable_cr0();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sets WP bit of CR0 register.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void enable_cr0();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread opening, and hides specific processes from the monitored processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process opening (mandatory for most of code injection techniques), and hides specific processes from the monitored processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567022(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567022(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process information retrieval, and hides specific processes from the monitored processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/desktop/ms725506(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/desktop/ms725506(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs virtual memory modification.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-02/0195.html (lulz)
//	Return value :
//		See http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-02/0195.html (lulz)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE jesaispas);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread-based Asynchronous Procedure Call creation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs section mapping (may be used for code injection).
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread context manipulation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSetContextThread(HANDLE ThreadHandle, PCONTEXT Context);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging operations (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging (may be used for code injection).
//	Parameters :
//		See http://www.openrce.org/articles/full_view/26
//	Return value :
//		See http://www.openrce.org/articles/full_view/26
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file creation and/or file opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//  Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file reading.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file modification.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion / rename.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file information access.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567052(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567052(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

#endif
