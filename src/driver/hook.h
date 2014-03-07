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
#define SHADOWSERVICE(_syscall) KeServiceDescriptorTableShadow[1].ServiceTableBase[_syscall]

// Syscalls numbers (XP)
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
#define CREATEMUTANT_INDEX 0x2B
#define DEVICEIOCONTROLFILE_INDEX 0x42
#define TERMINATEPROCESS_INDEX 0x101
#define DELAYEXECUTION_INDEX 0x3B
#define QUERYVALUEKEY_INDEX 0xB1
#define QUERYATTRIBUTESFILE_INDEX 0x8B
#define READVIRTUALMEMORY_INDEX 0xBA
#define RESUMETHREAD_INDEX 0xCE
#define CREATESECTION_INDEX 0x32
#define USERCALLONEPARAM_INDEX 0x143
#define LOADDRIVER_INDEX 0x61

// Syscalls numbers (7)
#define CREATETHREAD_7_INDEX 0x57
#define SETCONTEXTTHREAD_7_INDEX 0x13C
#define QUEUEAPCTHREAD_7_INDEX 0x10D
#define SYSTEMDEBUGCONTROL_7_INDEX 0x170
#define CREATEPROCESS_7_INDEX 0x4F
#define CREATEPROCESSEX_7_INDEX 0x50
#define CREATEUSERPROCESS_7_INDEX 0x5D
#define MAPVIEWOFSECTION_7_INDEX 0xa8
#define WRITEVIRTUALMEMORY_7_INDEX 0x18F
#define DEBUGACTIVEPROCESS_7_INDEX 0x60
#define OPENPROCESS_7_INDEX 0xbe
#define OPENTHREAD_7_INDEX 0xc6
#define QUERYSYSTEMINFORMATION_7_INDEX 0x105
#define CREATEFILE_7_INDEX 0x42
#define READFILE_7_INDEX 0x111
#define WRITEFILE_7_INDEX 0x18C
#define DELETEFILE_7_INDEX 0x66
#define SETINFORMATIONFILE_7_INDEX 0x149
#define QUERYINFORMATIONFILE_7_INDEX 0xe7
#define CREATEMUTANT_7_INDEX 0x4a
#define DEVICEIOCONTROLFILE_7_INDEX 0x6b
#define TERMINATEPROCESS_7_INDEX 0x172
#define DELAYEXECUTION_7_INDEX 0x62
#define QUERYVALUEKEY_7_INDEX 0x10a
#define QUERYATTRIBUTESFILE_7_INDEX 0xd9
#define READVIRTUALMEMORY_7_INDEX 0x115
#define RESUMETHREAD_7_INDEX 0x130
#define CREATESECTION_7_INDEX 0x54
#define USERCALLNOPARAM_7_INDEX 0x14d 
#define LOADDRIVER_7_INDEX 0x9B

typedef struct _ServiceDescriptorEntry {
     unsigned int *ServiceTableBase;
     unsigned int *ServiceCounterTableBase;
     unsigned int NumberOfServices;
     unsigned char *ParamTableBase;
 } ServiceDescriptorTableEntry, *pServiceDescriptorTableEntry;
#pragma pack()

typedef struct _SYSTEM_HANDLE_INFORMATION { 
	ULONG ProcessId; 
	UCHAR ObjectTypeNumber; 
	UCHAR Flags; 
	USHORT Handle; 
	PVOID Object; 
	ACCESS_MASK GrantedAccess; 
} _SYSTEM_HANDLE_INFORMATION, *P_SYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX { 
	ULONG NumberOfHandles; 
	_SYSTEM_HANDLE_INFORMATION Information[1]; 
} _SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX; 

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

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  UCHAR           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;


// Functions schemes definition
typedef NTSTATUS(*ZWSETCONTEXTTHREAD)(HANDLE, PCONTEXT); 
typedef NTSTATUS(*ZWMAPVIEWOFSECTION)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, SECTION_INHERIT, ULONG, ULONG);
typedef NTSTATUS(*ZWCREATETHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PINITIAL_TEB, BOOLEAN);
typedef NTSTATUS(*ZWQUEUEAPCTHREAD)(HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG);
typedef NTSTATUS(*ZWSYSTEMDEBUGCONTROL)(SYSDBG_COMMAND, PVOID, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(*ZWCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(*ZWCREATEPROCESSEX)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(*ZWCREATEUSERPROCESS)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG, PRTL_USER_PROCESS_PARAMETERS, PVOID, PVOID);
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
typedef NTSTATUS(*ZWCREATEMUTANT)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
typedef NTSTATUS(*ZWDEVICEIOCONTROLFILE)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(*ZWTERMINATEPROCESS)(HANDLE, NTSTATUS);
typedef NTSTATUS(*ZWDELAYEXECUTION)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(*ZWQUERYVALUEKEY)(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(*ZWQUERYATTRIBUTESFILE)(POBJECT_ATTRIBUTES, PFILE_BASIC_INFORMATION);
typedef NTSTATUS(*ZWREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(*ZWRESUMETHREAD)(HANDLE, PULONG);
typedef NTSTATUS(*ZWCREATESECTION)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef ULONG(*ZWUSERCALLONEPARAM)(ULONG, ULONG);
typedef ULONG(*ZWUSERCALLNOPARAM)(DWORD);
typedef NTSTATUS(*ZWLOADDRIVER)(PUNICODE_STRING);

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
ZWCREATEUSERPROCESS oldZwCreateUserProcess;
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
ZWCREATEMUTANT oldZwCreateMutant;
ZWDEVICEIOCONTROLFILE oldZwDeviceIoControlFile;
ZWTERMINATEPROCESS oldZwTerminateProcess;
ZWDELAYEXECUTION oldZwDelayExecution;
ZWQUERYVALUEKEY oldZwQueryValueKey;
ZWQUERYATTRIBUTESFILE oldZwQueryAttributesFile;
ZWREADVIRTUALMEMORY oldZwReadVirtualMemory;
ZWRESUMETHREAD oldZwResumeThread;
ZWCREATESECTION oldZwCreateSection;
ZWUSERCALLONEPARAM oldZwUserCallOneParam;
ZWUSERCALLNOPARAM oldZwUserCallNoParam;
ZWLOADDRIVER oldZwLoadDriver;

// SSDT import
__declspec(dllimport) ServiceDescriptorTableEntry KeServiceDescriptorTable;
__declspec(dllimport) KeAddSystemServiceTable(ULONG,ULONG,ULONG,ULONG,ULONG);

pServiceDescriptorTableEntry KeServiceDescriptorTableShadow;

/////////////////////////////////////////////////////////////////////////////		
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Get shadow table address
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
pServiceDescriptorTableEntry getShadowTableAddress();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		hook SSDT and Shadow SSDT tables
//	Parameters :
//		DWORD pid : python process identifier 
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt(ULONG pid);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs SSDT hooks (XP version)
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt_entries();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs SSDT hooks (7 version)
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt_entries_7();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Removes SSDT hooks (XP version)
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID unhook_ssdt_entries();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Removes SSDT hooks (7 version)
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID unhook_ssdt_entries_7();

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
//		Logs process creation.
//	Parameters :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//	Return value :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PVOID CreateInfo, PVOID AttributeList);

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

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs mutex creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs IOCTLs.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566441%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566441%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OuputBuffer, ULONG OutputBufferLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs process termination.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567115%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567115%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs delay execution.
//  Parameters :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html
//  Return value :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Hide VBOX keys.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Hide VBOX files
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/cc512135%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/cc512135%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs virtual memory read.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtReadVirtualMemory.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtReadVirtualMemory.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs resume thread
//  Parameters :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html
//  Return value :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process name creation.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Blocks shutdown attempts through ExWindowsEx
//	Parameters :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallOneParam
//	Return value :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallOneParam
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG newZwUserCallOneParam(ULONG Param, ULONG Routine);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Blocks shutdown attempts through ExWindowsEx (on Win7)
//	Parameters :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallNoParam
//	Return value :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallNoParam
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG newZwUserCallNoParam(ULONG Routine);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Block driver loading.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566470%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566470%28v=vs.85%29.aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwLoadDriver(PUNICODE_STRING DriverServiceName);

#endif
