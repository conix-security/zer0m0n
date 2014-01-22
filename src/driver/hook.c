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
//	File :		hook.c
//	Abstract :	SSDT hooks handling
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26
//	Notes : 
//		
////////////////////////////////////////////////////////////////////////////
#include "hook.h"
#include "main.h"
#include "utils.h"
#include "monitor.h"
#include "comm.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs SSDT hooks.
//	Parameters :
//		None
//	Return value :
//		None
//	Process :
//		Unset WP bit from CR0 register to be able to modify SSDT entries, restores the original values,
//		and sets WP bit again.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

VOID unhook_ssdt_entries()
{
	disable_cr0();
	
	(ZWCREATETHREAD)SYSTEMSERVICE(CREATETHREAD_INDEX) = oldZwCreateThread;
	(ZWMAPVIEWOFSECTION)SYSTEMSERVICE(MAPVIEWOFSECTION_INDEX) = oldZwMapViewOfSection;
	(ZWSETCONTEXTTHREAD)SYSTEMSERVICE(SETCONTEXTTHREAD_INDEX) = oldZwSetContextThread;
	(ZWQUEUEAPCTHREAD)SYSTEMSERVICE(QUEUEAPCTHREAD_INDEX) = oldZwQueueApcThread;
	(ZWSYSTEMDEBUGCONTROL)SYSTEMSERVICE(SYSTEMDEBUGCONTROL_INDEX) = oldZwSystemDebugControl;
	(ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_INDEX) = oldZwCreateProcess;
	(ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_INDEX) = oldZwCreateProcessEx;
	(ZWWRITEVIRTUALMEMORY)SYSTEMSERVICE(WRITEVIRTUALMEMORY_INDEX) = oldZwWriteVirtualMemory;
	(ZWDEBUGACTIVEPROCESS)SYSTEMSERVICE(DEBUGACTIVEPROCESS_INDEX) = oldZwDebugActiveProcess;
	(ZWOPENPROCESS)SYSTEMSERVICE(OPENPROCESS_INDEX) = oldZwOpenProcess;
	(ZWOPENTHREAD)SYSTEMSERVICE(OPENTHREAD_INDEX) = oldZwOpenThread;
	(ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(QUERYSYSTEMINFORMATION_INDEX) = oldZwQuerySystemInformation;
	(ZWCREATEFILE)SYSTEMSERVICE(CREATEFILE_INDEX) = oldZwCreateFile;
	(ZWREADFILE)SYSTEMSERVICE(READFILE_INDEX) = oldZwReadFile;
	(ZWWRITEFILE)SYSTEMSERVICE(WRITEFILE_INDEX) = oldZwWriteFile;
	(ZWDELETEFILE)SYSTEMSERVICE(DELETEFILE_INDEX) = oldZwDeleteFile;
	(ZWSETINFORMATIONFILE)SYSTEMSERVICE(SETINFORMATIONFILE_INDEX) = oldZwSetInformationFile;
	(ZWQUERYINFORMATIONFILE)SYSTEMSERVICE(QUERYINFORMATIONFILE_INDEX) = oldZwQueryInformationFile;
	
	enable_cr0();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs SSDT hooks.
//	Parameters :
//		None
//	Return value :
//		None
//	Process :
//		Unset WP bit from CR0 register to be able to modify SSDT entries, patch with our values after,
//		saving the original ones, and set the WP bit again.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt_entries()
{
	disable_cr0();
	
	oldZwCreateThread = (ZWCREATETHREAD)SYSTEMSERVICE(CREATETHREAD_INDEX);
	(ZWCREATETHREAD)SYSTEMSERVICE(CREATETHREAD_INDEX) = newZwCreateThread;
	
	oldZwSetContextThread = (ZWSETCONTEXTTHREAD)SYSTEMSERVICE(SETCONTEXTTHREAD_INDEX);
	(ZWSETCONTEXTTHREAD)SYSTEMSERVICE(SETCONTEXTTHREAD_INDEX) = newZwSetContextThread;
	
	oldZwQueueApcThread = (ZWQUEUEAPCTHREAD)SYSTEMSERVICE(QUEUEAPCTHREAD_INDEX);
	(ZWQUEUEAPCTHREAD)SYSTEMSERVICE(QUEUEAPCTHREAD_INDEX) = newZwQueueApcThread;
	
	oldZwWriteVirtualMemory = (ZWWRITEVIRTUALMEMORY)SYSTEMSERVICE(WRITEVIRTUALMEMORY_INDEX);
	(ZWWRITEVIRTUALMEMORY)SYSTEMSERVICE(WRITEVIRTUALMEMORY_INDEX) = newZwWriteVirtualMemory;
	
	oldZwSystemDebugControl = (ZWSYSTEMDEBUGCONTROL)SYSTEMSERVICE(SYSTEMDEBUGCONTROL_INDEX);
	(ZWSYSTEMDEBUGCONTROL)SYSTEMSERVICE(SYSTEMDEBUGCONTROL_INDEX) = newZwSystemDebugControl;
	
	oldZwCreateProcess = (ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_INDEX);
	(ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_INDEX) = newZwCreateProcess;
	
	oldZwCreateProcessEx = (ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_INDEX);
	(ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_INDEX) = newZwCreateProcessEx;
	
	oldZwMapViewOfSection = (ZWMAPVIEWOFSECTION)SYSTEMSERVICE(MAPVIEWOFSECTION_INDEX);
	(ZWMAPVIEWOFSECTION)SYSTEMSERVICE(MAPVIEWOFSECTION_INDEX) = newZwMapViewOfSection;
	
	oldZwDebugActiveProcess = (ZWDEBUGACTIVEPROCESS)SYSTEMSERVICE(DEBUGACTIVEPROCESS_INDEX);
	(ZWDEBUGACTIVEPROCESS)SYSTEMSERVICE(DEBUGACTIVEPROCESS_INDEX) = newZwDebugActiveProcess;
	
	oldZwOpenProcess = (ZWOPENPROCESS)SYSTEMSERVICE(OPENPROCESS_INDEX);
	(ZWOPENPROCESS)SYSTEMSERVICE(OPENPROCESS_INDEX) = newZwOpenProcess;
	
	oldZwOpenThread = (ZWOPENTHREAD)SYSTEMSERVICE(OPENTHREAD_INDEX);
	(ZWOPENTHREAD)SYSTEMSERVICE(OPENTHREAD_INDEX) = newZwOpenThread;
	
	oldZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(QUERYSYSTEMINFORMATION_INDEX);
	(ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(QUERYSYSTEMINFORMATION_INDEX) = newZwQuerySystemInformation;
	
	oldZwCreateFile = (ZWCREATEFILE)SYSTEMSERVICE(CREATEFILE_INDEX);
	(ZWCREATEFILE)SYSTEMSERVICE(CREATEFILE_INDEX) = newZwCreateFile;
	
	oldZwReadFile = (ZWREADFILE)SYSTEMSERVICE(READFILE_INDEX);
	(ZWREADFILE)SYSTEMSERVICE(READFILE_INDEX) = newZwReadFile;
	
	oldZwWriteFile = (ZWWRITEFILE)SYSTEMSERVICE(WRITEFILE_INDEX);
	(ZWWRITEFILE)SYSTEMSERVICE(WRITEFILE_INDEX) = newZwWriteFile;
	
	oldZwDeleteFile = (ZWDELETEFILE)SYSTEMSERVICE(DELETEFILE_INDEX);
	(ZWDELETEFILE)SYSTEMSERVICE(DELETEFILE_INDEX) = newZwDeleteFile;
	
	oldZwSetInformationFile = (ZWSETINFORMATIONFILE)SYSTEMSERVICE(SETINFORMATIONFILE_INDEX);
	(ZWSETINFORMATIONFILE)SYSTEMSERVICE(SETINFORMATIONFILE_INDEX) = newZwSetInformationFile;
	
	oldZwQueryInformationFile = (ZWQUERYINFORMATIONFILE)SYSTEMSERVICE(QUERYINFORMATIONFILE_INDEX);
	(ZWQUERYINFORMATIONFILE)SYSTEMSERVICE(QUERYINFORMATIONFILE_INDEX) = newZwQueryInformationFile;
	
	enable_cr0();
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread opening, and hides specific processes from the monitored processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//	Process :
//		Calls the original function and if it succeeds, gets the TID by handle. If the PID is hidden
//		closes the handle and returns STATUS_INVALID_PARAMETER.
//		It the call failed, if ClientID is not NULL, copies the ClientID->UniqueThread parameter and
//		logs it. If ClientID is NULL (XP / s2003), copies the ObjectAttributes->ObjectName parameter
//		and logs it.
//	TODO :
//		- while blocking a call, restore the original *ThreadHandle value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc, tid, pid, kUniqueThread;
	UNICODE_STRING kObjectName;
	HANDLE kThreadHandle;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	PETHREAD eThread = NULL;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWOPENTHREAD)(oldZwOpenThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ClientID);
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		if(NT_SUCCESS(statusCall))
		{
			__try 
			{
				if(ExGetPreviousMode() != KernelMode)
					ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
				kThreadHandle = *ThreadHandle;
			} 
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				errorCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ThreadHandle->-1,TID->-1,DesiredAccess->-1",errorCode)))
					sendLogs(currentProc, L"ZwOpenThread", parameter);
				else
					sendLogs(currentProc, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->-1,TID->-1,DesiredAccess->1");
				ExFreePool(parameter);
				return errorCode;
			}
		
			tid = getTIDByHandle(kThreadHandle);
			if(NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)tid, &eThread)))
				pid = *(DWORD*)((PCHAR)eThread+0x1EC);
			else
				pid = -1;
			
			if(isProcessHiddenByPid(pid))
			{
				ZwClose(kThreadHandle);
				if(parameter && RtlStringCchPrintfW(parameter, MAXSIZE, L"0,3221225485,sss,ThreadHandle->-1,TID->%d,DesiredAccess->0x%08x", tid, DesiredAccess))
					sendLogs(currentProc, L"ZwOpenThread", parameter);
				else
					sendLogs(currentProc, L"ZwOpenThread", L"0,3221225485,sss,ThreadHandle->-1,TID->-1,DesiredAccess->-1");
				return STATUS_INVALID_PARAMETER;
			}
			
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ThreadHandle->0x%08x,TID->%d,DesiredAccess->0x%08x", kThreadHandle, tid, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			// recup le tid
			if(ClientID != NULL)
			{
				__try 
				{
					if(ExGetPreviousMode() != KernelMode)
						ProbeForRead(ClientID, sizeof(CLIENT_ID), 1);
					kUniqueThread = (ULONG)ClientID->UniqueThread;
				} 
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					errorCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ThreadHandle->-1,TID->-1,DesiredAccess->-1", errorCode)))
						sendLogs(currentProc, L"ZwOpenThread", parameter);
					else 
						sendLogs(currentProc, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->-1,TID->-1,DesiredAccess->-1");
					if(parameter)
						ExFreePool(parameter);
					return statusCall;
				}
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,0,sss,ThreadHandle->-1,TID->%d,DesiredAccess->0x%08x", kUniqueThread, DesiredAccess)))
					log_lvl = LOG_PARAM;
			}
			else
			{
				__try 
				{
					if(ExGetPreviousMode() != KernelMode)
					{
						ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
						ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
						ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
					}
					kObjectName.Length = ObjectAttributes->ObjectName->Length;
					kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
					kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
					if(kObjectName.Buffer)
						RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
					else
					{
						if(parameter)
							ExFreePool(parameter);
						sendLogs(currentProc, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->-1,TID->-1,DesiredAccess->-1");
						return statusCall;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					errorCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ThreadHandle->-1,TID->-1,DesiredAccess->-1", errorCode)))
						sendLogs(currentProc, L"ZwOpenThread", parameter);
					else 
						sendLogs(currentProc, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->-1,TID->-1,DesiredAccess->-1");
					if(parameter)
						ExFreePool(parameter);
					if(kObjectName.Buffer)
						ExFreePool(kObjectName.Buffer);
					return statusCall;
				}
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,0,sss,ThreadHandle->-1,TID->%wZ,DesiredAccess->0x%08x", &kObjectName, DesiredAccess)))
					log_lvl = LOG_PARAM;
				if(kObjectName.Buffer)
					ExFreePool(kObjectName.Buffer);
			}
		}

		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwOpenThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwOpenThread", L"1,0,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return statusCall;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process opening (mandatory for most of code injection techniques), and hides specific
//		processes from the monitored processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567022(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567022(v=vs.85).aspx
//	Process :
//		Calls the original function and if it succeeds, gets the PID by handle. If the PID is hidden
//		closes the handle and returns STATUS_INVALID_PARAMETER.
//		It the call failed, if ClientID is not NULL, copies the ClientID->UniqueThread parameter and
//		logs it. If ClientID is NULL (XP / s2003), copies the ObjectAttributes->ObjectName parameter
//		and logs it.
//	TODO :
//		- while blocking a call, restore the original *ProcessHandle value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
{	
	NTSTATUS statusCall, status, errorCode;
	ULONG currentProc, kUniqueProcess, i, pid;
	UNICODE_STRING kObjectName, remoteProc;
	HANDLE kRootDirectory, kProcessHandle;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;

	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWOPENPROCESS)(oldZwOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientID);
	if(isProcessMonitoredByPid(currentProc))
	{   	
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		remoteProc.Length = 0;
		remoteProc.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
		remoteProc.Buffer = ExAllocatePoolWithTag(NonPagedPool, remoteProc.MaximumLength, PROCNAME_TAG);
		
		if(NT_SUCCESS(statusCall))
		{
			__try 
			{
				if(ExGetPreviousMode() != KernelMode)
					ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				kProcessHandle = *ProcessHandle;
			} 
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				errorCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->-1,ProcessName->-1,PID->-1,DesiredAccess->-1",errorCode)))
					sendLogs(currentProc, L"ZwOpenProcess", parameter);
				else
					sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->-1,ProcessName->-1,PID->-1,DesiredAccess->1");
				ExFreePool(parameter);
				return errorCode;
			}
		
			pid = getPIDByHandle(kProcessHandle);
			if(remoteProc.Buffer)
				status = getProcNameByPID(pid, &remoteProc);
			else
				status = -1;
				
			if(isProcessHiddenByPid(pid))
			{
				ZwClose(kProcessHandle);
				if(parameter && NT_SUCCESS(status) && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,-1,ssss,ProcessHandle->0x%08x,ProcessName->%wZ,PID->%d,DesiredAccess->0x%08x", kProcessHandle, &remoteProc, pid, DesiredAccess)))
					sendLogs(currentProc, L"ZwOpenProcess", parameter);
				else
					sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->-1,ProcessName->Error_HIDDEN,PID->-1,DesiredAccess->-1");
				
				if(remoteProc.Buffer)
					ExFreePool(remoteProc.Buffer);
				if(parameter)
					ExFreePool(parameter);
				return STATUS_INVALID_PARAMETER;
			}
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(status) && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,ProcessHandle->0x%08x,ProcessName->%wZ,PID->%d,DesiredAccess->0x%08x", kProcessHandle, &remoteProc, pid, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		else
		{	
			log_lvl = LOG_ERROR;
			if(ClientID != NULL)
			{
				__try 
				{
					if(ExGetPreviousMode() != KernelMode)
						ProbeForRead(ClientID, sizeof(CLIENT_ID), 1);
					kUniqueProcess = (ULONG)ClientID->UniqueProcess;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					errorCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->-1,ProcessName->-1,PID->-1,DesiredAccess->-1", errorCode)))
						sendLogs(currentProc, L"ZwOpenProcess", parameter);
					else 
						sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->-1,ProcessName->-1,PID->-1,DesiredAccess->-1");
					if(parameter)
						ExFreePool(parameter);
					if(remoteProc.Buffer)
						ExFreePool(remoteProc.Buffer);
					return statusCall;
				}
				
				if(remoteProc.Buffer)
					status = getProcNameByPID(kUniqueProcess, &remoteProc);
				else
					status = -1;
				
				if(parameter && NT_SUCCESS(status) && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->-1,ProcessName->%wZ,PID->%d,DesiredAccess->0x%08x", statusCall,&remoteProc, kUniqueProcess, DesiredAccess)))
					log_lvl = LOG_PARAM;
			}
			else
			{
				__try 
				{
					if(ExGetPreviousMode() != KernelMode)
					{
						ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
						ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
						ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
					}
					kObjectName.Length = ObjectAttributes->ObjectName->Length;
					kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
					kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
					if(kObjectName.Buffer)
						RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
					else
					{
						if(parameter)
							ExFreePool(parameter);
						if(remoteProc.Buffer)
							ExFreePool(remoteProc.Buffer);
						sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->-1,ProcessName->-1,PID->-1,DesiredAccess->-1");
						return statusCall;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					errorCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->-1,ProcessName->-1,PID->-1,DesiredAccess->-1", errorCode)))
						sendLogs(currentProc, L"ZwOpenProcess", parameter);
					else 
						sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->-1,ProcessName->-1,PID->-1,DesiredAccess->-1");
					if(parameter)
						ExFreePool(parameter);
					if(remoteProc.Buffer)
						ExFreePool(remoteProc.Buffer);
					if(kObjectName.Buffer)
						ExFreePool(kObjectName.Buffer);
					return statusCall;
				}
				if(parameter && kObjectName.Buffer && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->-1,ProcessName->%wZ,PID->-1,DesiredAccess->0x%08x", statusCall,&kObjectName,DesiredAccess)))
				{
					log_lvl = LOG_PARAM;
					ExFreePool(kObjectName.Buffer);
				}
			}
		}		
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwOpenProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwOpenProcess", L"1,0,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(remoteProc.Buffer)
			ExFreePool(remoteProc.Buffer);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process information retrieval, and hides specific processes from the monitored processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/desktop/ms725506(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/desktop/ms725506(v=vs.85).aspx
//	Process :
//		Checks the information type. If SystemProcessInformation (enumerate running processes), the
//		hidden PIDs are unlinked from the result (SYSTEM_PROCESS_INFORMATION linked list).
//	Todo :
//		- Hide also thread listing
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS statusCall;
	ULONG currentProc, tid, i;
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = NULL, pPrev = NULL;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	
	statusCall = ((ZWQUERYSYSTEMINFORMATION)(oldZwQuerySystemInformation))(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if(isProcessMonitoredByPid(currentProc))
	{
		if(NT_SUCCESS(statusCall))
		{
			if(SystemInformationClass == SystemProcessInformation)
			{
				pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
				pPrev = pSystemProcessInformation;
				
				while(pSystemProcessInformation->NextEntryOffset)
				{
					if(isProcessHiddenByPid((ULONG)pSystemProcessInformation->ProcessId))
						pPrev->NextEntryOffset += pSystemProcessInformation->NextEntryOffset;	// UNLINK
					
					pPrev = pSystemProcessInformation;
					pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((char*)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
				}
				
				sendLogs(currentProc, L"ZwQuerySystemInformation",L"1,0,s,SystemInformationClass->5");
				return statusCall;
			}
			else
			{
				log_lvl = LOG_SUCCESS;
				parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,SystemInformationClass->%d", SystemInformationClass)))
					log_lvl = LOG_PARAM;
			}
		}
		else
		{
			log_lvl = LOG_ERROR;
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,SystemInformationClass->%d", statusCall, SystemInformationClass)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwQuerySystemInformation", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwQuerySystemInformation", L"0,-1,s,SystemInformationClass->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwQuerySystemInformation", L"1,0,s,SystemInformationClass->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs virtual memory modification.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//	Process :
//		Adds the process to the monitored processes list and logs the BaseAddress, Buffer, ProcessHandle, and NumberOfBytesToWrite parameters.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	NTSTATUS statusCall;
	ULONG currentProc, remotePid;
	PWCHAR parameter = NULL;
	ULONG log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWWRITEVIRTUALMEMORY)(oldZwWriteVirtualMemory))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		remotePid = getPIDByHandle(ProcessHandle);
		
		if(NT_SUCCESS(statusCall) && remotePid)
			startMonitoringProcess(remotePid);
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,Buffer->0x%08x,NumberOfBytesToWrite->%d", ProcessHandle, remotePid, BaseAddress, Buffer, NumberOfBytesToWrite)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,Buffer->0x%08x,NumberOfBytesToWrite->%d", statusCall, ProcessHandle, remotePid, BaseAddress, Buffer, NumberOfBytesToWrite)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwWriteVirtualMemory", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwWriteVirtualMemory", L"0,1,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,Buffer->ERROR,NumberOfBytesToWrite->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwWriteVirtualMemory", L"1,0,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,Buffer->ERROR,NumberOfBytesToWrite->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging (may be used for code injection).
//	Parameters :
//		See http://www.openrce.org/articles/full_view/26
//	Return value :
//		See http://www.openrce.org/articles/full_view/26
//	Process :
//		Adds the process to the monitored processes list and logs the PID, ProcessHandle and DebugHandle parameters
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle)
{
	NTSTATUS statusCall;
	ULONG remotePid, currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWDEBUGACTIVEPROCESS)(oldZwDebugActiveProcess))(ProcessHandle, DebugHandle);
	
	if(isProcessMonitoredByPid(currentProc))
	{		
		remotePid = getPIDByHandle(ProcessHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ProcessHandle->0x%08x,PID->%d,DebugHandle->0x%08x", ProcessHandle, remotePid, DebugHandle)))
				log_lvl = LOG_PARAM;
			if(remotePid)
				startMonitoringProcess(remotePid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ProcessHandle->0x%08x,PID->%d,DebugHandle->0x%08x", statusCall, ProcessHandle, remotePid, DebugHandle)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwDebugActiveProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwDebugActiveProcess", L"0,-1,sss,ProcessHandle->ERROR,PID->ERROR,DebugHandle->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwDebugActiveProcess", L"1,0,sss,ProcessHandle->ERROR,PID->ERROR,DebugHandle->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//	Process :
//		Starts the process, gets its PID and adds it to the monitored processes list, copies
//		ObjectAttributes->ObjectName parameter then logs.
//	TODO : 
//		- also log ProcessHandle, DesiredAccess, InheritObjectTable, ParentProcess
//		- also log Filename (& Commandline) parameters
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc, child_pid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	HANDLE kRootDirectory, kProcessHandle;
	UNICODE_STRING full_path, kObjectName;
	POBJECT_NAME_INFORMATION nameInfo = NULL;
	full_path.Buffer = NULL;
	kObjectName.Buffer = NULL;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEPROCESS)(oldZwCreateProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		kObjectName.Buffer = NULL;
		
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
			{
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				if(ObjectAttributes)
				{
					ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
					ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
					ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
				}
			}	
			kProcessHandle = *ProcessHandle;
			child_pid = getPIDByHandle(kProcessHandle);
			if(ObjectAttributes)
			{
				kRootDirectory = ObjectAttributes->RootDirectory;
				kObjectName.Length = ObjectAttributes->ObjectName->Length;
				kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
				kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			errorCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritObjectTable->-1,ParentProcess->-1,FileName->-1", errorCode)))
				sendLogs(currentProc, L"ZwCreateProcess", parameter);
			else 
				sendLogs(currentProc, L"ZwCreateProcess", L"0,-1,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritObjectTable->-1,ParentProcess->-1,FileName->-1");
			ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return errorCode;
		}
		
		if(kRootDirectory && ObjectAttributes)	// handle the not null rootdirectory case
		{
			// allocate both name information struct and unicode string buffer
			nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			if(nameInfo)
			{
				if(NT_SUCCESS(ZwQueryObject(kRootDirectory, ObjectNameInformation, nameInfo, MAXSIZE, NULL)))
				{
					full_path.MaximumLength = nameInfo->Name.Length + kObjectName.Length + 2 + sizeof(WCHAR);
					full_path.Buffer = ExAllocatePoolWithTag(NonPagedPool, full_path.MaximumLength, BUFFER_TAG);
					RtlZeroMemory(full_path.Buffer, full_path.MaximumLength);
					RtlCopyUnicodeString(&full_path, &(nameInfo->Name));
					RtlAppendUnicodeToString(&full_path, L"\\");
					RtlAppendUnicodeStringToString(&full_path, &kObjectName);
				}
			}
		}
		else
			RtlInitUnicodeString(&full_path, kObjectName.Buffer);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritObjectTable->%d,ParentProcess->0x%08x,FileName->%wZ", kProcessHandle,child_pid,DesiredAccess,InheritObjectTable,ParentProcess,&full_path)))
				log_lvl = LOG_PARAM;
			if(child_pid)
				startMonitoringProcess(child_pid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritObjectTable->%d,ParentProcess->0x%08x,FileName->%wZ", statusCall,kProcessHandle,child_pid,DesiredAccess,InheritObjectTable,ParentProcess,&full_path)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateProcess", L"0,-1,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritObjectTable->-1,ParentProcess->-1,FileName->-1");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateProcess", L"1,0,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritObjectTable->-1,ParentProcess->-1,FileName->-1");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-02/0195.html (lulz)
//	Return value :
//		See http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-02/0195.html (lulz)
//	Process :
//		Starts the process, gets its PID and adds it to the monitored processes list, copies
//		ObjectAttributes->ObjectName parameter then logs.
////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE dunno)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc, child_pid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	HANDLE kRootDirectory, kProcessHandle;
	UNICODE_STRING full_path, kObjectName;
	POBJECT_NAME_INFORMATION nameInfo = NULL;
	full_path.Buffer = NULL;
	kObjectName.Buffer = NULL;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEPROCESSEX)(oldZwCreateProcessEx))(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort, dunno);	 
		
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		kObjectName.Buffer = NULL;
		
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
			{
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				if(ObjectAttributes)
				{
					ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
					ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
					ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
				}
			}
			kProcessHandle = *ProcessHandle;
			child_pid = getPIDByHandle(kProcessHandle);
			if(ObjectAttributes)
			{
				kRootDirectory = ObjectAttributes->RootDirectory;
				kObjectName.Length = ObjectAttributes->ObjectName->Length;
				kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
				kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
		} 
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			errorCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritHandles->-1,InheritFromProcessHandle->-1,FileName->-1", errorCode)))
				sendLogs(currentProc, L"ZwCreateProcessEx", parameter);
			else 
				sendLogs(currentProc, L"ZwCreateProcessEx", L"0,-1,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritHandles->-1,InheritFromProcessHandle->-1,FileName->-1");
			ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return errorCode;
		}
		
		if(kRootDirectory && ObjectAttributes)	// handle the not null rootdirectory case
		{
			// allocate both name information struct and unicode string buffer
			nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			if(nameInfo)
			{
				if(NT_SUCCESS(ZwQueryObject(kRootDirectory, ObjectNameInformation, nameInfo, MAXSIZE, NULL)))
				{
					full_path.MaximumLength = nameInfo->Name.Length + kObjectName.Length + 2 + sizeof(WCHAR);
					full_path.Buffer = ExAllocatePoolWithTag(NonPagedPool, full_path.MaximumLength, BUFFER_TAG);
					RtlZeroMemory(full_path.Buffer, full_path.MaximumLength);
					RtlCopyUnicodeString(&full_path, &(nameInfo->Name));
					RtlAppendUnicodeToString(&full_path, L"\\");
					RtlAppendUnicodeStringToString(&full_path, &kObjectName);
				}
				else
					RtlInitUnicodeString(&full_path, kObjectName.Buffer);
			}
			else
				RtlInitUnicodeString(&full_path, kObjectName.Buffer);
		}
		else
			RtlInitUnicodeString(&full_path, kObjectName.Buffer);
		
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritHandles->%d,InheritFromProcessHandle->0x%08x,FileName->%wZ", kProcessHandle,child_pid,DesiredAccess,InheritHandles,InheritFromProcessHandle,&full_path)))
				log_lvl = LOG_PARAM;
			
			if(child_pid)
				startMonitoringProcess(child_pid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritObjectTable->%d,ParentProcess->0x%08x,FileName->%wZ", statusCall,kProcessHandle,child_pid,DesiredAccess,InheritHandles,InheritFromProcessHandle,&full_path)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateProcessEx", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateProcessEx", L"0,-1,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritHandles->-1,InheritFromProcessHandle->-1,FileName->-1");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateProcessEx", L"1,0,ssssss,ProcessHandle->-1,PID->-1,DesiredAccess->-1,InheritHandles->-1,InheritFromProcessHandle->-1,FileName->-1");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread-based Asynchronous Procedure Call creation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//	Process :
//		Proceed the call then gets the thread owner and adds it to the monitored processes list, then
//		log.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved)
{
	NTSTATUS statusCall;
	ULONG currentProc, tid;
	DWORD pid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	PETHREAD eThread = NULL;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWQUEUEAPCTHREAD)(oldZwQueueApcThread))(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		tid = getTIDByHandle(ThreadHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		if(NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)tid, &eThread)))
			pid = *(DWORD*)((PCHAR)eThread+0x1EC);
		else
			pid = -1;
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,ThreadHandle->0x%08x,TID->%d,PID->%d,ApcRoutine->0x%08x", ThreadHandle, tid, pid, ApcRoutine)))
				log_lvl = LOG_PARAM;
			
			if(pid)
				startMonitoringProcess(pid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ThreadHandle->0x%08x,TID->%d,PID->%d,ApcRoutine->0x%08x", statusCall, ThreadHandle, tid, pid, ApcRoutine)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwQueueApcThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwQueueApcThread", L"0,-1,ssss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR,ApcRoutine->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwQueueApcThread", L"1,0,ssss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR,ApcRoutine->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//	Process :
//		Gets the thread's owner, proceeds the call then adds immediately the PID to the monitored
//		processes list if it succeeded. Then logs.
//	Notes :
//		Actually, a race condition occurs : we must create the thread before adding the remote process
//		to the list in order to check if the thread was created successfuly. However, a malware would
//		not create a thread without giving it nothing to execute, right? :]
//	TODO :
//		- Create the thread in suspended state and resume it after adding the process to the list to avoid
//		race condition issues.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc, pid, tid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	HANDLE kThreadHandle;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	
	pid = getPIDByHandle(ProcessHandle);	// faster than placing it after the monitored process check
	statusCall = ((ZWCREATETHREAD)(oldZwCreateThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		if(NT_SUCCESS(statusCall) && pid)
			startMonitoringProcess(pid);	// <-- RACE CONDITION
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		_try
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
			kThreadHandle = *ThreadHandle;
		} 
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			errorCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR", errorCode)))
				sendLogs(currentProc, L"ZwCreateThread", parameter);
			else 
				sendLogs(currentProc, L"ZwCreateThread", L"0,-1,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
			if(parameter)
				ExFreePool(parameter);
			return errorCode;
		}
		
		tid = getTIDByHandle(kThreadHandle);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,PID->%d,ThreadHandle->0x%08x,TID->%d,CreateSuspended->%d,DesiredAccess->0x%08x", kThreadHandle, pid, tid, CreateSuspended, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,PID->%d,ThreadHandle->0x%08x,TID->%d,CreateSuspended->%d,DesiredAccess->0x%08x", statusCall, kThreadHandle, pid, tid, CreateSuspended, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateThread", L"0,-1,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateThread", L"1,0,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs section mapping (may be used for code injection).
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//	Process :
//		Proceeds the call, then if the process is not the current one, adds it to the monitored
//		processes list then logs it.
//	TODO :
//		- Also log SectionOffset, ViewSize
//		- Check if a race condition occurs (the process is not added before the call is passed)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	NTSTATUS statusCall;
	ULONG pid, currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWMAPVIEWOFSECTION)(oldZwMapViewOfSection))(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		pid = getPIDByHandle(ProcessHandle);
		
		if(currentProc != pid)
		{
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			
			if(NT_SUCCESS(statusCall))
			{
				log_lvl = LOG_SUCCESS;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,SectionHandle->0x%08x,Win32Protect->%d", ProcessHandle, pid, BaseAddress, SectionHandle, Win32Protect)))
					log_lvl = LOG_PARAM;
				if(pid)
					startMonitoringProcess(pid);
			}
			else
			{
				log_lvl = LOG_ERROR;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,SectionHandle->0x%08x,Win32Protect->%d", statusCall, ProcessHandle, pid, BaseAddress, SectionHandle, Win32Protect)))
					log_lvl = LOG_PARAM;
			}
			
			switch(log_lvl)
			{
				case LOG_PARAM:
					sendLogs(currentProc, L"NtMapViewOfSection", parameter);
				break;
				case LOG_SUCCESS:
					sendLogs(currentProc, L"NtMapViewOfSection", L"0,-1,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,SectionHandle->ERROR,Win32Protect->ERROR");
				break;
				default:
					sendLogs(currentProc, L"NtMapViewOfSection", L"1,0,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,SectionHandle->ERROR,Win32Protect->ERROR");
				break;
			}
			if(parameter != NULL)
				ExFreePool(parameter);
		}
	}
	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread context manipulation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//	Process :
//		Pass the call, adds the process (thread owner) to the monitored processes list and logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
{
	NTSTATUS statusCall;
	ULONG currentProc, tid;
	DWORD pid;
	PWCHAR parameter = NULL;
	PETHREAD eThread = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWSETCONTEXTTHREAD)(oldZwSetContextThread))(ThreadHandle, Context);
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		tid = getTIDByHandle(ThreadHandle);
		
		if(NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)tid, &eThread)))
			pid = *(DWORD*)((PCHAR)eThread+0x1EC);
		else
			pid = -1;
			
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ThreadHandle->0x%08x,TID->%d,PID->%d", ThreadHandle, tid, pid)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,sss,ThreadHandle->0x%08x,TID->%d,PID->%d", statusCall, ThreadHandle, tid, pid)))
				log_lvl = LOG_PARAM;
		}
	
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwSetContextThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwSetContextThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwSetContextThread", L"1,0,sss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging operations (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//	Process :
//		Pass the call, adds the process to the monitored processes list and logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
{
	NTSTATUS statusCall;
	ULONG currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWSYSTEMDEBUGCONTROL)(oldZwSystemDebugControl))(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,Command->%d", Command)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,s,Command->%d", statusCall, Command)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwSystemDebugControl", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwSystemDebugControl", L"0,-1,s,Command->Error");
			break;
			default:
				sendLogs(currentProc, L"ZwSystemDebugControl", L"1,0,s,Command->Error");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file creation and/or file opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Process :
//		Copies arguments, handles the non-NULL ObjectAttributes->RootDirectory parameter case (concat.
//		of RootDirectory and ObjectName) then log.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc, returnLength;
	PWCHAR parameter = NULL;
	HANDLE kRootDirectory, kFileHandle;
	UNICODE_STRING full_path, kObjectName;
	POBJECT_NAME_INFORMATION nameInfo = NULL;
	USHORT log_lvl = LOG_ERROR;
	full_path.Buffer = NULL;
	kObjectName.Buffer = NULL;
	
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEFILE)(oldZwCreateFile))(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		kObjectName.Buffer = NULL;
		
		__try
		{
			if(ExGetPreviousMode() != KernelMode)
			{
				ProbeForRead(FileHandle, sizeof(HANDLE), 1);
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
			}
			kFileHandle = *FileHandle;
			kRootDirectory = ObjectAttributes->RootDirectory;
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
			kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
			RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			errorCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR", errorCode)))
				sendLogs(currentProc, L"ZwCreateFile", parameter);
			else 
				sendLogs(currentProc ,L"ZwCreateFile", L"0,-1,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR");
			ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return errorCode;
		}
		
		if(kRootDirectory)	// handle the not null rootdirectory case
		{
			// allocate both name information struct and unicode string buffer
			nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			if(nameInfo)
			{
				if(NT_SUCCESS(ZwQueryObject(kRootDirectory, ObjectNameInformation, nameInfo, MAXSIZE, NULL)))
				{
					full_path.MaximumLength = nameInfo->Name.Length + kObjectName.Length + 2 + sizeof(WCHAR);
					full_path.Buffer = ExAllocatePoolWithTag(NonPagedPool, full_path.MaximumLength, BUFFER_TAG);
					RtlZeroMemory(full_path.Buffer, full_path.MaximumLength);
					RtlCopyUnicodeString(&full_path, &(nameInfo->Name));
					RtlAppendUnicodeToString(&full_path, L"\\");
					RtlAppendUnicodeStringToString(&full_path, &kObjectName);
				}
			}
		}
		else
			RtlInitUnicodeString(&full_path, kObjectName.Buffer);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssssss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x,CreateDisposition->%d,CreateOptions->%d,FileAttributes->%d,ShareAccess->%d", kFileHandle,&full_path, DesiredAccess, CreateDisposition, CreateOptions, FileAttributes, ShareAccess)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,sssssss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x,CreateDisposition->%d,CreateOptions->%d,FileAttributes->%d,ShareAccess->%d", statusCall, kFileHandle, &full_path, DesiredAccess, CreateDisposition, CreateOptions, FileAttributes, ShareAccess)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateFile", L"0,-1,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateFile", L"1,0,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR");
			break;
		}
		if(kObjectName.Buffer && kObjectName.Buffer != full_path.Buffer)
			ExFreePool(kObjectName.Buffer);
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInfo != NULL)
			ExFreePool(nameInfo);
		if(full_path.Buffer)
			ExFreePool(full_path.Buffer);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file reading.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//	Process :
//		Gets the filename and logs it.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc, returnLength;
	POBJECT_NAME_INFORMATION nameInfo = NULL;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWREADFILE)(oldZwReadFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		
		nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
		if(nameInfo)
			ZwQueryObject(FileHandle, ObjectNameInformation, nameInfo, MAXSIZE, NULL);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", statusCall, FileHandle, &(nameInfo->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", statusCall, FileHandle, &(nameInfo->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwReadFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwReadFile", L"0,-1,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwReadFile", L"1,0,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInfo != NULL)
			ExFreePool(nameInfo);
	}

	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file modification.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//	Process :
//		Gets the filename and logs it.
//	TODO :
//		- Log &Buffer, Length, ByteOffset
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS statusCall;
	ULONG currentProc, returnLength;
	POBJECT_NAME_INFORMATION nameInfo = NULL;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWWRITEFILE)(oldZwWriteFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
		if(nameInfo)
			ZwQueryObject(FileHandle, ObjectNameInformation, nameInfo, MAXSIZE, NULL);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", FileHandle, &(nameInfo->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", statusCall, FileHandle, &(nameInfo->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwWriteFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwWriteFile", L"0,-1,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwWriteFile", L"1,0,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInfo != NULL)
			ExFreePool(nameInfo);
	}

	return statusCall;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//	Process :
//		Copies the ObjectAttributes->ObjectName parameter then logs the file deletion.
//	TODO :
//		- Handle file deletion case: move the file in a special directory so it can be dumped.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	UNICODE_STRING kObjectName;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWDELETEFILE)(oldZwDeleteFile))(ObjectAttributes);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		kObjectName.Buffer = NULL;
		__try
		{
			if(ExGetPreviousMode() != KernelMode)
			{
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
			}
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
			kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
			if(kObjectName.Buffer)
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			else
			{
				sendLogs(currentProc ,L"ZwDeleteFile", L"0,-1,s,FileName->ERROR");
				if(parameter)
					ExFreePool(parameter);
				return statusCall;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			errorCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,FileName->ERROR", errorCode)))
				sendLogs(currentProc, L"ZwDeleteFile", parameter);
			else 
				sendLogs(currentProc ,L"ZwDeleteFile", L"0,-1,s,FileName->ERROR");
			if(parameter)
				ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return errorCode;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,0,s,FileName->%wZ", &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,s,FileName->%wZ", statusCall, &kObjectName)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwDeleteFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwDeleteFile", L"0,-1,s,FileName->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwDeleteFile", L"1,0,s,FileName->ERROR");
			break;
		}
		if(kObjectName.Buffer)
			ExFreePool(kObjectName.Buffer);
		if(parameter)
			ExFreePool(parameter);
	}
	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion / rename.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//	Process :
//		Copy the FileHandle parameter, then checks the FileInformationClass argument.
//		If FileDispositionInformation, the file may be deleted, the FileInformation->DeleteFile
//		parameter is copied and tested.
//		If FileRenameInformation, the FileInformation->FileName parameter is copied along with the
//		FileInformation->RootDirectory parameter, then the call is logged.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS statusCall, errorCode;
	ULONG currentProc;
	ULONG kFileNameLength;
	HANDLE kFileHandle, kRootDirectory;
	BOOLEAN kDeleteFile;
	UNICODE_STRING full_path;
	PFILE_RENAME_INFORMATION kFileRenameInformation = NULL;
	POBJECT_NAME_INFORMATION originalName = NULL;
	PWCHAR renamedfileName = NULL;
	PWCHAR parameter = NULL;
	PWCHAR kFileName = NULL;
	USHORT log_lvl = LOG_ERROR;
	full_path.Buffer = NULL;
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWSETINFORMATIONFILE)(oldZwSetInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(FileHandle, sizeof(HANDLE), 1);
			kFileHandle = FileHandle;
		} 
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			errorCode = GetExceptionCode();
			if(FileInformationClass == FileDispositionInformation)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,FileHandle->-1,FileName->-1,FileInformationClass->-1", errorCode)))
					sendLogs(currentProc, L"ZwSetInformationFile (Delete)", parameter);
				else 
					sendLogs(currentProc, L"ZwSetInformationFile (Delete)", L"0,-1,sss,FileHandle->-1,FileName->-1,FileInformationClass->-1");
			}
			else if(FileInformationClass == FileRenameInformation)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,FileHandle->-1,OriginalName->-1,Renamed->-1,FileInformationClass->-1", errorCode)))
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", parameter);
				else 
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->-1,OriginalName->-1,Renamed->-1,FileInformationClass->-1");
			}
			if(parameter)
				ExFreePool(parameter);
			return errorCode;
		}
		
		// CHANGE FILE DISPOSITION INFORMATION CASE
		if(FileInformationClass == FileDispositionInformation)
		{
			__try 
			{
				if(ExGetPreviousMode() != KernelMode)
					ProbeForRead(FileInformation, sizeof(FILE_DISPOSITION_INFORMATION), 1);
				kDeleteFile = ((PFILE_DISPOSITION_INFORMATION)FileInformation)->DeleteFile;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				errorCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,FileHandle->-1,FileName->-1,FileInformationClass->-1", errorCode)))
					sendLogs(currentProc, L"ZwSetInformationFile (Delete)", parameter);
				else
					sendLogs(currentProc, L"ZwSetInformationFile (Delete)", L"0,-1,sss,FileHandle->-1,FileName->-1,FileInformationClass->-1");
				if(parameter)
					ExFreePool(parameter);
				return errorCode;
			}
			
			if(kDeleteFile == TRUE)
			{
				originalName = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
				if(originalName && parameter)
					ZwQueryObject(kFileHandle, ObjectNameInformation, originalName, MAXSIZE, NULL);
				if(NT_SUCCESS(statusCall))
				{
					log_lvl = LOG_SUCCESS;
					if(parameter && originalName && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,sss,FileHandle->0x%08x,FileName->%wZ,FileInformationClass->%d", statusCall, FileHandle, &(originalName->Name), FileInformationClass)))
						log_lvl = LOG_PARAM;
				}
				else
				{
					log_lvl = LOG_ERROR;
					if(parameter && originalName && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,FileHandle->0x%08x,FileName->%wZ,FileInformationClass->%d", statusCall, FileHandle, &(originalName->Name), FileInformationClass)))
						log_lvl = LOG_PARAM;
				}
				switch(log_lvl)
				{
					case LOG_PARAM:
						sendLogs(currentProc, L"ZwSetInformationFile (Delete)", parameter);
					break;
					case LOG_SUCCESS:
						sendLogs(currentProc, L"ZwSetInformationFile (Delete)", L"1,0,sss,FileHandle->Error,FileName->Error,FileInformationClass->Error");
					break;
					default:
						sendLogs(currentProc, L"ZwSetInformationFile (Delete)", L"0,0,sss,FileHandle->Error,FileName->Error,FileInformationClass->Error");
					break;
				}
				if(originalName != NULL)
					ExFreePool(originalName);
			}
		}
		
		// RENAME FILE CASE
		if(FileInformationClass == FileRenameInformation)
		{
			__try 
			{
				if(ExGetPreviousMode() != KernelMode)
				{
					ProbeForRead(FileInformation, sizeof(FILE_RENAME_INFORMATION), 1);
					ProbeForRead(((PFILE_RENAME_INFORMATION)FileInformation)->FileName, ((PFILE_RENAME_INFORMATION)FileInformation)->FileNameLength, 1);
				}
				kFileRenameInformation = (PFILE_RENAME_INFORMATION)FileInformation;
				kRootDirectory = kFileRenameInformation->RootDirectory;
				kFileNameLength = kFileRenameInformation->FileNameLength;
				
				kFileName = ExAllocatePoolWithTag(NonPagedPool, kFileNameLength + sizeof(WCHAR), BUFFER_TAG);
				if(!kFileName)
				{
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->-1,OriginalName->-1,Renamed->-1,FileInformationClass->-1");
					if(parameter)
						ExFreePool(parameter);
					return statusCall;
				}
				RtlZeroMemory(kFileName, kFileNameLength + sizeof(WCHAR));
				RtlCopyMemory(kFileName, kFileRenameInformation->FileName, kFileNameLength);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				errorCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,FileHandle->-1,OriginalName->-1,Renamed->-1,FileInformationClass->-1", errorCode)))
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", parameter);
				else
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->-1,OriginalName->-1,Renamed->-1,FileInformationClass->-1");
				if(parameter)
					ExFreePool(parameter);
				if(kFileName)
					ExFreePool(kFileName);
				return errorCode;
			}
			
			if(kRootDirectory)	// handle the not null RootDirectory case
			{
				// allocate both name information struct and unicode string buffer
				originalName = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
				if(originalName)
				{
					if(NT_SUCCESS(ZwQueryObject(kRootDirectory, ObjectNameInformation, originalName, MAXSIZE, NULL)) && kFileNameLength < 0xFFF0)
					{
						full_path.MaximumLength = originalName->Name.Length + (USHORT)kFileNameLength + 2 + sizeof(WCHAR);
						full_path.Buffer = ExAllocatePoolWithTag(NonPagedPool, full_path.MaximumLength, BUFFER_TAG);
						RtlZeroMemory(full_path.Buffer, full_path.MaximumLength);
						RtlCopyUnicodeString(&full_path, &(originalName->Name));
						RtlAppendUnicodeToString(&full_path, L"\\");
						RtlAppendUnicodeToString(&full_path, kFileName);
					}
				}
				else
					RtlInitUnicodeString(&full_path, kFileName);
			}
			else
				RtlInitUnicodeString(&full_path, kFileName);
			
			originalName = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			if(originalName && parameter)
				ZwQueryObject(kFileHandle, ObjectNameInformation, originalName, MAXSIZE, NULL);
			
			if(NT_SUCCESS(statusCall))
			{
				log_lvl = LOG_SUCCESS;
				if(parameter && originalName && kFileName)
					if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,FileHandle->0x%08x,OriginalName->%wZ,Renamed->%wZ,FileInformationClass->%d", FileHandle, &(originalName->Name), &full_path, FileInformationClass)))
						log_lvl = LOG_PARAM;
			}
			else
			{
				log_lvl = LOG_ERROR;
				if(parameter && originalName && kFileName)
					if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,FileHandle->0x%08x,,OriginalName->%wZ,Renamed->%wZ,FileInformationClass->%d", statusCall, FileHandle, &(originalName->Name), &full_path, FileInformationClass)))
						log_lvl = LOG_PARAM;
			}
			
			if(full_path.Buffer && full_path.Buffer != kFileName)
				ExFreePool(full_path.Buffer);
			if(kFileName)
				ExFreePool(kFileName);
			if(originalName)
				ExFreePool(originalName);
			
			switch(log_lvl)
			{
				case LOG_PARAM:
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", parameter);
				break;
				case LOG_SUCCESS:
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", L"1,0,ssss,FileHandle->Error,OriginalName->Error,Renamed->Error,FileInformationClass->Error");
				break;
				default:
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->Error,OriginalName->Error,Renamed->Error,FileInformationClass->Error");
				break;
			}
		}
		if(parameter)
			ExFreePool(parameter);
	}
	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file information access.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567052(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567052(v=vs.85).aspx
//	Process :
//		Logs file handle and fileinformationclass.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS statusCall, errorCode;
	DWORD currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWQUERYINFORMATIONFILE)(oldZwQueryInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	
	if(isProcessMonitoredByPid(currentProc))
	{
	
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,FileHandle->0x%08x,FileInformationClass->%d", FileHandle, FileInformationClass)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ss,FileHandle->0x%08x,FileInformationClass->%d", statusCall, FileHandle, FileInformationClass)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwQueryInformationFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwQueryInformationFile", L"0,-1,ss,FileHandle->ERROR,FileInformationClass->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwQueryInformationFile", L"1,0,ss,FileHandle->ERROR,FileInformationClass->ERROR");
			break;
		}
		if(parameter)
			ExFreePool(parameter);
	}

	return statusCall;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsets WP bit of CR0 register (allows writing into SSDT).
//	Parameters :
//		None
//	Return value :
//		None
//	Notes :
//		http://en.wikipedia.org/wiki/Control_register#CR0
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void disable_cr0()
{
	__asm
	{
		push eax
		mov eax, CR0
		and eax, 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sets WP bit of CR0 register.
//	Parameters :
//		None
//	Return value :
//		None
//	Notes :
//		http://en.wikipedia.org/wiki/Control_register#CR0
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void enable_cr0()
{
	__asm
	{
		push eax
		mov eax, CR0
		or eax, NOT 0FFFEFFFFh
		mov CR0, eax
		pop eax
	}
}
