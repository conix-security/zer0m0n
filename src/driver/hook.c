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
//		Only logs calls performed by a monitored process, and retrieves the TID dynamically.
//		TODO : block/hide hidden process threads.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
{
	NTSTATUS status;
	ULONG currentProc, tid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWOPENTHREAD)(oldZwOpenThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ClientID);
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		if(parameter)
		{
			tid = getTIDByHandle(*ThreadHandle);
			
			if(NT_SUCCESS(status))
			{
				log_lvl = LOG_SUCCESS;
				if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,TID->%d", tid)))
					log_lvl = LOG_PARAM;
			}
			else
			{
				log_lvl = LOG_ERROR;
				if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,TID->%d", status, tid)))
					log_lvl = LOG_PARAM;
			}
		}
		else
		{
			if(NT_SUCCESS(status))
				log_lvl = LOG_SUCCESS;
			else
				log_lvl = LOG_ERROR;
		}

		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwOpenThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwOpenThread", L"0,-1,s,TID->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwOpenThread", L"1,0,s,TID->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return status;
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
//		Checks if the requested PID is blocked (check by name), and if so, returns STATUS_INVALID_PARAMETER
//		code.
//		Logs the pid and its name.
//		If one error occurs before assessing if the process must be hidden, returns STATUS_INVALID_PARAMETER
//	Notes :
//		We do not add the process to the monitored process list at this point.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
{	
	NTSTATUS statusCall, status;
	ULONG currentProc, remotePid, i;
	UNICODE_STRING remoteProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;

	currentProc = (ULONG)PsGetCurrentProcessId();	
	
	if(isProcessMonitoredByPid(currentProc))
	{   		
		remoteProc.Length = 0;
		remoteProc.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
		remoteProc.Buffer = ExAllocatePoolWithTag(NonPagedPool, remoteProc.MaximumLength, PROCNAME_TAG);
		
		if(remoteProc.Buffer)
		{
			if(ClientID != NULL)
			{
				try 
				{
					if(ExGetPreviousMode() != KernelMode)
						ProbeForRead(ClientID, sizeof(ClientID), 1);
					remotePid = (ULONG)ClientID->UniqueProcess;
				} except (EXCEPTION_EXECUTE_HANDLER)
				{
					ExFreePool(remoteProc.Buffer);
					return STATUS_INVALID_PARAMETER;
				}
			}
			else
			{
				ExFreePool(remoteProc.Buffer);
				statusCall = ((ZWOPENPROCESS)(oldZwOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientID);
				if(NT_SUCCESS(statusCall))
					sendLogs(currentProc, L"ZwOpenProcess", L"1,0,ss,ProcessName->Error,PID->-1");
				else
					sendLogs(currentProc, L"ZwOpenProcess", L"0,0,ss,ProcessName->Error,PID->-1");
				return ((ZWOPENPROCESS)(oldZwOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientID);
			}			
			
			status = getProcNameByPID(remotePid, &remoteProc);
			if(NT_SUCCESS(status))
			{
				if(isProcessHiddenByPid(remotePid))	// hide process
				{
					parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,-1,ss,ProcessName->%wZ,PID->%d", &remoteProc, remotePid)))
					{
						sendLogs(currentProc, L"ZwOpenProcess", parameter);
						ExFreePool(parameter);
					}
					else
						sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ss,ProcessName->Error_HIDDEN,PID->-1");
					
					ExFreePool(remoteProc.Buffer);
					return STATUS_INVALID_PARAMETER;
				}			
				
				statusCall = ((ZWOPENPROCESS)(oldZwOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientID);
				
				parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
				if(NT_SUCCESS(statusCall))
				{
					log_lvl = LOG_SUCCESS;
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,ProcessName->%wZ,PID->%d", &remoteProc, remotePid)))
						log_lvl = LOG_PARAM;
				}
				else
				{
					log_lvl = LOG_ERROR;
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ss,ProcessName->%wZ,PID->%d", statusCall, &remoteProc, remotePid)))
						log_lvl = LOG_PARAM;
				}
				
				switch(log_lvl)
				{
					case LOG_PARAM:
						sendLogs(currentProc, L"ZwOpenProcess", parameter);
					break;
					case LOG_SUCCESS:
						sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ss,ProcessName->ERROR,PID->ERROR");
					break;
					default:
						sendLogs(currentProc, L"ZwOpenProcess", L"1,0,ss,ProcessName->ERROR,PID->ERROR");
					break;
				}
				if(parameter != NULL)
					ExFreePool(parameter);

				ExFreePool(remoteProc.Buffer);
				return statusCall;
					
			}
			ExFreePool(remoteProc.Buffer);
		}
		// At this point, we could not retrieve the process name from its PID thus not assess if the process must be hidden.
		// We can't allow a monitored process opening it, so we fail the call.
		sendLogs(currentProc, L"ZwOpenProcess", L"0,-1,ss,ProcessName->Error_getname_BLOCKED,PID->-1");
		return STATUS_INVALID_PARAMETER;
	}
	return ((ZWOPENPROCESS)(oldZwOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientID);
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
//		hidden ones are unlinked from the result.
//	Todo :
//		Thread listing ?
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS status;
	ULONG currentProc, tid, i;
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = NULL, pPrev = NULL;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;

	currentProc = (ULONG)PsGetCurrentProcessId();
	
	status = ((ZWQUERYSYSTEMINFORMATION)(oldZwQuerySystemInformation))(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if(isProcessMonitoredByPid(currentProc))
	{
		if(NT_SUCCESS(status))
		{
			if(SystemInformationClass == SystemProcessInformation)
			{
				pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
				pPrev = pSystemProcessInformation;
				
				while(pSystemProcessInformation->NextEntryOffset)
				{
					if(isProcessHiddenByPid((ULONG)pSystemProcessInformation->ProcessId))
						pPrev->NextEntryOffset += pSystemProcessInformation->NextEntryOffset;	// unlinking hidden process

					pPrev = pSystemProcessInformation;
					// next entry
					pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((char*)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
				}
				
				sendLogs(currentProc, L"ZwQuerySystemInformation",L"1,0,s,SystemInformationClass->5");
				return status;
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
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,SystemInformationClass->%d", status, SystemInformationClass)))
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

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs virtual memory modification.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
//	Process :
//		Adds the process to the monitored processes list and logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	NTSTATUS status, statp;
	ULONG currentProc, remotePid;
	PWCHAR parameter = NULL;
	ULONG log_lvl = LOG_ERROR;

	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWWRITEVIRTUALMEMORY)(oldZwWriteVirtualMemory))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		remotePid = getPIDByHandle(ProcessHandle);
	
		if(NT_SUCCESS(status) && remotePid)
			startMonitoringProcess(remotePid);

		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,PID->%d,BaseAddress->0x%08x", remotePid, BaseAddress)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ss,PID->%d,BaseAddress->0x%08x", status, remotePid, BaseAddress)))
				log_lvl = LOG_PARAM;
		}

		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwWriteVirtualMemory", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwWriteVirtualMemory", L"0,1,ss,PID->ERROR,BaseAddress->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwWriteVirtualMemory", L"1,0,ss,PID->ERROR,BaseAddress->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);

	}
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging (may be used for code injection).
//	Parameters :
//		See http://www.openrce.org/articles/full_view/26
//	Return value :
//		See http://www.openrce.org/articles/full_view/26
//	Process :
//		Adds the process to the monitored processes list and logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle)
{
	NTSTATUS status;
	ULONG remotePid, currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWDEBUGACTIVEPROCESS)(oldZwDebugActiveProcess))(ProcessHandle, DebugHandle);
	
	if(isProcessMonitoredByPid(currentProc))
	{		
		remotePid = getPIDByHandle(ProcessHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);

		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,PID->%d", remotePid)))
				log_lvl = LOG_PARAM;
			if(remotePid)
				startMonitoringProcess(remotePid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,PID->%d", status, remotePid)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwDebugActiveProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwDebugActiveProcess", L"0,-1,s,PID->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwDebugActiveProcess", L"1,0,s,PID->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html
//	Process :
//		Adds the process (gets new PID after passing the call) to the monitored processes list and logs.
//	Note :
//		There is no race condition : the main thread is not started yet.
//	TODO : 
//		log arguments
//		log filename
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{
	NTSTATUS status;
	ULONG currentProc, child_pid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	status = ((ZWCREATEPROCESS)(oldZwCreateProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	currentProc = (ULONG)PsGetCurrentProcessId();
	if(isProcessMonitoredByPid(currentProc))
	{
		child_pid = getPIDByHandle(*ProcessHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(wchar_t), PROC_POOL_TAG);

		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,PID->%d", child_pid)))
				log_lvl = LOG_PARAM;
			if(child_pid)
				startMonitoringProcess(child_pid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,PID->%d", status, child_pid)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateProcess", L"0,-1,s,PID->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateProcess", L"1,0,s,PID->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-02/0195.html (lulz)
//	Return value :
//		See http://www.tech-archive.net/Archive/Development/microsoft.public.win32.programmer.kernel/2004-02/0195.html (lulz)
//	Process :
//		Adds the process to the monitored processes list and logs.
//	TODO : 
//		log arguments
//		log filename
////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE dunno)
{
	NTSTATUS status;
	ULONG currentProc, child_pid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWCREATEPROCESSEX)(oldZwCreateProcessEx))(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort, dunno);	 
		
	if(isProcessMonitoredByPid(currentProc))
	{
		child_pid = getPIDByHandle(*ProcessHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(wchar_t), PROC_POOL_TAG);

		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,PID->%d", child_pid)))
				log_lvl = LOG_PARAM;

			if(child_pid)
				startMonitoringProcess(child_pid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,PID->%d", status, child_pid)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateProcessEx", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateProcessEx", L"0,-1,s,PID->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateProcessEx", L"1,0,s,PID->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread-based Asynchronous Procedure Call creation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
//	Process :
//		Adds the process (thread owner) to the monitored processes list and logs.
//
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved)
{
	NTSTATUS status;
	ULONG currentProc, tid;
	DWORD pid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	PETHREAD eThread = NULL;
	
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWQUEUEAPCTHREAD)(oldZwQueueApcThread))(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		tid = getTIDByHandle(ThreadHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		if(NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)tid, &eThread)))
			pid = *(DWORD*)((PCHAR)eThread+0x1EC);
		else
			pid = -1;
			
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,TID->%d,PID->%d", tid, pid)))
				log_lvl = LOG_PARAM;
			
			if(pid)
				startMonitoringProcess(pid);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,TID->%d,PID->%d", status, tid, pid)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwQueueApcThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwQueueApcThread", L"0,-1,s,TID->ERROR,PID->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwQueueApcThread", L"1,0,s,TID->ERROR,PID->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread creation.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtCreateThread.html
//	Process :
//		Adds the process (thread owner) to the monitored processes list and logs. Actually, a race
//		condition occurs : we must create the thread before adding the remote process to the list in
//		order to check if the thread was created successfuly. However, a malware would not create a
//		thread without giving it nothing to execute.
//	TODO :
//		Create the thread in suspended state and resume it after adding the process to the list to avoid
//		race condition issues.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	NTSTATUS status;
	ULONG currentProc, pid, tid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	
	pid = getPIDByHandle(ProcessHandle);	// faster than placing it after the monitored process check
	status = ((ZWCREATETHREAD)(oldZwCreateThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);

	if(isProcessMonitoredByPid(currentProc))
	{
		if(NT_SUCCESS(status) && pid)
			startMonitoringProcess(pid);	// <-- RACE CONDITION
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		tid = getTIDByHandle(*ThreadHandle);
		
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,PID->%d,TID->%d,CreateSuspended->%d", pid, tid, CreateSuspended)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,PID->%d,TID->%d,CreateSuspended->%d", status, pid, tid, CreateSuspended)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateThread", L"0,-1,sss,PID->ERROR,TID->ERROR,CreateSuspended->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateThread", L"1,0,sss,PID->ERROR,TID->ERROR,CreateSuspended->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs section mapping (may be used for code injection).
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566481(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	NTSTATUS status;
	ULONG pid, currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWMAPVIEWOFSECTION)(oldZwMapViewOfSection))(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);	

	if(isProcessMonitoredByPid(currentProc))
	{
		pid = getPIDByHandle(ProcessHandle);
		
		// log it only if the process is different
		if(currentProc != pid)
		{
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			
			if(NT_SUCCESS(status))
			{
				log_lvl = LOG_SUCCESS;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,PID->%d,BaseAddress->0x%08x", pid, BaseAddress)))
					log_lvl = LOG_PARAM;
				if(pid)
					startMonitoringProcess(pid);
			}
			else
			{
				log_lvl = LOG_ERROR;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ss,PID->%d,BaseAddress->0x%08x", status, pid, BaseAddress)))
					log_lvl = LOG_PARAM;
			}
		
			// then log and return
			switch(log_lvl)
			{
				case LOG_PARAM:
					sendLogs(currentProc, L"ZwMapViewOfSection", parameter);
				break;
				case LOG_SUCCESS:
					sendLogs(currentProc, L"NtMapViewOfSection", L"0,-1,ss,PID->ERROR,BaseAddress->ERROR");
				break;
				default:
					sendLogs(currentProc, L"NtMapViewOfSection", L"1,0,ss,PID->ERROR,BaseAddress->ERROR");
				break;
			}
			if(parameter != NULL)
				ExFreePool(parameter);
		}
	}

	return status;	
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread context manipulation (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html
//	Process :
//		Adds the process (thread owner) to the monitored processes list and logs.
//	TODO :
//		Add the process.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
{
	NTSTATUS status;
	ULONG currentProc, tid;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWSETCONTEXTTHREAD)(oldZwSetContextThread))(ThreadHandle, Context);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		tid = getTIDByHandle(ThreadHandle);
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,TID->%d", tid)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,s,TID->%d", status, tid)))
				log_lvl = LOG_PARAM;
		}
	
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwSetContextThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwSetContextThread", L"0,-1,s,TID->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwSetContextThread", L"1,0,s,TID->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process debugging operations (may be used for code injection).
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html
//	Process :
//		Adds the process to the monitored processes list and logs.
//	TODO:
//		Log stuff
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
{
	NTSTATUS status;
	ULONG currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWSYSTEMDEBUGCONTROL)(oldZwSystemDebugControl))(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0")))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d", status)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwSystemDebugControl", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwSystemDebugControl", L"0,-1");
			break;
			default:
				sendLogs(currentProc, L"ZwSystemDebugControl", L"1,0");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file creation and/or file opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Process :
//		Retrieves filename (along with the directory, if supplied), access mask and handle, then logs
//		it.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	NTSTATUS status;
	ULONG currentProc, returnLength;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	UNICODE_STRING full_path, to_add;
	POBJECT_NAME_INFORMATION nameInfo = NULL;
	BOOLEAN to_release = FALSE;
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWCREATEFILE)(oldZwCreateFile))(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	if(isProcessMonitoredByPid(currentProc))
	{
		RtlInitUnicodeString(&to_add, L"\\");
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		if(ObjectAttributes->RootDirectory)	// handle the not null rootdirectory case
		{	
			nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, 'RoxX');
			if(nameInfo)
			{
				if(NT_SUCCESS(ZwQueryObject(ObjectAttributes->RootDirectory, ObjectNameInformation, nameInfo, MAXSIZE, NULL)))
				{
					full_path.MaximumLength = nameInfo->Name.Length + ObjectAttributes->ObjectName->Length + to_add.Length + sizeof(WCHAR);
					full_path.Buffer = ExAllocatePoolWithTag(NonPagedPool, full_path.MaximumLength, 'berK');
					RtlZeroMemory(full_path.Buffer, full_path.MaximumLength);
					RtlCopyUnicodeString(&full_path, &(nameInfo->Name));
					RtlAppendUnicodeStringToString(&full_path, &to_add);
					RtlAppendUnicodeStringToString(&full_path, ObjectAttributes->ObjectName);
					to_release = TRUE;
				}
			}
		}
		else
			RtlInitUnicodeString(&full_path, ObjectAttributes->ObjectName->Buffer);
		
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x", *FileHandle,&full_path, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,sss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x", status, *FileHandle, &full_path, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwCreateFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwCreateFile", L"0,-1,sss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwCreateFile", L"1,0,sss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInfo != NULL)
			ExFreePool(nameInfo);
		if(to_release)
			ExFreePool(full_path.Buffer);	
	}
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file reading.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567072(v=vs.85).aspx
//	Process :
//		Gets the filename and logs (along with the handle).
//	TODO :
//		Log handle
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS status;
	ULONG currentProc, returnLength;
	POBJECT_NAME_INFORMATION nameInfo;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWREADFILE)(oldZwReadFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
		if(nameInfo)
			ZwQueryObject(FileHandle, ObjectNameInformation, nameInfo, MAXSIZE, NULL);
		
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,ss,FileHandle->0x%08x,FileName->%wZ", status, FileHandle, &(nameInfo->Name))))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ss,FileHandle->0x%08x,FileName->%wZ", status, FileHandle, &(nameInfo->Name))))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwReadFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwReadFile", L"0,-1,ss,FileHandle->ERROR, FileName->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwReadFile", L"1,0,ss,FileHandle->ERROR, FileName->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInfo != NULL)
			ExFreePool(nameInfo);
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file modification.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567121(v=vs.85).aspx
//	Process :
//		Logs filename and handle.
//	TODO :
//		Log handle
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS status;
	ULONG currentProc, returnLength;
	POBJECT_NAME_INFORMATION nameInfo;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWWRITEFILE)(oldZwWriteFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
		if(nameInfo)
			ZwQueryObject(FileHandle, ObjectNameInformation, nameInfo, MAXSIZE, NULL);
		
		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,FileHandle->0x%08x,FileName->%wZ", FileHandle, &(nameInfo->Name))))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(nameInfo && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ss,FileHandle->0x%08x,FileName->%wZ", status, FileHandle, &(nameInfo->Name))))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwWriteFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwWriteFile", L"0,-1,ss,FileHandle->ERROR, FileName->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwWriteFile", L"1,0,ss,FileHandle->ERROR, FileName->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInfo != NULL)
			ExFreePool(nameInfo);
	}

	return status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566435(v=vs.85).aspx
//	Process :
//		Logs filename.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS status;
	ULONG currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWDELETEFILE)(oldZwDeleteFile))(ObjectAttributes);

	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);

		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,0,s,FileName->%wZ", ObjectAttributes->ObjectName)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,s,FileName->%wZ", status, ObjectAttributes->ObjectName)))
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
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file deletion / rename.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567096(v=vs.85).aspx
//	Process :
//		Checks the case (delete or rename) with the FileInformationClass parameter, and logs the
//		filename and handle.
//	TODO :
//		Log handle
//		Other interesting operations ?
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS status;
	ULONG currentProc;
	POBJECT_NAME_INFORMATION nameInfo = NULL;
	PWCHAR renamedfileName = NULL;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWSETINFORMATIONFILE)(oldZwSetInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		// CHANGE FILE DISPOSITION INFORMATION CASE
		if(FileInformationClass == FileDispositionInformation)
		{
			if(((PFILE_DISPOSITION_INFORMATION)FileInformation)->DeleteFile == TRUE)
			{
				parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
				nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
				if(nameInfo && parameter)
					ZwQueryObject(FileHandle, ObjectNameInformation, nameInfo, MAXSIZE, NULL);
				if(NT_SUCCESS(status))
				{
					log_lvl = LOG_SUCCESS;
					if(parameter && nameInfo && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,s,FileName->%wZ", status, &(nameInfo->Name))))
						log_lvl = LOG_PARAM;
				}
				else
				{
					log_lvl = LOG_ERROR;
					if(parameter && nameInfo && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,FileName->%wZ", status, &(nameInfo->Name))))
						log_lvl = LOG_PARAM;
				}
				switch(log_lvl)
				{
					case LOG_PARAM:
						sendLogs(currentProc, L"ZwSetInformationFile (Delete)", parameter);
					break;
					case LOG_SUCCESS:
						sendLogs(currentProc, L"ZwSetInformationFile (Delete)", L"1,0,s,Error");
					break;
					default:
						sendLogs(currentProc, L"ZwSetInformationFile (Delete)", L"0,0,s,Error");
					break;
				}
				if(parameter != NULL)
					ExFreePool(parameter);
				if(nameInfo != NULL)
					ExFreePool(nameInfo);
			}	
		}
		// RENAME FILE CASE
		if(FileInformationClass == FileRenameInformation)
		{
			renamedfileName = ExAllocatePoolWithTag(NonPagedPool, ((PFILE_RENAME_INFORMATION)FileInformation)->FileNameLength, BUFFER_TAG);
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			nameInfo = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			if(nameInfo && parameter && renamedfileName)
				ZwQueryObject(FileHandle, ObjectNameInformation, nameInfo, MAXSIZE, NULL);
			
			if(NT_SUCCESS(status))
			{
				log_lvl = LOG_SUCCESS;
				if(parameter && nameInfo && renamedfileName)
					if(NT_SUCCESS(RtlCopyMemory(renamedfileName, ((PFILE_RENAME_INFORMATION)FileInformation)->FileName, ((PFILE_RENAME_INFORMATION)FileInformation)->FileNameLength)))
						if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,OriginalName->%wZ,Renamed->%ws", &(nameInfo->Name), renamedfileName)))
							log_lvl = LOG_PARAM;
			}
			else
			{
				log_lvl = LOG_ERROR;
				if(parameter && nameInfo && renamedfileName)
					if(NT_SUCCESS(RtlCopyMemory(renamedfileName, ((PFILE_RENAME_INFORMATION)FileInformation)->FileName, ((PFILE_RENAME_INFORMATION)FileInformation)->FileNameLength)))
						if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ss,OriginalName->%wZ,Renamed->%ws", status, &(nameInfo->Name), renamedfileName)))
							log_lvl = LOG_PARAM;
			}

			if(renamedfileName)
				ExFreePool(renamedfileName);
			if(nameInfo != NULL)
				ExFreePool(nameInfo);

			switch(log_lvl)
			{
				case LOG_PARAM:
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", parameter);
				break;
				case LOG_SUCCESS:
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", L"1,0,ss,OriginalName->Error,Renamed->Error");
				break;
				default:
					sendLogs(currentProc, L"ZwSetInformationFile (Rename)", L"0,-1,ss,OriginalName->Error,Renamed->Error");
				break;
			}
			if(parameter != NULL)
				ExFreePool(parameter);
		}
	}

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs file information access.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567052(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567052(v=vs.85).aspx
//	Process :
//		Logs filename and handle.
//	TODO :
//		Log handle
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS status;
	DWORD currentProc;
	PWCHAR parameter = NULL;
	USHORT log_lvl = LOG_ERROR;
	
	currentProc = (ULONG)PsGetCurrentProcessId();
	status = ((ZWQUERYINFORMATIONFILE)(oldZwQueryInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	
	if(isProcessMonitoredByPid(currentProc))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);

		if(NT_SUCCESS(status))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,FileInformationClass->%d", FileInformationClass)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,s,FileInformationClass->%d", status, FileInformationClass)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProc, L"ZwQueryInformationFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProc, L"ZwQueryInformationFile", L"0,-1,s,FileInformationClass->ERROR");
			break;
			default:
				sendLogs(currentProc, L"ZwQueryInformationFile", L"1,0,s,FileInformationClass->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}

	return status;
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
