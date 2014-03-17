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
//		hook SSDT and Shadow SSDT tables
//	Parameters :
//		DWORD pid : python process identifier 
//	Return value :
//		None
//	Process :
//		Attach python process received from cuckoo to access Shadow SSDT and hook both SSDT and Shadow SSDT
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt(ULONG pid)
{
	NTSTATUS status;
	PKAPC_STATE ApcState;
	status = PsLookupProcessByProcessId((HANDLE)pid, &crsEProc);
	if(NT_SUCCESS(status))
	{
		ApcState = (PKAPC_STATE)ExAllocatePool(NonPagedPool, sizeof(KAPC_STATE));
		KeStackAttachProcess(crsEProc, ApcState);
	}
	else
		return;

	if(is_xp)
		hook_ssdt_entries();
	else
		hook_ssdt_entries_7();

	KeUnstackDetachProcess(ApcState);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Uninstalls SSDT hooks (XP version)
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

	if(oldZwCreateThread != NULL)
		(ZWCREATETHREAD)SYSTEMSERVICE(CREATETHREAD_INDEX) = oldZwCreateThread;
		
	if(oldZwCreateThreadEx != NULL)
		(ZWCREATETHREADEX)SYSTEMSERVICE(CREATETHREADEX_INDEX) = oldZwCreateThreadEx;
	
	if(oldZwMapViewOfSection != NULL)
		(ZWMAPVIEWOFSECTION)SYSTEMSERVICE(MAPVIEWOFSECTION_INDEX) = oldZwMapViewOfSection;
	
	if(oldZwSetContextThread != NULL)
		(ZWSETCONTEXTTHREAD)SYSTEMSERVICE(SETCONTEXTTHREAD_INDEX) = oldZwSetContextThread;
	
	if(oldZwQueueApcThread != NULL)
		(ZWQUEUEAPCTHREAD)SYSTEMSERVICE(QUEUEAPCTHREAD_INDEX) = oldZwQueueApcThread;
	
	if(oldZwSystemDebugControl != NULL)
		(ZWSYSTEMDEBUGCONTROL)SYSTEMSERVICE(SYSTEMDEBUGCONTROL_INDEX) = oldZwSystemDebugControl;
	
	if(oldZwCreateProcess != NULL)
		(ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_INDEX) = oldZwCreateProcess;
	
	if(oldZwCreateProcessEx != NULL)
		(ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_INDEX) = oldZwCreateProcessEx;
	
	if(oldZwWriteVirtualMemory != NULL)
		(ZWWRITEVIRTUALMEMORY)SYSTEMSERVICE(WRITEVIRTUALMEMORY_INDEX) = oldZwWriteVirtualMemory;
	
	if(oldZwDebugActiveProcess != NULL)
		(ZWDEBUGACTIVEPROCESS)SYSTEMSERVICE(DEBUGACTIVEPROCESS_INDEX) = oldZwDebugActiveProcess;
	
	if(oldZwOpenProcess != NULL)
		(ZWOPENPROCESS)SYSTEMSERVICE(OPENPROCESS_INDEX) = oldZwOpenProcess;
	
	if(oldZwOpenThread != NULL)
		(ZWOPENTHREAD)SYSTEMSERVICE(OPENTHREAD_INDEX) = oldZwOpenThread;
	
	if(oldZwQuerySystemInformation != NULL)
		(ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(QUERYSYSTEMINFORMATION_INDEX) = oldZwQuerySystemInformation;
	
	if(oldZwCreateFile != NULL)
		(ZWCREATEFILE)SYSTEMSERVICE(CREATEFILE_INDEX) = oldZwCreateFile;
	
	if(oldZwReadFile != NULL)
		(ZWREADFILE)SYSTEMSERVICE(READFILE_INDEX) = oldZwReadFile;
	
	if(oldZwWriteFile != NULL)
		(ZWWRITEFILE)SYSTEMSERVICE(WRITEFILE_INDEX) = oldZwWriteFile;
	
	if(oldZwDeleteFile != NULL)
		(ZWDELETEFILE)SYSTEMSERVICE(DELETEFILE_INDEX) = oldZwDeleteFile;
	
	if(oldZwSetInformationFile != NULL)
		(ZWSETINFORMATIONFILE)SYSTEMSERVICE(SETINFORMATIONFILE_INDEX) = oldZwSetInformationFile;
	
	if(oldZwQueryInformationFile != NULL)
		(ZWQUERYINFORMATIONFILE)SYSTEMSERVICE(QUERYINFORMATIONFILE_INDEX) = oldZwQueryInformationFile;
	
	if(oldZwCreateMutant != NULL)
		(ZWCREATEMUTANT)SYSTEMSERVICE(CREATEMUTANT_INDEX) = oldZwCreateMutant;
		
	if(oldZwDeviceIoControlFile != NULL)
		(ZWDEVICEIOCONTROLFILE)SYSTEMSERVICE(DEVICEIOCONTROLFILE_INDEX) = oldZwDeviceIoControlFile;
		
	if(oldZwTerminateProcess != NULL)
		(ZWTERMINATEPROCESS)SYSTEMSERVICE(TERMINATEPROCESS_INDEX) = oldZwTerminateProcess;
		
	if(oldZwDelayExecution != NULL)
		(ZWDELAYEXECUTION)SYSTEMSERVICE(DELAYEXECUTION_INDEX) = oldZwDelayExecution;
		
	if(oldZwQueryValueKey != NULL)
		(ZWQUERYVALUEKEY)SYSTEMSERVICE(QUERYVALUEKEY_INDEX) = oldZwQueryValueKey;
		
	if(oldZwQueryAttributesFile != NULL)
		(ZWQUERYATTRIBUTESFILE)SYSTEMSERVICE(QUERYATTRIBUTESFILE_INDEX) = oldZwQueryAttributesFile;
		
	if(oldZwReadVirtualMemory != NULL)
		(ZWREADVIRTUALMEMORY)SYSTEMSERVICE(QUERYATTRIBUTESFILE_INDEX) = oldZwReadVirtualMemory;
		
	if(oldZwResumeThread != NULL)
		(ZWRESUMETHREAD)SYSTEMSERVICE(RESUMETHREAD_INDEX) = oldZwResumeThread;
	
	if(oldZwCreateSection != NULL)
		(ZWCREATESECTION)SYSTEMSERVICE(CREATESECTION_INDEX) = oldZwCreateSection;
		
	if(oldZwUserCallOneParam != NULL)
		(ZWUSERCALLONEPARAM)SHADOWSERVICE(USERCALLONEPARAM_INDEX) = oldZwUserCallOneParam;

	if(oldZwLoadDriver != NULL)
		(ZWLOADDRIVER)SYSTEMSERVICE(LOADDRIVER_INDEX) = oldZwLoadDriver;	
		
	enable_cr0();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Uninstalls SSDT hooks (7 version)
//	Parameters :
//		None
//	Return value :
//		None
//	Process :
//		Unset WP bit from CR0 register to be able to modify SSDT entries, restores the original values,
//		and sets WP bit again.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID unhook_ssdt_entries_7()
{
	disable_cr0();

	if(oldZwCreateThread != NULL)
		(ZWCREATETHREAD)SYSTEMSERVICE(CREATETHREAD_7_INDEX) = oldZwCreateThread;
		
	if(oldZwCreateThreadEx != NULL)
		(ZWCREATETHREADEX)SYSTEMSERVICE(CREATETHREADEX_7_INDEX) = oldZwCreateThreadEx;
	
	if(oldZwMapViewOfSection != NULL)
		(ZWMAPVIEWOFSECTION)SYSTEMSERVICE(MAPVIEWOFSECTION_7_INDEX) = oldZwMapViewOfSection;
	
	if(oldZwSetContextThread != NULL)
		(ZWSETCONTEXTTHREAD)SYSTEMSERVICE(SETCONTEXTTHREAD_7_INDEX) = oldZwSetContextThread;
	
	if(oldZwCreateProcess != NULL)
		(ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_7_INDEX) = oldZwCreateProcess;
	
	if(oldZwCreateProcessEx != NULL)
		(ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_7_INDEX) = oldZwCreateProcessEx;
	
	if(oldZwCreateUserProcess != NULL)
		(ZWCREATEUSERPROCESS)SYSTEMSERVICE(CREATEUSERPROCESS_7_INDEX) = oldZwCreateUserProcess;
		
	if(oldZwQueueApcThread != NULL)
		(ZWQUEUEAPCTHREAD)SYSTEMSERVICE(QUEUEAPCTHREAD_7_INDEX) = oldZwQueueApcThread;
	
	if(oldZwSystemDebugControl != NULL)
		(ZWSYSTEMDEBUGCONTROL)SYSTEMSERVICE(SYSTEMDEBUGCONTROL_7_INDEX) = oldZwSystemDebugControl;
	
	if(oldZwWriteVirtualMemory != NULL)
		(ZWWRITEVIRTUALMEMORY)SYSTEMSERVICE(WRITEVIRTUALMEMORY_7_INDEX) = oldZwWriteVirtualMemory;
	
	if(oldZwDebugActiveProcess != NULL)
		(ZWDEBUGACTIVEPROCESS)SYSTEMSERVICE(DEBUGACTIVEPROCESS_7_INDEX) = oldZwDebugActiveProcess;
	
	if(oldZwOpenProcess != NULL)
		(ZWOPENPROCESS)SYSTEMSERVICE(OPENPROCESS_7_INDEX) = oldZwOpenProcess;
	
	if(oldZwOpenThread != NULL)
		(ZWOPENTHREAD)SYSTEMSERVICE(OPENTHREAD_7_INDEX) = oldZwOpenThread;
	
	if(oldZwQuerySystemInformation != NULL)
		(ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(QUERYSYSTEMINFORMATION_7_INDEX) = oldZwQuerySystemInformation;
	
	if(oldZwCreateFile != NULL)
		(ZWCREATEFILE)SYSTEMSERVICE(CREATEFILE_7_INDEX) = oldZwCreateFile;
	
	if(oldZwReadFile != NULL)
		(ZWREADFILE)SYSTEMSERVICE(READFILE_7_INDEX) = oldZwReadFile;
	
	if(oldZwWriteFile != NULL)
		(ZWWRITEFILE)SYSTEMSERVICE(WRITEFILE_7_INDEX) = oldZwWriteFile;
	
	if(oldZwDeleteFile != NULL)
		(ZWDELETEFILE)SYSTEMSERVICE(DELETEFILE_7_INDEX) = oldZwDeleteFile;
	
	if(oldZwSetInformationFile != NULL)
		(ZWSETINFORMATIONFILE)SYSTEMSERVICE(SETINFORMATIONFILE_7_INDEX) = oldZwSetInformationFile;
	
	if(oldZwQueryInformationFile != NULL)
		(ZWQUERYINFORMATIONFILE)SYSTEMSERVICE(QUERYINFORMATIONFILE_7_INDEX) = oldZwQueryInformationFile;
	
	if(oldZwCreateMutant != NULL)
		(ZWCREATEMUTANT)SYSTEMSERVICE(CREATEMUTANT_7_INDEX) = oldZwCreateMutant;
		
	if(oldZwDeviceIoControlFile != NULL)
		(ZWDEVICEIOCONTROLFILE)SYSTEMSERVICE(DEVICEIOCONTROLFILE_7_INDEX) = oldZwDeviceIoControlFile;
		
	if(oldZwTerminateProcess != NULL)
		(ZWTERMINATEPROCESS)SYSTEMSERVICE(TERMINATEPROCESS_7_INDEX) = oldZwTerminateProcess;
		
	if(oldZwDelayExecution != NULL)
		(ZWDELAYEXECUTION)SYSTEMSERVICE(DELAYEXECUTION_7_INDEX) = oldZwDelayExecution;
		
	if(oldZwQueryValueKey != NULL)
		(ZWQUERYVALUEKEY)SYSTEMSERVICE(QUERYVALUEKEY_7_INDEX) = oldZwQueryValueKey;
		
	if(oldZwQueryAttributesFile != NULL)
		(ZWQUERYATTRIBUTESFILE)SYSTEMSERVICE(QUERYATTRIBUTESFILE_7_INDEX) = oldZwQueryAttributesFile;
		
	if(oldZwReadVirtualMemory != NULL)
		(ZWREADVIRTUALMEMORY)SYSTEMSERVICE(QUERYATTRIBUTESFILE_7_INDEX) = oldZwReadVirtualMemory;
		
	if(oldZwResumeThread != NULL)
		(ZWRESUMETHREAD)SYSTEMSERVICE(RESUMETHREAD_7_INDEX) = oldZwResumeThread;
	
	if(oldZwCreateSection != NULL)
		(ZWCREATESECTION)SYSTEMSERVICE(CREATESECTION_7_INDEX) = oldZwCreateSection;
	
	if(oldZwCreateProcess != NULL)
		(ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_7_INDEX) = oldZwCreateProcess;
	
	if(oldZwCreateProcessEx != NULL)
		(ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_7_INDEX) = oldZwCreateProcessEx;
		
	if(oldZwUserCallNoParam != NULL)
		(ZWUSERCALLNOPARAM)SHADOWSERVICE(USERCALLNOPARAM_7_INDEX) = oldZwUserCallNoParam;
	
	if(oldZwLoadDriver != NULL)
		(ZWLOADDRIVER)SYSTEMSERVICE(LOADDRIVER_7_INDEX) = oldZwLoadDriver;	
		
	enable_cr0();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs SSDT hooks (XP version)
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
	
	oldZwCreateThreadEx = (ZWCREATETHREADEX)SYSTEMSERVICE(CREATETHREADEX_INDEX);
	(ZWCREATETHREADEX)SYSTEMSERVICE(CREATETHREADEX_INDEX) = newZwCreateThreadEx;
	
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

	oldZwCreateMutant = (ZWCREATEMUTANT)SYSTEMSERVICE(CREATEMUTANT_INDEX);
	(ZWCREATEMUTANT)SYSTEMSERVICE(CREATEMUTANT_INDEX) = newZwCreateMutant;
	
	oldZwDeviceIoControlFile = (ZWDEVICEIOCONTROLFILE)SYSTEMSERVICE(DEVICEIOCONTROLFILE_INDEX);
	(ZWDEVICEIOCONTROLFILE)SYSTEMSERVICE(DEVICEIOCONTROLFILE_INDEX) = newZwDeviceIoControlFile;
	
	oldZwTerminateProcess = (ZWTERMINATEPROCESS)SYSTEMSERVICE(TERMINATEPROCESS_INDEX);
	(ZWTERMINATEPROCESS)SYSTEMSERVICE(TERMINATEPROCESS_INDEX) = newZwTerminateProcess;
	
	oldZwDelayExecution = (ZWDELAYEXECUTION)SYSTEMSERVICE(DELAYEXECUTION_INDEX);
	(ZWDELAYEXECUTION)SYSTEMSERVICE(DELAYEXECUTION_INDEX) = newZwDelayExecution;
	
	oldZwQueryValueKey = (ZWQUERYVALUEKEY)SYSTEMSERVICE(QUERYVALUEKEY_INDEX);
	(ZWQUERYVALUEKEY)SYSTEMSERVICE(QUERYVALUEKEY_INDEX) = newZwQueryValueKey;
	
	oldZwQueryAttributesFile = (ZWQUERYATTRIBUTESFILE)SYSTEMSERVICE(QUERYATTRIBUTESFILE_INDEX);
	(ZWQUERYATTRIBUTESFILE)SYSTEMSERVICE(QUERYATTRIBUTESFILE_INDEX) = newZwQueryAttributesFile;
	
	oldZwReadVirtualMemory = (ZWREADVIRTUALMEMORY)SYSTEMSERVICE(READVIRTUALMEMORY_INDEX);
	(ZWREADVIRTUALMEMORY)SYSTEMSERVICE(READVIRTUALMEMORY_INDEX) = newZwReadVirtualMemory;
	
	oldZwResumeThread = (ZWRESUMETHREAD)SYSTEMSERVICE(RESUMETHREAD_INDEX);
	(ZWRESUMETHREAD)SYSTEMSERVICE(RESUMETHREAD_INDEX) = newZwResumeThread;
	
	oldZwCreateSection = (ZWCREATESECTION)SYSTEMSERVICE(CREATESECTION_INDEX);
	(ZWCREATESECTION)SYSTEMSERVICE(CREATESECTION_INDEX) = newZwCreateSection;
	
	oldZwUserCallOneParam = (ZWUSERCALLONEPARAM)SHADOWSERVICE(USERCALLONEPARAM_INDEX);
	(ZWUSERCALLONEPARAM)SHADOWSERVICE(USERCALLONEPARAM_INDEX) = newZwUserCallOneParam;
	
	oldZwLoadDriver = (ZWLOADDRIVER)SYSTEMSERVICE(LOADDRIVER_INDEX);
	(ZWLOADDRIVER)SYSTEMSERVICE(LOADDRIVER_INDEX) = newZwLoadDriver;
	
	enable_cr0();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Installs SSDT hooks (7 version)
//	Parameters :
//		None
//	Return value :
//		None
//	Process :
//		Unset WP bit from CR0 register to be able to modify SSDT entries, patch with our values after,
//		saving the original ones, and set the WP bit again.
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt_entries_7()
{
	disable_cr0();
	
	oldZwCreateThread = (ZWCREATETHREAD)SYSTEMSERVICE(CREATETHREAD_7_INDEX);
	(ZWCREATETHREAD)SYSTEMSERVICE(CREATETHREAD_7_INDEX) = newZwCreateThread;
	
	oldZwCreateThreadEx = (ZWCREATETHREADEX)SYSTEMSERVICE(CREATETHREADEX_7_INDEX);
	(ZWCREATETHREADEX)SYSTEMSERVICE(CREATETHREADEX_7_INDEX) = newZwCreateThreadEx;
	
	oldZwSetContextThread = (ZWSETCONTEXTTHREAD)SYSTEMSERVICE(SETCONTEXTTHREAD_7_INDEX);
	(ZWSETCONTEXTTHREAD)SYSTEMSERVICE(SETCONTEXTTHREAD_7_INDEX) = newZwSetContextThread;
	
	oldZwCreateProcess = (ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_7_INDEX);
	(ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_7_INDEX) = newZwCreateProcess;
	
	oldZwCreateProcessEx = (ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_7_INDEX);
	(ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_7_INDEX) = newZwCreateProcessEx;
	
	oldZwCreateUserProcess = (ZWCREATEUSERPROCESS)SYSTEMSERVICE(CREATEUSERPROCESS_7_INDEX);
	(ZWCREATEUSERPROCESS)SYSTEMSERVICE(CREATEUSERPROCESS_7_INDEX) = newZwCreateUserProcess;
	
	oldZwQueueApcThread = (ZWQUEUEAPCTHREAD)SYSTEMSERVICE(QUEUEAPCTHREAD_7_INDEX);
	(ZWQUEUEAPCTHREAD)SYSTEMSERVICE(QUEUEAPCTHREAD_7_INDEX) = newZwQueueApcThread;
	
	oldZwWriteVirtualMemory = (ZWWRITEVIRTUALMEMORY)SYSTEMSERVICE(WRITEVIRTUALMEMORY_7_INDEX);
	(ZWWRITEVIRTUALMEMORY)SYSTEMSERVICE(WRITEVIRTUALMEMORY_7_INDEX) = newZwWriteVirtualMemory;
	
	oldZwSystemDebugControl = (ZWSYSTEMDEBUGCONTROL)SYSTEMSERVICE(SYSTEMDEBUGCONTROL_7_INDEX);
	(ZWSYSTEMDEBUGCONTROL)SYSTEMSERVICE(SYSTEMDEBUGCONTROL_7_INDEX) = newZwSystemDebugControl;
	
	oldZwMapViewOfSection = (ZWMAPVIEWOFSECTION)SYSTEMSERVICE(MAPVIEWOFSECTION_7_INDEX);
	(ZWMAPVIEWOFSECTION)SYSTEMSERVICE(MAPVIEWOFSECTION_7_INDEX) = newZwMapViewOfSection;
	
	oldZwDebugActiveProcess = (ZWDEBUGACTIVEPROCESS)SYSTEMSERVICE(DEBUGACTIVEPROCESS_7_INDEX);
	(ZWDEBUGACTIVEPROCESS)SYSTEMSERVICE(DEBUGACTIVEPROCESS_7_INDEX) = newZwDebugActiveProcess;
	
	oldZwOpenProcess = (ZWOPENPROCESS)SYSTEMSERVICE(OPENPROCESS_7_INDEX);
	(ZWOPENPROCESS)SYSTEMSERVICE(OPENPROCESS_7_INDEX) = newZwOpenProcess;
	
	oldZwCreateProcess = (ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_7_INDEX);
	(ZWCREATEPROCESS)SYSTEMSERVICE(CREATEPROCESS_7_INDEX) = newZwCreateProcess;
	
	oldZwCreateProcessEx = (ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_7_INDEX);
	(ZWCREATEPROCESSEX)SYSTEMSERVICE(CREATEPROCESSEX_7_INDEX) = newZwCreateProcessEx;
	
	oldZwOpenThread = (ZWOPENTHREAD)SYSTEMSERVICE(OPENTHREAD_7_INDEX);
	(ZWOPENTHREAD)SYSTEMSERVICE(OPENTHREAD_7_INDEX) = newZwOpenThread;
	
	oldZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(QUERYSYSTEMINFORMATION_7_INDEX);
	(ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(QUERYSYSTEMINFORMATION_7_INDEX) = newZwQuerySystemInformation;
	
	oldZwCreateFile = (ZWCREATEFILE)SYSTEMSERVICE(CREATEFILE_7_INDEX);
	(ZWCREATEFILE)SYSTEMSERVICE(CREATEFILE_7_INDEX) = newZwCreateFile;
	
	oldZwReadFile = (ZWREADFILE)SYSTEMSERVICE(READFILE_7_INDEX);
	(ZWREADFILE)SYSTEMSERVICE(READFILE_7_INDEX) = newZwReadFile;
	
	oldZwWriteFile = (ZWWRITEFILE)SYSTEMSERVICE(WRITEFILE_7_INDEX);
	(ZWWRITEFILE)SYSTEMSERVICE(WRITEFILE_7_INDEX) = newZwWriteFile;
	
	oldZwDeleteFile = (ZWDELETEFILE)SYSTEMSERVICE(DELETEFILE_7_INDEX);
	(ZWDELETEFILE)SYSTEMSERVICE(DELETEFILE_7_INDEX) = newZwDeleteFile;
	
	oldZwSetInformationFile = (ZWSETINFORMATIONFILE)SYSTEMSERVICE(SETINFORMATIONFILE_7_INDEX);
	(ZWSETINFORMATIONFILE)SYSTEMSERVICE(SETINFORMATIONFILE_7_INDEX) = newZwSetInformationFile;
	
	oldZwQueryInformationFile = (ZWQUERYINFORMATIONFILE)SYSTEMSERVICE(QUERYINFORMATIONFILE_7_INDEX);
	(ZWQUERYINFORMATIONFILE)SYSTEMSERVICE(QUERYINFORMATIONFILE_7_INDEX) = newZwQueryInformationFile;

	oldZwCreateMutant = (ZWCREATEMUTANT)SYSTEMSERVICE(CREATEMUTANT_7_INDEX);
	(ZWCREATEMUTANT)SYSTEMSERVICE(CREATEMUTANT_7_INDEX) = newZwCreateMutant;
	
	oldZwDeviceIoControlFile = (ZWDEVICEIOCONTROLFILE)SYSTEMSERVICE(DEVICEIOCONTROLFILE_7_INDEX);
	(ZWDEVICEIOCONTROLFILE)SYSTEMSERVICE(DEVICEIOCONTROLFILE_7_INDEX) = newZwDeviceIoControlFile;
	
	oldZwTerminateProcess = (ZWTERMINATEPROCESS)SYSTEMSERVICE(TERMINATEPROCESS_7_INDEX);
	(ZWTERMINATEPROCESS)SYSTEMSERVICE(TERMINATEPROCESS_7_INDEX) = newZwTerminateProcess;
	
	oldZwDelayExecution = (ZWDELAYEXECUTION)SYSTEMSERVICE(DELAYEXECUTION_7_INDEX);
	(ZWDELAYEXECUTION)SYSTEMSERVICE(DELAYEXECUTION_7_INDEX) = newZwDelayExecution;
	
	oldZwQueryValueKey = (ZWQUERYVALUEKEY)SYSTEMSERVICE(QUERYVALUEKEY_7_INDEX);
	(ZWQUERYVALUEKEY)SYSTEMSERVICE(QUERYVALUEKEY_7_INDEX) = newZwQueryValueKey;
	
	oldZwQueryAttributesFile = (ZWQUERYATTRIBUTESFILE)SYSTEMSERVICE(QUERYATTRIBUTESFILE_7_INDEX);
	(ZWQUERYATTRIBUTESFILE)SYSTEMSERVICE(QUERYATTRIBUTESFILE_7_INDEX) = newZwQueryAttributesFile;
	
	oldZwReadVirtualMemory = (ZWREADVIRTUALMEMORY)SYSTEMSERVICE(READVIRTUALMEMORY_7_INDEX);
	(ZWREADVIRTUALMEMORY)SYSTEMSERVICE(READVIRTUALMEMORY_7_INDEX) = newZwReadVirtualMemory;
	
	oldZwResumeThread = (ZWRESUMETHREAD)SYSTEMSERVICE(RESUMETHREAD_7_INDEX);
	(ZWRESUMETHREAD)SYSTEMSERVICE(RESUMETHREAD_7_INDEX) = newZwResumeThread;
	
	oldZwCreateSection = (ZWCREATESECTION)SYSTEMSERVICE(CREATESECTION_7_INDEX);
	(ZWCREATESECTION)SYSTEMSERVICE(CREATESECTION_7_INDEX) = newZwCreateSection;
	
	oldZwUserCallNoParam = (ZWUSERCALLNOPARAM)SHADOWSERVICE(USERCALLNOPARAM_7_INDEX);
	(ZWUSERCALLNOPARAM)SHADOWSERVICE(USERCALLNOPARAM_7_INDEX) = newZwUserCallNoParam;
	
	oldZwLoadDriver = (ZWLOADDRIVER)SYSTEMSERVICE(LOADDRIVER_7_INDEX);
	(ZWLOADDRIVER)SYSTEMSERVICE(LOADDRIVER_7_INDEX) = newZwLoadDriver;

	enable_cr0();
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		get Shadow table address
//	Parameters :
//		None
//	Return value :
//		None
//  Process :
//      search in KeAddSystemServiceTable for LEA opcode, the first one will the one with the shadow table address,
//		returns that address
////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
pServiceDescriptorTableEntry getShadowTableAddress()   
{   
	PUCHAR c;
	for(c = (PUCHAR)&KeAddSystemServiceTable; c < (PUCHAR)&KeAddSystemServiceTable + PAGE_SIZE; c++)
	{
		if(*(PUSHORT)c == 0x888d)
			return *(PVOID*)(c+2);
	}
	return NULL;
}   

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs thread opening, and hides specific processes from the monitored processes.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/bb432382(v=vs.85).aspx
//	Process :
//		Calls the original function and if it succeeds, gets the targetThreadId by handle. If the targetProcessId is hidden
//		closes the handle and returns STATUS_INVALID_PARAMETER.
//		It the call failed, if ClientID is not NULL, copies the ClientID->UniqueThread parameter and
//		logs it. If ClientID is NULL (XP / s2003), copies the ObjectAttributes->ObjectName parameter
//		and logs it.
//	TODO :
//		- while blocking a call, restore the original *ThreadHandle value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetThreadId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	ULONG kUniqueThread;
	HANDLE kThreadHandle;
	UNICODE_STRING kObjectName;

	kObjectName.Buffer = NULL;

	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWOPENTHREAD)(oldZwOpenThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ClientID);
	if(isProcessMonitoredByPid(currentProcessId))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		DbgPrint("call ZwOpenThread\n");
		#endif
	
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
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR",exceptionCode)))
					sendLogs(currentProcessId, L"ZwOpenThread", parameter);
				else
					sendLogs(currentProcessId, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->1");
				if(parameter)
					ExFreePool(parameter);
				return statusCall;
			}
		
			targetThreadId = getTIDByHandle(kThreadHandle);
			targetProcessId = getPIDByThreadHandle(kThreadHandle);
			
			if(isProcessHiddenByPid(targetProcessId))
			{
				ZwClose(kThreadHandle);
				if(parameter && RtlStringCchPrintfW(parameter, MAXSIZE, L"0,3221225485,sss,ThreadHandle->ERROR,TID->%d,DesiredAccess->0x%08x", targetThreadId, DesiredAccess))
					sendLogs(currentProcessId, L"ZwOpenThread", parameter);
				else
					sendLogs(currentProcessId, L"ZwOpenThread", L"0,3221225485,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
				ExFreePool(parameter);
				return STATUS_INVALID_PARAMETER;
			}
			
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ThreadHandle->0x%08x,TID->%d,DesiredAccess->0x%08x", kThreadHandle, targetThreadId, DesiredAccess)))
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
					kUniqueThread = (ULONG)ClientID->UniqueThread;
				} 
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					exceptionCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR", exceptionCode)))
						sendLogs(currentProcessId, L"ZwOpenThread", parameter);
					else 
						sendLogs(currentProcessId, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
					if(parameter)
						ExFreePool(parameter);
					return statusCall;
				}
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,0,sss,ThreadHandle->ERROR,TID->%d,DesiredAccess->0x%08x", kUniqueThread, DesiredAccess)))
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
					if(!kObjectName.Buffer)
					{
						if(parameter)
							ExFreePool(parameter);
						sendLogs(currentProcessId, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
						return statusCall;
					}
					RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					exceptionCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR", exceptionCode)))
						sendLogs(currentProcessId, L"ZwOpenThread", parameter);
					else 
						sendLogs(currentProcessId, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
					if(parameter)
						ExFreePool(parameter);
					if(kObjectName.Buffer)
						ExFreePool(kObjectName.Buffer);
					return statusCall;
				}
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,0,sss,ThreadHandle->ERROR,TID->%wZ,DesiredAccess->0x%08x", &kObjectName, DesiredAccess)))
					log_lvl = LOG_PARAM;
				if(kObjectName.Buffer)
					ExFreePool(kObjectName.Buffer);
			}
		}

		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwOpenThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwOpenThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwOpenThread", L"1,0,sss,ThreadHandle->ERROR,TID->ERROR,DesiredAccess->ERROR");
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
//		Calls the original function and if it succeeds, gets the targetProcessId by handle. If the targetProcessId is hidden
//		closes the handle and returns STATUS_INVALID_PARAMETER.
//		It the call failed, if ClientID is not NULL, copies the ClientID->UniqueThread parameter and
//		logs it. If ClientID is NULL (XP / s2003), copies the ObjectAttributes->ObjectName parameter
//		and logs it.
//	TODO :
//		- while blocking a call, restore the original *ProcessHandle value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
{	
	NTSTATUS statusCall, status, exceptionCode;
	ULONG currentProcessId, i, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	UNICODE_STRING targetProcessName;
	PWCHAR parameter = NULL;
	
	HANDLE kRootDirectory, kProcessHandle;
	UNICODE_STRING kObjectName;
	ULONG kUniqueProcess;
	
	kObjectName.Buffer = NULL;
	targetProcessName.Buffer = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWOPENPROCESS)(oldZwOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientID);
	if(isProcessMonitoredByPid(currentProcessId))
	{   	
	
		#ifdef DEBUG
		DbgPrint("call ZwOpenProcess\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		targetProcessName.Length = 0;
		targetProcessName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
		targetProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, targetProcessName.MaximumLength, PROCNAME_TAG);
		
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
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR",exceptionCode)))
					sendLogs(currentProcessId, L"ZwOpenProcess", parameter);
				else
					sendLogs(currentProcessId, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->1");
				ExFreePool(parameter);
				return statusCall;;
			}
		
			targetProcessId = getPIDByHandle(kProcessHandle);
			if(targetProcessName.Buffer)
				status = getProcNameByPID(targetProcessId, &targetProcessName);
			else
				status = STATUS_NOT_FOUND;
				
			if(isProcessHiddenByPid(targetProcessId))
			{
				ZwClose(kProcessHandle);
				if(parameter && NT_SUCCESS(status) && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,-1,ssss,ProcessHandle->0x%08x,ProcessName->%wZ,PID->%d,DesiredAccess->0x%08x", kProcessHandle, &targetProcessName, targetProcessId, DesiredAccess)))
					sendLogs(currentProcessId, L"ZwOpenProcess", parameter);
				else
					sendLogs(currentProcessId, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->ERROR,ProcessName->ERROR_HIDDEN,PID->ERROR,DesiredAccess->ERROR");
				
				if(targetProcessName.Buffer)
					ExFreePool(targetProcessName.Buffer);
				if(parameter)
					ExFreePool(parameter);
				return STATUS_INVALID_PARAMETER;
			}
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(status) && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,ProcessHandle->0x%08x,ProcessName->%wZ,PID->%d,DesiredAccess->0x%08x", kProcessHandle, &targetProcessName, targetProcessId, DesiredAccess)))
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
					exceptionCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR", exceptionCode)))
						sendLogs(currentProcessId, L"ZwOpenProcess", parameter);
					else 
						sendLogs(currentProcessId, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR");
					if(parameter)
						ExFreePool(parameter);
					if(targetProcessName.Buffer)
						ExFreePool(targetProcessName.Buffer);
					return statusCall;
				}
				
				if(targetProcessName.Buffer)
					status = getProcNameByPID(kUniqueProcess, &targetProcessName);
				else
					status = STATUS_NOT_FOUND;
				
				if(parameter && NT_SUCCESS(status) && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->ERROR,ProcessName->%wZ,PID->%d,DesiredAccess->0x%08x", statusCall,&targetProcessName, kUniqueProcess, DesiredAccess)))
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
						if(targetProcessName.Buffer)
							ExFreePool(targetProcessName.Buffer);
						sendLogs(currentProcessId, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR");
						return statusCall;
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					exceptionCode = GetExceptionCode();
					if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR", exceptionCode)))
						sendLogs(currentProcessId, L"ZwOpenProcess", parameter);
					else 
						sendLogs(currentProcessId, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR");
					if(parameter)
						ExFreePool(parameter);
					if(targetProcessName.Buffer)
						ExFreePool(targetProcessName.Buffer);
					if(kObjectName.Buffer)
						ExFreePool(kObjectName.Buffer);
					return statusCall;
				}
				if(parameter && kObjectName.Buffer && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->ERROR,ProcessName->%wZ,PID->ERROR,DesiredAccess->0x%08x", statusCall,&kObjectName,DesiredAccess)))
				{
					log_lvl = LOG_PARAM;
					ExFreePool(kObjectName.Buffer);
				}
			}
		}		
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwOpenProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwOpenProcess", L"0,-1,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwOpenProcess", L"1,0,ssss,ProcessHandle->ERROR,ProcessName->ERROR,PID->ERROR,DesiredAccess->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(targetProcessName.Buffer)
			ExFreePool(targetProcessName.Buffer);
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
//		hidden targetProcessIds are unlinked from the result (SYSTEM_PROCESS_INFORMATION linked list).
//	Todo :
//		- Hide also thread listing
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetThreadId, i;
	USHORT log_lvl = LOG_ERROR;
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = NULL, pPrev = NULL;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = ((ZWQUERYSYSTEMINFORMATION)(oldZwQuerySystemInformation))(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwQuerySystemInformation\n");
		#endif
		
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
				
				sendLogs(currentProcessId, L"ZwQuerySystemInformation",L"1,0,s,SystemInformationClass->5");
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
				sendLogs(currentProcessId, L"ZwQuerySystemInformation", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwQuerySystemInformation", L"0,-1,s,SystemInformationClass->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwQuerySystemInformation", L"1,0,s,SystemInformationClass->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs virtual memory read.
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtReadVirtualMemory.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtReadVirtualMemory.html
//	Process :
//		logs the ProcessHandle, BaseAddress and NumberOfBytesToRead parameters.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetProcessId;
	ULONG log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWREADVIRTUALMEMORY)(oldZwReadVirtualMemory))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwReadVirtualMemory\n");
		#endif
		
		targetProcessId = getPIDByHandle(ProcessHandle);
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,NumberOfBytesToRead->%d", ProcessHandle, targetProcessId, BaseAddress, NumberOfBytesToRead)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,NumberOfBytesToRead->%d", statusCall, ProcessHandle, targetProcessId, BaseAddress, NumberOfBytesToRead)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwReadVirtualMemory", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwReadVirtualMemory", L"0,1,ssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,NumberOfBytesToRead->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwReadVirtualMemory", L"1,0,ssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,NumberOfBytesToRead->ERROR");
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
	ULONG currentProcessId, targetProcessId;
	ULONG log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWWRITEVIRTUALMEMORY)(oldZwWriteVirtualMemory))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwWriteVirtualMemory\n");
		#endif
		
		targetProcessId = getPIDByHandle(ProcessHandle);
		
		if(NT_SUCCESS(statusCall) && targetProcessId)
			startMonitoringProcess(targetProcessId);
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,Buffer->0x%08x,NumberOfBytesToWrite->%d", ProcessHandle, targetProcessId, BaseAddress, Buffer, NumberOfBytesToWrite)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,Buffer->0x%08x,NumberOfBytesToWrite->%d", statusCall, ProcessHandle, targetProcessId, BaseAddress, Buffer, NumberOfBytesToWrite)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwWriteVirtualMemory", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwWriteVirtualMemory", L"0,1,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,Buffer->ERROR,NumberOfBytesToWrite->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwWriteVirtualMemory", L"1,0,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,Buffer->ERROR,NumberOfBytesToWrite->ERROR");
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
//		Adds the process to the monitored processes list and logs the targetProcessId, ProcessHandle and DebugHandle parameters
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle)
{
	NTSTATUS statusCall;
	ULONG targetProcessId, currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWDEBUGACTIVEPROCESS)(oldZwDebugActiveProcess))(ProcessHandle, DebugHandle);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{		
		#ifdef DEBUG
		DbgPrint("call ZwDebugActiveProcess\n");
		#endif
		
		targetProcessId = getPIDByHandle(ProcessHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ProcessHandle->0x%08x,PID->%d,DebugHandle->0x%08x", ProcessHandle, targetProcessId, DebugHandle)))
				log_lvl = LOG_PARAM;
			if(targetProcessId)
				startMonitoringProcess(targetProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ProcessHandle->0x%08x,PID->%d,DebugHandle->0x%08x", statusCall, ProcessHandle, targetProcessId, DebugHandle)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwDebugActiveProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwDebugActiveProcess", L"0,-1,sss,ProcessHandle->ERROR,PID->ERROR,DebugHandle->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwDebugActiveProcess", L"1,0,sss,ProcessHandle->ERROR,PID->ERROR,DebugHandle->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process name creation.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566428%28v=vs.85%29.aspx
//	Process :
//		logs SectionHandle, FileHandle and FileName
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
	NTSTATUS statusCall;
	ULONG currentProcessId;
	POBJECT_NAME_INFORMATION filename;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATESECTION)(oldZwCreateSection))(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{		
		#ifdef DEBUG
		DbgPrint("call ZwCreateSection\n");
		#endif
		
		if((AllocationAttributes & 0x1000000/*SEC_IMAGE*/) && (SectionPageProtection & PAGE_EXECUTE) && FileHandle)
		{
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			filename = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			
			if(NT_SUCCESS(statusCall))
			{	
				if(filename)
				{
					ZwQueryObject(FileHandle, ObjectNameInformation, filename, MAXSIZE, NULL);
					if(parameter && filename && SectionHandle && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,SectionHandle->0x%08x,FileHandle->0x%08x,FileName->%wZ", *SectionHandle, FileHandle, &(filename->Name))))
						sendLogs(currentProcessId, L"ZwCreateSection", parameter);		
				}
				else
					sendLogs(currentProcessId, L"ZwCreateSection", L"1,0,sss,SectionHandle->ERROR,FileHandle->ERROR,FileName->ERROR");
			}
			else
			{
				if(parameter && filename && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,SectionHandle->0,FileHandle->0x%08x,FileName->%wZ", statusCall, FileHandle, &(filename->Name))))
					sendLogs(currentProcessId, L"ZwCreateSection", parameter);
			}
			if(filename != NULL)
				ExFreePool(filename);
			if(parameter != NULL)
				ExFreePool(parameter);
		}
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
//		Starts the process, gets its targetProcessId and adds it to the monitored processes list and logs
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, childProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	HANDLE kProcessHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEPROCESS)(oldZwCreateProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwCreateProcess\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
			kProcessHandle = *ProcessHandle;
			childProcessId = getPIDByHandle(kProcessHandle);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritObjectTable->ERROR,ParentProcess->ERROR,SectionHandle->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateProcess", parameter);
			else 
				sendLogs(currentProcessId, L"ZwCreateProcess", L"0,-1,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritObjectTable->ERROR,ParentProcess->ERROR,SectionHandle->ERROR");
			ExFreePool(parameter);
			return statusCall;;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritObjectTable->%d,ParentProcess->0x%08x,SectionHandle->0x%08x", kProcessHandle,childProcessId,DesiredAccess,InheritObjectTable,ParentProcess,SectionHandle)))
				log_lvl = LOG_PARAM;
			if(childProcessId)
				startMonitoringProcess(childProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritObjectTable->%d,ParentProcess->0x%08x,SectionHandle->0x%08x", statusCall,kProcessHandle,childProcessId,DesiredAccess,InheritObjectTable,ParentProcess,SectionHandle)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwCreateProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateProcess", L"0,-1,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritObjectTable->ERROR,ParentProcess->ERROR,SectionHandle->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateProcess", L"1,0,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritObjectTable->ERROR,ParentProcess->ERROR,SectionHandle->ERROR");
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
//		Starts the process, gets its targetProcessId and adds it to the monitored processes list then logs
////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE dunno)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, childProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	HANDLE kProcessHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEPROCESSEX)(oldZwCreateProcessEx))(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort, dunno);	 
		
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwCreateProcessEx\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
			kProcessHandle = *ProcessHandle;
			childProcessId = getPIDByHandle(kProcessHandle);
		} 
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritHandles->ERROR,InheritFromProcessHandle->ERROR,SectionHandle->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateProcessEx", parameter);
			else 
				sendLogs(currentProcessId, L"ZwCreateProcessEx", L"0,-1,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritHandles->ERROR,InheritFromProcessHandle->ERROR,SectionHandle->ERROR");
			ExFreePool(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritHandles->%d,InheritFromProcessHandle->0x%08x,SectionHandle->0x%08x", kProcessHandle,childProcessId,DesiredAccess,InheritHandles,InheritFromProcessHandle,SectionHandle)))
				log_lvl = LOG_PARAM;
			
			if(childProcessId)
				startMonitoringProcess(childProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssss,ProcessHandle->0x%08x,PID->%d,DesiredAccess->0x%08x,InheritObjectTable->%d,ParentProcess->0x%08x,SectionHandle->0x%08x", statusCall,kProcessHandle,childProcessId,DesiredAccess,InheritHandles,InheritFromProcessHandle,SectionHandle)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwCreateProcessEx", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateProcessEx", L"0,-1,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritHandles->ERROR,InheritFromProcessHandle->ERROR,SectionHandle->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateProcessEx", L"1,0,ssssss,ProcessHandle->ERROR,PID->ERROR,DesiredAccess->ERROR,InheritHandles->ERROR,InheritFromProcessHandle->ERROR,SectionHandle->ERROR");
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
	ULONG currentProcessId, targetThreadId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWQUEUEAPCTHREAD)(oldZwQueueApcThread))(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwQueueApcThread\n");
		#endif
		
		targetThreadId = getTIDByHandle(ThreadHandle);
		targetProcessId = getPIDByThreadHandle(ThreadHandle);
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,ThreadHandle->0x%08x,TID->%d,PID->%d,ApcRoutine->0x%08x", ThreadHandle, targetThreadId, targetProcessId, ApcRoutine)))
				log_lvl = LOG_PARAM;
			
			if(targetProcessId)
				startMonitoringProcess(targetProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,ThreadHandle->0x%08x,TID->%d,PID->%d,ApcRoutine->0x%08x", statusCall, ThreadHandle, targetThreadId, targetProcessId, ApcRoutine)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwQueueApcThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwQueueApcThread", L"0,-1,ssss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR,ApcRoutine->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwQueueApcThread", L"1,0,ssss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR,ApcRoutine->ERROR");
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
//		Gets the thread's owner, proceeds the call then adds immediately the targetProcessId to the monitored
//		processes list if it succeeded. Then logs.
//	Notes :
//		Actually, a race condition occurs : we must create the thread before adding the remote process
//		to the list in order to check if the thread was created successfuly. However, a malware would
//		not create a thread without giving it nothing to execute, right? :]
//	TODO :
//		- Create the thread in suspended state and resume it after adding the process to the list to avoid
//		race condition issues.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientID, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId, createdThreadId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	HANDLE kThreadHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	targetProcessId = getPIDByHandle(ProcessHandle);	// faster than placing it after the monitored process check
	statusCall = ((ZWCREATETHREAD)(oldZwCreateThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, ThreadContext, InitialTeb, CreateSuspended);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwCreateThread\n");
		#endif
		
		if(NT_SUCCESS(statusCall) && targetProcessId)
			startMonitoringProcess(targetProcessId);	// <-- RACE CONDITION
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		_try
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
			kThreadHandle = *ThreadHandle;
		} 
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateThread", parameter);
			else 
				sendLogs(currentProcessId, L"ZwCreateThread", L"0,-1,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
			if(parameter)
				ExFreePool(parameter);
			return statusCall;
		}
		
		createdThreadId = getTIDByHandle(kThreadHandle);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,PID->%d,ThreadHandle->0x%08x,TID->%d,CreateSuspended->%d,DesiredAccess->0x%08x", targetProcessId, kThreadHandle, createdThreadId, CreateSuspended, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,PID->%d,ThreadHandle->0x%08x,TID->%d,CreateSuspended->%d,DesiredAccess->0x%08x", statusCall, targetProcessId, kThreadHandle, createdThreadId, CreateSuspended, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwCreateThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateThread", L"0,-1,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateThread", L"1,0,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
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
//		See http://securityxploded.com/ntcreatethreadex.php (lulz)
//	Return value :
//		See http://securityxploded.com/ntcreatethreadex.php (lulz)
//	Process :
//		Gets the thread's owner, proceeds the call then adds immediately the targetProcessId to the monitored
//		processes list if it succeeded. Then logs.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress, PVOID Parameter, BOOLEAN CreateSuspended, ULONG StackZeroBits, ULONG SizeOfStackCommit, ULONG SizeOfStackReserve, PVOID BytesBuffer)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId, createdThreadId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	HANDLE kThreadHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	targetProcessId = getPIDByHandle(ProcessHandle);	// faster than placing it after the monitored process check
	statusCall = ((ZWCREATETHREADEX)(oldZwCreateThreadEx))(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartAddress, Parameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, BytesBuffer);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwCreateThreadEx\n");
		#endif
		
		if(NT_SUCCESS(statusCall) && targetProcessId)
			startMonitoringProcess(targetProcessId);	// <-- RACE CONDITION
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		_try
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
			kThreadHandle = *ThreadHandle;
		} 
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateThreadEx", parameter);
			else 
				sendLogs(currentProcessId, L"ZwCreateThreadEx", L"0,-1,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
			if(parameter)
				ExFreePool(parameter);
			return statusCall;
		}
		
		createdThreadId = getTIDByHandle(kThreadHandle);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,PID->%d,ThreadHandle->0x%08x,TID->%d,CreateSuspended->%d,DesiredAccess->0x%08x", targetProcessId, kThreadHandle, createdThreadId, CreateSuspended, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,PID->%d,ThreadHandle->0x%08x,TID->%d,CreateSuspended->%d,DesiredAccess->0x%08x", statusCall, targetProcessId, kThreadHandle, createdThreadId, CreateSuspended, DesiredAccess)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwCreateThreadEx", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateThreadEx", L"0,-1,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateThreadEx", L"1,0,sssss,PID->ERROR,ThreadHandle->ERROR,TID->ERROR,CreateSuspended->ERROR,DesiredAccess->ERROR");
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
	ULONG targetProcessId, currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWMAPVIEWOFSECTION)(oldZwMapViewOfSection))(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{		
		targetProcessId = getPIDByHandle(ProcessHandle);
		
		if(currentProcessId != targetProcessId)
		{
			#ifdef DEBUG
			DbgPrint("call ZwMapViewOfSection\n");
			#endif
		
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			
			if(NT_SUCCESS(statusCall))
			{
				log_lvl = LOG_SUCCESS;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,SectionHandle->0x%08x,Win32Protect->%d", ProcessHandle, targetProcessId, BaseAddress, SectionHandle, Win32Protect)))
					log_lvl = LOG_PARAM;
				
				startMonitoringProcess(targetProcessId);
			}
			else
			{
				log_lvl = LOG_ERROR;
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,ProcessHandle->0x%08x,PID->%d,BaseAddress->0x%08x,SectionHandle->0x%08x,Win32Protect->%d", statusCall, ProcessHandle, targetProcessId, BaseAddress, SectionHandle, Win32Protect)))
					log_lvl = LOG_PARAM;
			}
			
			switch(log_lvl)
			{
				case LOG_PARAM:
					sendLogs(currentProcessId, L"NtMapViewOfSection", parameter);
				break;
				case LOG_SUCCESS:
					sendLogs(currentProcessId, L"NtMapViewOfSection", L"0,-1,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,SectionHandle->ERROR,Win32Protect->ERROR");
				break;
				default:
					sendLogs(currentProcessId, L"NtMapViewOfSection", L"1,0,sssss,ProcessHandle->ERROR,PID->ERROR,BaseAddress->ERROR,SectionHandle->ERROR,Win32Protect->ERROR");
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
	ULONG currentProcessId, targetThreadId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWSETCONTEXTTHREAD)(oldZwSetContextThread))(ThreadHandle, Context);
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwSetContextThread\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		targetThreadId = getTIDByHandle(ThreadHandle);
		targetProcessId = getPIDByThreadHandle(ThreadHandle);
	
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ThreadHandle->0x%08x,TID->%d,PID->%d", ThreadHandle, targetThreadId, targetProcessId)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,sss,ThreadHandle->0x%08x,TID->%d,PID->%d", statusCall, ThreadHandle, targetThreadId, targetProcessId)))
				log_lvl = LOG_PARAM;
		}
	
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwSetContextThread", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwSetContextThread", L"0,-1,sss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwSetContextThread", L"1,0,sss,ThreadHandle->ERROR,TID->ERROR,PID->ERROR");
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
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWSYSTEMDEBUGCONTROL)(oldZwSystemDebugControl))(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwSystemDebugControl\n");
		#endif
		
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
				sendLogs(currentProcessId, L"ZwSystemDebugControl", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwSystemDebugControl", L"0,-1,s,Command->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwSystemDebugControl", L"1,0,s,Command->ERROR");
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
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, returnLength;
	USHORT log_lvl = LOG_ERROR;
	UNICODE_STRING full_path;
	PWCHAR parameter = NULL;
	POBJECT_NAME_INFORMATION nameInformation = NULL;
	
	HANDLE kRootDirectory, kFileHandle;
	UNICODE_STRING kObjectName;
	
	full_path.Buffer = NULL;
	kObjectName.Buffer = NULL;
	
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEFILE)(oldZwCreateFile))(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwCreateFile\n");
		#endif
		
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
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateFile", parameter);
			else 
				sendLogs(currentProcessId ,L"ZwCreateFile", L"0,-1,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR");
			ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return statusCall;
		}
		
		if(kRootDirectory)	// handle the not null rootdirectory case
		{
			// allocate both name information struct and unicode string buffer
			nameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			if(nameInformation)
			{
				if(NT_SUCCESS(ZwQueryObject(kRootDirectory, ObjectNameInformation, nameInformation, MAXSIZE, NULL)))
				{
					full_path.MaximumLength = nameInformation->Name.Length + kObjectName.Length + 2 + sizeof(WCHAR);
					full_path.Buffer = ExAllocatePoolWithTag(NonPagedPool, full_path.MaximumLength, BUFFER_TAG);
					RtlZeroMemory(full_path.Buffer, full_path.MaximumLength);
					RtlCopyUnicodeString(&full_path, &(nameInformation->Name));
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
				sendLogs(currentProcessId, L"ZwCreateFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateFile", L"0,-1,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateFile", L"1,0,sssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR");
			break;
		}
		if(kObjectName.Buffer && kObjectName.Buffer != full_path.Buffer)
			ExFreePool(kObjectName.Buffer);
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInformation != NULL)
			ExFreePool(nameInformation);
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
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, returnLength;
	USHORT log_lvl = LOG_ERROR;
	POBJECT_NAME_INFORMATION nameInformation = NULL;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWREADFILE)(oldZwReadFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwReadFile\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		nameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
		if(nameInformation)
			ZwQueryObject(FileHandle, ObjectNameInformation, nameInformation, MAXSIZE, NULL);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(nameInformation && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", statusCall, FileHandle, &(nameInformation->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(nameInformation && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", statusCall, FileHandle, &(nameInformation->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwReadFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwReadFile", L"0,-1,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwReadFile", L"1,0,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInformation != NULL)
			ExFreePool(nameInformation);
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
	ULONG currentProcessId, returnLength;
	USHORT log_lvl = LOG_ERROR;
	POBJECT_NAME_INFORMATION nameInformation = NULL;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWWRITEFILE)(oldZwWriteFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwWriteFile\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		nameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
		if(nameInformation)
			ZwQueryObject(FileHandle, ObjectNameInformation, nameInformation, MAXSIZE, NULL);
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(nameInformation && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", FileHandle, &(nameInformation->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(nameInformation && parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ssss,FileHandle->0x%08x,FileName->%wZ,Buffer->0x%08x,Length->%d", statusCall, FileHandle, &(nameInformation->Name), Buffer, Length)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwWriteFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwWriteFile", L"0,-1,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwWriteFile", L"1,0,ssss,FileHandle->ERROR,FileName->ERROR,Buffer->ERROR,Length->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
		if(nameInformation != NULL)
			ExFreePool(nameInformation);
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
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	UNICODE_STRING kObjectName;
	kObjectName.Buffer = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWDELETEFILE)(oldZwDeleteFile))(ObjectAttributes);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwDeleteFile\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
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
				sendLogs(currentProcessId ,L"ZwDeleteFile", L"0,-1,s,FileName->ERROR");
				if(parameter)
					ExFreePool(parameter);
				return statusCall;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,FileName->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwDeleteFile", parameter);
			else 
				sendLogs(currentProcessId ,L"ZwDeleteFile", L"0,-1,s,FileName->ERROR");
			if(parameter)
				ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return statusCall;
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
				sendLogs(currentProcessId, L"ZwDeleteFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwDeleteFile", L"0,-1,s,FileName->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwDeleteFile", L"1,0,s,FileName->ERROR");
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
//		If FileRenameInformationrmation, the FileInformation->FileName parameter is copied along with the
//		FileInformation->RootDirectory parameter, then the call is logged.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	UNICODE_STRING full_path;
	POBJECT_NAME_INFORMATION originalNameInformation = NULL;
	PWCHAR parameter = NULL;
	PWCHAR newFileName = NULL;
	
	BOOLEAN kDeleteFile;
	ULONG kFileNameLength;
	PFILE_RENAME_INFORMATION kFileRenameInformation = NULL;
	PWCHAR kFileName = NULL;
	HANDLE kFileHandle, kRootDirectory;
	
	full_path.Buffer = NULL;
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWSETINFORMATIONFILE)(oldZwSetInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwSetInformationFile\n");
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(FileHandle, sizeof(HANDLE), 1);
			kFileHandle = FileHandle;
		} 
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(FileInformationClass == FileDispositionInformation)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR", exceptionCode)))
					sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", parameter);
				else 
					sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", L"0,-1,sss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR");
			}
			else if(FileInformationClass == FileRenameInformation)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,FileHandle->ERROR,OriginalName->ERROR,Renamed->ERROR,FileInformationClass->ERROR", exceptionCode)))
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", parameter);
				else 
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->ERROR,OriginalName->ERROR,Renamed->ERROR,FileInformationClass->ERROR");
			}
			if(parameter)
				ExFreePool(parameter);
			return statusCall;
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
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR", exceptionCode)))
					sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", parameter);
				else
					sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", L"0,-1,sss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR");
				if(parameter)
					ExFreePool(parameter);
				return statusCall;
			}
			
			if(kDeleteFile == TRUE)
			{
				originalNameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
				if(originalNameInformation && parameter)
					ZwQueryObject(kFileHandle, ObjectNameInformation, originalNameInformation, MAXSIZE, NULL);
				if(NT_SUCCESS(statusCall))
				{
					log_lvl = LOG_SUCCESS;
					if(parameter && originalNameInformation && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,sss,FileHandle->0x%08x,FileName->%wZ,FileInformationClass->%d", statusCall, FileHandle, &(originalNameInformation->Name), FileInformationClass)))
						log_lvl = LOG_PARAM;
				}
				else
				{
					log_lvl = LOG_ERROR;
					if(parameter && originalNameInformation && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,FileHandle->0x%08x,FileName->%wZ,FileInformationClass->%d", statusCall, FileHandle, &(originalNameInformation->Name), FileInformationClass)))
						log_lvl = LOG_PARAM;
				}
				switch(log_lvl)
				{
					case LOG_PARAM:
						sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", parameter);
					break;
					case LOG_SUCCESS:
						sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", L"1,0,sss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR");
					break;
					default:
						sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", L"0,0,sss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR");
					break;
				}
				if(originalNameInformation != NULL)
					ExFreePool(originalNameInformation);
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
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->ERROR,OriginalName->ERROR,Renamed->ERROR,FileInformationClass->ERROR");
					if(parameter)
						ExFreePool(parameter);
					return statusCall;
				}
				RtlZeroMemory(kFileName, kFileNameLength + sizeof(WCHAR));
				RtlCopyMemory(kFileName, kFileRenameInformation->FileName, kFileNameLength);
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,FileHandle->ERROR,OriginalName->ERROR,Renamed->ERROR,FileInformationClass->ERROR", exceptionCode)))
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", parameter);
				else
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->ERROR,OriginalName->ERROR,Renamed->ERROR,FileInformationClass->ERROR");
				if(parameter)
					ExFreePool(parameter);
				if(kFileName)
					ExFreePool(kFileName);
				return statusCall;
			}
			
			if(kRootDirectory)	// handle the not null RootDirectory case
			{
				// allocate both name information struct and unicode string buffer
				originalNameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
				if(originalNameInformation)
				{
					if(NT_SUCCESS(ZwQueryObject(kRootDirectory, ObjectNameInformation, originalNameInformation, MAXSIZE, NULL)) && kFileNameLength < 0xFFF0)
					{
						full_path.MaximumLength = originalNameInformation->Name.Length + (USHORT)kFileNameLength + 2 + sizeof(WCHAR);
						full_path.Buffer = ExAllocatePoolWithTag(NonPagedPool, full_path.MaximumLength, BUFFER_TAG);
						RtlZeroMemory(full_path.Buffer, full_path.MaximumLength);
						RtlCopyUnicodeString(&full_path, &(originalNameInformation->Name));
						RtlAppendUnicodeToString(&full_path, L"\\");
						RtlAppendUnicodeToString(&full_path, kFileName);
					}
				}
				else
					RtlInitUnicodeString(&full_path, kFileName);
			}
			else
				RtlInitUnicodeString(&full_path, kFileName);
			
			originalNameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
			if(originalNameInformation && parameter)
				ZwQueryObject(kFileHandle, ObjectNameInformation, originalNameInformation, MAXSIZE, NULL);
			
			if(NT_SUCCESS(statusCall))
			{
				log_lvl = LOG_SUCCESS;
				if(parameter && originalNameInformation && kFileName)
					if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,FileHandle->0x%08x,OriginalName->%wZ,Renamed->%wZ,FileInformationClass->%d", FileHandle, &(originalNameInformation->Name), &full_path, FileInformationClass)))
						log_lvl = LOG_PARAM;
			}
			else
			{
				log_lvl = LOG_ERROR;
				if(parameter && originalNameInformation && kFileName)
					if(NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,FileHandle->0x%08x,,OriginalName->%wZ,Renamed->%wZ,FileInformationClass->%d", statusCall, FileHandle, &(originalNameInformation->Name), &full_path, FileInformationClass)))
						log_lvl = LOG_PARAM;
			}
			
			if(full_path.Buffer && full_path.Buffer != kFileName)
				ExFreePool(full_path.Buffer);
			if(kFileName)
				ExFreePool(kFileName);
			if(originalNameInformation)
				ExFreePool(originalNameInformation);
			
			switch(log_lvl)
			{
				case LOG_PARAM:
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", parameter);
				break;
				case LOG_SUCCESS:
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", L"1,0,ssss,FileHandle->ERROR,OriginalName->ERROR,Renamed->ERROR,FileInformationClass->ERROR");
				break;
				default:
					sendLogs(currentProcessId, L"ZwSetInformationFile (Rename)", L"0,-1,ssss,FileHandle->ERROR,OriginalName->ERROR,Renamed->ERROR,FileInformationClass->ERROR");
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
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWQUERYINFORMATIONFILE)(oldZwQueryInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwQueryInformationFile\n");
		#endif
		
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
				sendLogs(currentProcessId, L"ZwQueryInformationFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwQueryInformationFile", L"0,-1,ss,FileHandle->ERROR,FileInformationClass->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwQueryInformationFile", L"1,0,ss,FileHandle->ERROR,FileInformationClass->ERROR");
			break;
		}
		if(parameter)
			ExFreePool(parameter);
	}

	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs mutex creation
//	Parameters :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//	Return value :
//		See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html
//	Process :
//		logs mutex handle, desired access, mutex name and initial owner
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	HANDLE kMutantHandle;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	kObjectName.Buffer = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEMUTANT)(oldZwCreateMutant))(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{	
		#ifdef DEBUG
		DbgPrint("call ZwCreateMutant\n");
		#endif
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try
		{
			if(ExGetPreviousMode() != KernelMode)
			{
				ProbeForRead(MutantHandle, sizeof(HANDLE), 1);
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
			}
			kMutantHandle = *MutantHandle;
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
			kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
			if(kObjectName.Buffer)
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			else
			{
				sendLogs(currentProcessId ,L"ZwCreateMutant", L"0,-1,ssss,MutantHandle->ERROR,DesiredAccess->ERROR,MutexName->ERROR,InitialOwner->ERROR");
				if(parameter)
					ExFreePool(parameter);
				return statusCall;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{	
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,MutantHandle->ERROR,DesiredAccess->ERROR,MutexName->ERROR,InitialOwner->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateMutant", parameter);
			else 
				sendLogs(currentProcessId ,L"ZwCreateMutant", L"0,-1,ssss,MutantHandle->ERROR,DesiredAccess->ERROR,MutexName->ERROR,InitialOwner->ERROR");
			if(parameter)
				ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return statusCall;
		}
	
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssss,MutantHandle->0x%08x,DesiredAccess->0x%08x,MutexName->%wZ,InitialOwner->%d", kMutantHandle, DesiredAccess, &kObjectName, InitialOwner)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ssss,MutantHandle->0x%08x,DesiredAccess->0x%08x,MutexName->%wZ,InitialOwner->%d", statusCall, kMutantHandle, DesiredAccess, &kObjectName, InitialOwner)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwCreateMutant", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateMutant", L"0,-1,ssss,MutantHandle->ERROR,DesiredAccess->ERROR,MutexName->ERROR,InitialOwner->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateMutant", L"1,0,ssss,MutantHandle->ERROR,DesiredAccess->ERROR,MutexName->ERROR,InitialOwner->ERROR");
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
//  	Logs IOCTLs
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566441%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566441%28v=vs.85%29.aspx
//	Process :
//		logs file handle and IoControlCode	
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OuputBuffer, ULONG OutputBufferLength)
{
	NTSTATUS statusCall;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWDEVICEIOCONTROLFILE)(oldZwDeviceIoControlFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OuputBuffer, OutputBufferLength);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		#ifdef DEBUG
		DbgPrint("call ZwDeviceIoControlFile\n");
		#endif
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,FileHandle->0x%08x,IoControlCode->0x%08x", FileHandle, IoControlCode)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ss,FileHandle->0x%08x,IoControlCode->0x%08x", statusCall, FileHandle, IoControlCode)))
				log_lvl = LOG_PARAM;
		}
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwDeviceIoControlFile", parameter);
			break;
				
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwDeviceIoControlFile", L"0,-1,ss,FileHandle->ERROR,IoControlCode->ERROR");
			break;
				
			default:
				sendLogs(currentProcessId, L"ZwDeviceIoControlFile", L"1,0,ss,FileHandle->ERROR,IoControlCode->ERROR");
			break;
		}
		if(parameter)
				ExFreePool(parameter);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs process termination.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567115%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567115%28v=vs.85%29.aspx
//	Process :
//		logs process handle , pid and exit status	
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	targetProcessId = getPIDByHandle(ProcessHandle);
	
	statusCall = ((ZWTERMINATEPROCESS)(oldZwTerminateProcess))(ProcessHandle, ExitStatus);
	
	if(isProcessMonitoredByPid(currentProcessId) || isProcessMonitoredByPid(targetProcessId))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		DbgPrint("call ZwTerminateProcess\n");
		#endif
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(ProcessHandle)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ProcessHandle->0x%08x,PID->%d,ExitStatus->0x%08x", ProcessHandle, targetProcessId, ExitStatus)))
					log_lvl = LOG_PARAM;
			}
			else
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sss,ProcessHandle->-1,PID->%d,ExitStatus->0x%08x", currentProcessId, ExitStatus)))
					log_lvl = LOG_PARAM;
			}
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(ProcessHandle)
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ProcessHandle->0x%08x,PID->%d,ExitStatus->0x%08x", statusCall, ProcessHandle, targetProcessId, ExitStatus)))
					log_lvl = LOG_PARAM;
			}
			else
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sss,ProcessHandle->-1,PID->%d,ExitStatus->0x%08x", statusCall, currentProcessId, ExitStatus)))
					log_lvl = LOG_PARAM;
			}
		}
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwTerminateProcess", parameter);
			break;
				
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwTerminateProcess", L"0,-1,sss,ProcessHandle->ERROR,PID->ERROR,ExitStatus->ERROR");
			break;
				
			default:
				sendLogs(currentProcessId, L"ZwTerminateProcess", L"1,0,sss,ProcessHandle->ERROR,PID->ERROR,ExitStatus->ERROR");
			break;
		}
		if(parameter)
				ExFreePool(parameter);
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs resume thread
//  Parameters :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html
//  Return value :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html
//	Process :
//		logs thread handle and SuspendCount
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, kSuspendCount;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = ((ZWRESUMETHREAD)(oldZwResumeThread))(ThreadHandle, SuspendCount);
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		DbgPrint("call ZwResumeThread\n");
		#endif
		
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(SuspendCount, sizeof(ULONG), 1);
			kSuspendCount = *SuspendCount;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ss,ThreadHandle->ERROR,SuspendCount->ERROR",exceptionCode)))
				sendLogs(currentProcessId, L"ZwResumeThread", parameter);
			else
				sendLogs(currentProcessId, L"ZwResumeThread", L"0,-1,ss,ThreadHandle->ERROR,SuspendCount->ERROR");
			ExFreePool(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,ThreadHandle->0x%08x,SuspendCount->%d", ThreadHandle, kSuspendCount)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ss,ThreadHandle->0x%08x,SuspendCount->%d", statusCall, ThreadHandle, kSuspendCount)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwResumeThread", parameter);
			break;
				
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwResumeThread", L"0,-1,ss,ThreadHandle->ERROR,SuspendCount->ERROR");
			break;
				
			default:
				sendLogs(currentProcessId, L"ZwResumeThread", L"1,0,ss,ThreadHandle->ERROR,SuspendCount->ERROR");
			break;
		}
		if(parameter)
				ExFreePool(parameter);
	}
	return statusCall;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Block driver loading.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566470%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566470%28v=vs.85%29.aspx
//	Process : Avoid any driver to load during malware execution
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwLoadDriver(PUNICODE_STRING DriverServiceName)
{	
	NTSTATUS exceptionCode;
	UNICODE_STRING kDriverServiceName;
	PWCHAR parameter = NULL;
	ULONG currentProcessId;
	
	#ifdef DEBUG
	DbgPrint("call ZwLoadDriver\n");
	#endif	

	parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	__try 
	{
		if(ExGetPreviousMode() != KernelMode)
			ProbeForRead(DriverServiceName, sizeof(UNICODE_STRING), 1);
		kDriverServiceName = *DriverServiceName;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		exceptionCode = GetExceptionCode();
		if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,DriverName->ERROR",exceptionCode)))
			sendLogs(currentProcessId, L"ZwLoadDriver", parameter);
		ExFreePool(parameter);
		return STATUS_UNSUCCESSFUL;
	}
	
	if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,DriverName->%wZ", STATUS_UNSUCCESSFUL, &kDriverServiceName)))
		sendLogs(currentProcessId, L"ZwLoadDriver", parameter);
	else
		sendLogs(currentProcessId, L"ZwLoadDriver", L"0,-1,s,DriverName->ERROR");
	
	return STATUS_UNSUCCESSFUL;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Logs delay execution.
//  Parameters :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html
//  Return value :
//  	See http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html
//	Process :
//		logs delay execution (in ms)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
{
	NTSTATUS exceptionCode;
	ULONG currentProcessId;
	ULONG ms;
	PWCHAR parameter = NULL;
	LARGE_INTEGER kDelayInterval;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();

	if(isProcessMonitoredByPid(currentProcessId))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		DbgPrint("call ZwDelayExecution\n");
		#endif
		
		__try 
		{
			if(ExGetPreviousMode() != KernelMode)
				ProbeForRead(DelayInterval, sizeof(LARGE_INTEGER), 1);
			kDelayInterval = *DelayInterval;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,DelayInterval->ERROR",exceptionCode)))
				sendLogs(currentProcessId, L"ZwDelayExecution", parameter);
			else
				sendLogs(currentProcessId, L"ZwDelayExecution", L"0,-1,s,DelayInterval->ERROR");
			ExFreePool(parameter);
			return ((ZWDELAYEXECUTION)(oldZwDelayExecution))(Alertable, DelayInterval);
		}
		
		ms = (ULONG)(-kDelayInterval.QuadPart / 10000);
		
		if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,DelayInterval->%d", ms)))
			sendLogs(currentProcessId, L"ZwDelayExecution", parameter);
			
		if(parameter)
				ExFreePool(parameter);
	}
	return ((ZWDELAYEXECUTION)(oldZwDelayExecution))(Alertable, DelayInterval);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//	Return value :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PVOID CreateInfo, PVOID AttributeList)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, childProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	HANDLE kProcessHandle, kThreadHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWCREATEUSERPROCESS)(oldZwCreateUserProcess))(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);

	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwCreateUserProcess\n");
		#endif
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try
		{
			if(ExGetPreviousMode() != KernelMode)
			{
				ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
				ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
			}
			kProcessHandle = *ProcessHandle;
			kThreadHandle = *ThreadHandle;
			childProcessId = getPIDByHandle(kProcessHandle);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssssss,ProcessHandle->ERROR,ThreadHandle->ERROR,PID->ERROR,ProcessDesiredAccess->ERROR,ThreadDesiredAccess->ERROR,ImagePathName->ERROR,CommandLine->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateUserProcess", parameter);
			else
				sendLogs(currentProcessId, L"ZwCreateUserProcess", L"0,-1,sssssss,ProcessHandle->ERROR,ThreadHandle->ERROR,PID->ERROR,ProcessDesiredAccess->ERROR,ThreadDesiredAccess->ERROR,ImagePathName->ERROR,CommandLine->ERROR");
			ExFreePool(parameter);
			return statusCall;
		}
		
		if(NT_SUCCESS(statusCall))
		{
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssssss,ProcessHandle->0x%08x,ThreadHandle->0x%08x,PID->%d,ProcessDesiredAccess->0x%08x,ThreadDesiredAccess->0x%08x,ImagePathName->%wZ,CommandLine->%wZ", kProcessHandle, kThreadHandle, childProcessId, ProcessDesiredAccess, ThreadDesiredAccess, &ProcessParameters->ImagePathName, &ProcessParameters->CommandLine)))
				log_lvl = LOG_PARAM;
			if(childProcessId)
				startMonitoringProcess(childProcessId);
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssssss,ProcessHandle->0x%08x,ThreadHandle->0x%08x,PID->%d,ProcessDesiredAccess->0x%08x,ThreadDesiredAccess->0x%08x,ImagePathName->%wZ,CommandLine->%wZ", statusCall, kProcessHandle, kThreadHandle, childProcessId, ProcessDesiredAccess, ThreadDesiredAccess, &ProcessParameters->ImagePathName, &ProcessParameters->CommandLine)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwCreateUserProcess", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateUserProcess", L"0,-1,sssssss,ProcessHandle->ERROR,ThreadHandle->ERROR,PID->ERROR,ProcessDesiredAccess->ERROR,ThreadDesiredAccess->ERROR,ImagePathName->ERROR,CommandLine->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateUserProcess", L"1,0,sssssss,ProcessHandle->ERROR,ThreadHandle->ERROR,PID->ERROR,ProcessDesiredAccess->ERROR,ThreadDesiredAccess->ERROR,ImagePathName->ERROR,CommandLine->ERROR");
			break;
		}
		if(parameter != NULL)
			ExFreePool(parameter);
	}	
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Hide VBOX keys.
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff567069%28v=vs.85%29.aspx
//	Process :
//		if a malware tries to identify VirtualBox by querying the key "Identifier", "SystemBiosVersion" 
//		or "VideoBiosVersion"
//		for "HKLM\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
// 		and "HKLM\\HARDWARE\\Description\\System", we return fake informations
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	NTSTATUS statusCall, status;
	ULONG currentProcessId, len;
	ULONG sizeNeeded = 0;
	PKEY_NAME_INFORMATION nameInfo = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = ((ZWQUERYVALUEKEY)(oldZwQueryValueKey))(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
		
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwQueryValueKey\n");
		#endif
		
		if(NT_SUCCESS(statusCall))
		{
			if(ValueName->Buffer)
			{			
				ZwQueryKey(KeyHandle, KeyNameInformation, NULL, 0, &sizeNeeded);
				nameInfo = ExAllocatePoolWithTag(NonPagedPool, sizeNeeded*sizeof(WCHAR), PROC_POOL_TAG);
				if(!nameInfo)
					return statusCall;
				RtlZeroMemory(nameInfo, sizeNeeded*sizeof(WCHAR));
				status = ZwQueryKey(KeyHandle, KeyNameInformation, nameInfo, sizeNeeded*sizeof(WCHAR), &len);
				if(!NT_SUCCESS(status))
					return statusCall;
									
				if(!_wcsicmp(nameInfo->Name, L"\\REGISTRY\\MACHINE\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"))
				{						   
					if(!_wcsicmp(ValueName->Buffer, L"Identifier"))
					{
						len = wcslen(L"ST38001A");
						if(KeyValueInformation && RtlStringCchPrintfW(((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Name, len, L"ST38001A"))
						{
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Type = 1;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->TitleIndex = 0;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->NameLength = len;
						}
					}
				}
				else if(!_wcsicmp(nameInfo->Name, L"\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\System"))
				{
					if(!_wcsicmp(ValueName->Buffer, L"SystemBiosVersion"))
					{
						len = wcslen(L"DELL   - 15 Phoenix ROM BIOS PLUS Version 1.10 A07");
						if(KeyValueInformation && RtlStringCchPrintfW(((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Name, len, L"DELL   - 15 Phoenix ROM BIOS PLUS Version 1.10 A07"))
						{
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Type = 7;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->TitleIndex = 0;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->NameLength = len;
						}
					}
					else if(!_wcsicmp(ValueName->Buffer, L"VideoBiosVersion"))
					{
						len = wcslen(L"Hardware Version 1.0");
						if(KeyValueInformation && RtlStringCchPrintfW(((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Name, len, L"Hardware Version 1.0"))
						{
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Type = 7;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->TitleIndex = 0;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->NameLength = len;
						}
					}
				}
				
				else if(!_wcsicmp(nameInfo->Name, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\Disk\\Enum") || !_wcsicmp(nameInfo->Name, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"))
				{
					if(!_wcsicmp(ValueName->Buffer, L"0"))
					{
						len = wcslen(L"IDE\\DiskWDC_WD3200AAKX-753CA1___________________17.01H17\\5&3cc78f3&0&0.0.0");
						if(KeyValueInformation && RtlStringCchPrintfW(((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Name, len, L"IDE\\DiskWDC_WD3200AAKX-753CA1___________________17.01H17\\5&3cc78f3&0&0.0.0"))
						{
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->Type = 1;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->TitleIndex = 0;
							((PKEY_VALUE_BASIC_INFORMATION)KeyValueInformation)->NameLength = len;
						}
					}
				}
				
				if(nameInfo)
					ExFreePool(nameInfo);
			}
		}
	}
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Hide VBOX files
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/cc512135%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/cc512135%28v=vs.85%29.aspx
//	Process :
//		if a malware tries to identify VirtualBox by trying to get attributes of vbox files, we return
//		INVALID_FILE_ATTRIBUTES.
//		we only log when there is an attempt to detect VirtualBox
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newZwQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	
	kObjectName.Buffer = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((ZWQUERYATTRIBUTESFILE)(oldZwQueryAttributesFile))(ObjectAttributes, FileInformation);

	if(isProcessMonitoredByPid(currentProcessId))
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		DbgPrint("call ZwQueryAttributesFile\n");
		#endif
		
		if(NT_SUCCESS(statusCall))
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
				if(!kObjectName.Buffer)
				{
					if(parameter)
						ExFreePool(parameter);
					sendLogs(currentProcessId, L"ZwQueryAttributesFile", L"0,-1,s,FileName->ERROR");
					return statusCall;
				}
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,s,FileName->ERROR", exceptionCode)))
					sendLogs(currentProcessId, L"ZwQueryAttributesFile", parameter);
				else 
					sendLogs(currentProcessId, L"ZwQueryAttributesFile", L"0,-1,s,FileName->ERROR");
				if(parameter)
					ExFreePool(parameter);
				if(kObjectName.Buffer)
					ExFreePool(kObjectName.Buffer);
				return statusCall;
			}
			
			if(!_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\drivers\\VBoxMouse.sys") || 
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\drivers\\VBoxGuest.sys") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\drivers\\VBoxSF.sys") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\drivers\\VBoxVideo.sys") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxControl.exe") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxDisp.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxHook.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxMRXNP.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxOGL.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxOGLarrayspu.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxOGLcrutil.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxOGLerrorspu.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxOGLfeedbackspu.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxOGLpackspu.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxOGLpassthroughspu.dll") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxService.exe") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\VBoxTray.exe") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\drivers\\vmmouse.sys") ||
			   !_wcsicmp(kObjectName.Buffer, L"\\??\\C:\\Windows\\system32\\drivers\\vmhgfs.sys"))
			   
			{
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,-1,s,FileName->%ws", kObjectName.Buffer)))
					sendLogs(currentProcessId, L"ZwQueryAttributesFile", parameter);
				else 
					sendLogs(currentProcessId, L"ZwQueryAttributesFile", L"0,-1,s,FileName->ERROR");
				if(parameter)
					ExFreePool(parameter);
				if(kObjectName.Buffer)
					ExFreePool(kObjectName.Buffer);
				return -1; // INVALID_FILE_ATTRIBUTES
			}	
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
		}
		if(parameter)
			ExFreePool(parameter);
	}		
	return statusCall;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Blocks shutdown attempts through ExWindowsEx (on WinXP)
//	Parameters :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallOneParam
//	Return value :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallOneParam
// 	Process :
//		if Routine == 0x34 // PrepareForLogoff , block the call, log it with the parameters
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG newZwUserCallOneParam(ULONG Param, ULONG Routine)
{
	ULONG currentProcessId;
	PWCHAR parameter = NULL;
		
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		if(Routine == 0x34)
		{
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,Param->0x%08x,Routine->0x%08x", Param, Routine)))
				sendLogs(currentProcessId, L"ZwUserCallOneParam", parameter);
			else
				sendLogs(currentProcessId, L"ZwUserCallOneParam", L"1,0,ss,Param->ERROR,Routine->ERROR");				
			if(parameter)
				ExFreePool(parameter);
			cleanMonitoredProcessList();	
			return 0;	
		}
	}
	return ((ZWUSERCALLONEPARAM)(oldZwUserCallOneParam))(Param, Routine);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Blocks shutdown attempts through ExWindowsEx (on Win7)
//	Parameters :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallNoParam
//	Return value :
//		https://www.reactos.org/wiki/Techwiki:Win32k/NtUserCallNoParam
// 	Process :
//		if Routine == 0x10 // PrepareForLogoff , block and log the call
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONG newZwUserCallNoParam(ULONG Routine)
{
	ULONG currentProcessId;
	PWCHAR parameter = NULL;
		
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	if(isProcessMonitoredByPid(currentProcessId))
	{
		#ifdef DEBUG
		DbgPrint("call ZwUserCallNoParam() !\n");
		#endif
		
		if(Routine == 0x10)
		{
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,Routine->16")))
				sendLogs(currentProcessId, L"ZwUserCallNoParam", parameter);
			else
				sendLogs(currentProcessId, L"ZwUserCallNoParam", L"1,0,s,Routine->16");				
			if(parameter)
				ExFreePool(parameter);
			cleanMonitoredProcessList();	
			return 0;	
		}
	}
	return ((ZWUSERCALLNOPARAM)(oldZwUserCallNoParam))(Routine);
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
VOID disable_cr0()
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
VOID enable_cr0()
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
