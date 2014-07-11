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
//		Unsets WP bit of CR0 register (allows writing into SSDT).
//		See http://en.wikipedia.org/wiki/Control_register#CR0
//	Parameters :
//		None
//	Return value :
//		KIRQL : current IRQL value
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
KIRQL WPOFF( )
{
    KIRQL Irql = KeRaiseIrqlToDpcLevel();
    UINT_PTR cr0 = __readcr0();
      
    cr0 &= ~0x10000;
    __writecr0( cr0 );
    _disable();
  
    return Irql;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Sets WP bit of CR0 register.
//	Parameters :
//		None
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID WPON(KIRQL Irql)
{
    UINT_PTR cr0 = __readcr0();
      
    cr0 |= 0x10000;
    _enable();  
    __writecr0( cr0 );
  
    KeLowerIrql( Irql );
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve KeServiceDescriptorTable address
//	Parameters :
//		None
//	Return value :
//		ULONGLONG : The service descriptor table address 
//	Process :
//		Since KeServiceDescriptorTable isn't an exported symbol anymore, we have to retrieve it. 
//		When looking at the disassembly version of nt!KiSystemServiceRepeat, we can see interesting instructions :
//			4c8d15c7202300	lea r10, [nt!KeServiceDescriptorTable (addr)]    => it's the address we are looking for (:
//			4c8d1d00212300	lea r11, [nt!KeServiceDescriptorTableShadow (addr)]
//			f7830001000080  test dword ptr[rbx+100h], 80h
//
//		Furthermore, the LSTAR MSR value (at 0xC0000082) is initialized with nt!KiSystemCall64, which is a function 
//		close to nt!KiSystemServiceRepeat. We will begin to search from this address, the opcodes 0x83f7, the ones 
//		after the two lea instructions, once we get here, we can finally retrieve the KeServiceDescriptorTable address 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
ULONGLONG GetKeServiceDescriptorTable64()
{
    PUCHAR      pStartSearchAddress   = (PUCHAR)__readmsr(0xC0000082);
    PUCHAR      pEndSearchAddress     = (PUCHAR)( ((ULONG_PTR)pStartSearchAddress + PAGE_SIZE) & (~0x0FFF) );
    PULONG      pFindCodeAddress      = NULL;
    ULONG_PTR   pKeServiceDescriptorTable;
  
    while ( ++pStartSearchAddress < pEndSearchAddress )
    {
        if ( (*(PULONG)pStartSearchAddress & 0xFFFFFF00) == 0x83f70000 )
        {
            pFindCodeAddress = (PULONG)(pStartSearchAddress - 12);
			return (ULONG_PTR)pFindCodeAddress + (((*(PULONG)pFindCodeAddress)>>24)+7) + (ULONG_PTR)(((*(PULONG)(pFindCodeAddress+1))&0x0FFFF)<<8); 
		}
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve the Nt* address function given its syscall number in the SSDT
//	Parameters :
//		PULONG KiServiceTable : the SSDT base address
//		ULONG  ServiceId 	  : a syscall number
//	Return value :
//		ULONGLONG : the address of the function which has the syscall number given in argument
//	Process :
//		Because the addresses contained in the SSDT have the last four bits reserved to store the number of arguments,
//		in order to retrieve only the address, we shift four bits to the right
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONGLONG GetNTAddressFromSSDT( PULONG KiServiceTable, ULONG ServiceId )
{
    return (LONGLONG)( KiServiceTable[ServiceId] >> 4 ) 
            + (ULONGLONG)KiServiceTable;
}
  
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve index of the Nt* function (given in parameter) in the SSDT
//	Parameters :
//		PULONG KiServiceTable : the SSDT address
//		PVOID FuncAddress 	  : a Nt* function address
//	Return value :
//		ULONG : the address which stores the Nt* function address (FuncAddress) in the SSDT
//	Process :
//		same as GetNtAddressFromSSDT() but in revert order
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
ULONG GetSSDTEntry(PULONG KiServiceTable, PVOID FuncAddress)
{
    return ((ULONG)((ULONGLONG)FuncAddress-(ULONGLONG)KiServiceTable)) << 4;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve 12 bytes of free space in order to use that space as trampoline 
//	Parameters :
//		PUCHAR pStartSearchAddress : address where we will begin to search for 12 bytes of code cave
//	Return value :
//		PVOID : address of the code cave found
//	Process :
//		Search for 12 successive bytes at 0x00 from the address given in argument and returns the address found
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID searchCodeCave(PUCHAR pStartSearchAddress)
{
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "pStartSearchAddress : %llx\n", pStartSearchAddress));
	#endif
	
	while(pStartSearchAddress++)
	{		
		if(MmIsAddressValid(pStartSearchAddress))
		{
			if(*(PULONG)pStartSearchAddress == 0x00000000 && *(PULONG)(pStartSearchAddress+4) == 0x00000000 && *(PULONG)(pStartSearchAddress+8) == 0x00000000)
				return pStartSearchAddress-1;	
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Retrieve kernel base address
//	Parameters :
//		None
//	Return value :
//		PVOID : the kernel base address
//	Process :
//		Retrieve the ntoskrnl module and returns its base address
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////   
PVOID getKernelBase()
{
	UNICODE_STRING funcAddr;
	ULONG ulNeededSize = 0, ModuleCount;
	PVOID pBuffer;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;
	PSYSTEM_MODULE pSystemModule = NULL;
	PVOID imgBaseAddr;
	
	ZwQuerySystemInformation(SystemModuleInformation, &ulNeededSize, 0, &ulNeededSize);
	if(ulNeededSize)
	{
		pBuffer = ExAllocatePoolWithTag(NonPagedPool, ulNeededSize, 'klmP');
		if(NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, pBuffer, ulNeededSize, &ulNeededSize)))
		{
			pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
			pSystemModule = &pSystemModuleInformation->Modules[0];
			imgBaseAddr = pSystemModule->Base;
			return imgBaseAddr;
		}
		else
			KdPrintEx((DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "ZwQuerySystemInformation failed !\n"));
	}
	else
		KdPrintEx((DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "ZwQuerySystemInformation failed !\n"));
	return 0;
}
 
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Overwrite an entry of the SSDT by our trampoline (which jumps to our hooked Nt* function)
//	Parameters :
//		PVOID NewFunc    : Pointer to our hooked Nt* function
//		PVOID *OldFunc   : Pointer to which will point to the original Nt* function
//		LONG  ServiceId  : Syscall number of the function
//		PVOID searchAddr : Pointer to an address where we will begin to search for code cave
//		PVOID searchAddr : Pointer to an address where we will begin to search for code cave
//		PULONG KiServiceTable : Pointer to the SSDT
//	Return value :
//		PVOID : Returns a new base address which will be use to search for code cave
//	Process :
//		We want to overwrite an entry of the SSDT to our hooked function, but we can't do it directly because
//		the entries in the SSDT are not real address of the Nt* functions (see GetNTAddressFromSSDT() comments).
//		We will use the free space at the end of the .text section of the kernel as a trampoline. 
//		We can't directly write our trampoline in that space because it's not a writeable section, and we can't use
//		NtProtectVirtualMemory() because it only works in user-land. The trick (thx Ivanlef0u ;) is to create a 
//		Memory Descriptor List (MDL) with the new rights (RWX) pointing to the virtual address of the code cave space.
//		We can now write our trampoline (mov rax, @new func; jmp rax) and overwrite SSDT entry by the address of the 
//		trampoline.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
PVOID install_hook(PVOID NewFunc, PVOID* OldFunc, LONG ServiceId, PVOID searchAddr, PULONG KiServiceTable)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UCHAR jmp_to_newFunction[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0"; //mov rax, xxx ; jmp rax
	KIRQL Irql;
    ULONG SsdtEntry;
	PVOID trampoline;
	PMDL mdl;
	PVOID memAddr;

	*OldFunc = (PVOID)GetNTAddressFromSSDT(KiServiceTable, ServiceId); 
		
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "OldFunc : %llx\n", *OldFunc));	
	#endif
	
	// mov rax, @NewFunc; jmp rax
	*(PULONGLONG)(jmp_to_newFunction+2) = (ULONGLONG)NewFunc;
	trampoline = searchCodeCave(searchAddr);
	
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "trampoline : %llx\n", trampoline));
	#endif
	
	mdl = IoAllocateMdl(trampoline, 12, FALSE, FALSE, NULL);
	if(mdl == NULL)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "IoAllocateMdl failed !!\n"));
		#endif
	}
	MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess); 
	memAddr = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	if(memAddr == NULL)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "MmMapLockedPagesSpecifyCache failed !!\n"));	
		#endif
	}
	Irql = WPOFF();
	RtlMoveMemory(memAddr, jmp_to_newFunction, 12); 

	SsdtEntry = GetSSDTEntry(KiServiceTable, trampoline);
	SsdtEntry &= 0xFFFFFFF0;
	SsdtEntry += KiServiceTable[ServiceId] & 0x0F;		
	KiServiceTable[ServiceId] = SsdtEntry;   
	
	WPON( Irql );
	
	return (PVOID)((ULONG_PTR)trampoline+12);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve end address of the .text section of the module given in argument
//	Parameters :
//		PVOID moduleBase : base address of a module
//	Return value :
//		Returns end address of .text section of moduleBase
//	Process :
//		Parse module base PE header to get the number of sections and to retrieve section header address,
//		then parse each section and when we get to the .text section, returns address of the end of the section
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID getEndOfTextSection(PVOID moduleBase)
{
	USHORT NumberOfSections;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS64 pNtHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	ULONG i;
	PVOID begin_text, end_text;
	
	pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
	pNtHeader = (PIMAGE_NT_HEADERS)((unsigned char*)moduleBase+pDosHeader->e_lfanew);
	
	NumberOfSections = pNtHeader->FileHeader.NumberOfSections;
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "Number of Sections: %d\n", NumberOfSections));
	#endif

	pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char*)pNtHeader+sizeof(IMAGE_NT_HEADERS64));
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "section header : %llx \n", pSectionHeader));
	#endif
	
	// parse each section in order to get to the executable section 
	for(i=0; i<NumberOfSections; i++)
	{
		// this is the .text section
		if(pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			begin_text = (PVOID)(pSectionHeader->VirtualAddress + (ULONG_PTR)moduleBase);
			end_text = (PVOID)((ULONG_PTR)begin_text + pSectionHeader->Misc.VirtualSize);
			#ifdef DEBUG
			KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "%s section is located at : %llx \n", pSectionHeader->Name, begin_text));
			KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "end of %s section at : %llx \n", pSectionHeader->Name, end_text));
			#endif
			break;
		}
		pSectionHeader++;
	}
	return end_text;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Restore SSDT
//	Parameters :
//		PVOID func : address of original Nt* function
//		ULONG ServiceId : func syscall number
//	Return value :
//		None
//	Process :
//		restore SSDT by overwriting SSDT entries which were altered by the original ones
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID unhook(PVOID func, ULONG ServiceId)
{
	KIRQL Irql;
	ULONG SsdtEntry;
	PULONG KiServiceTable;
	Irql = WPOFF();
	
	KiServiceTable = KeServiceDescriptorTable->ServiceTableBase;
	SsdtEntry = GetSSDTEntry(KiServiceTable, func);
	
	SsdtEntry &= 0xFFFFFFF0;
	SsdtEntry += KiServiceTable[ServiceId] & 0x0F;
	KiServiceTable[ServiceId] = SsdtEntry;   
	WPON(Irql);
} 

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Restore SSDT
//	Parameters :
//		None
//	Return value :
//		None
//	Process :
//		restore SSDT
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID remove_hooks()
{
	unhook(oldNtSetContextThread, SETCONTEXTTHREAD_INDEX);
	unhook(oldNtDebugActiveProcess, DEBUGACTIVEPROCESS_INDEX);
	unhook(oldNtOpenProcess, OPENPROCESS_INDEX);
	unhook(oldNtOpenThread, OPENTHREAD_INDEX);
	unhook(oldNtQuerySystemInformation, QUERYSYSTEMINFORMATION_INDEX);
	unhook(oldNtDeleteFile, DELETEFILE_INDEX);
	unhook(oldNtCreateMutant, CREATEMUTANT_INDEX);
	unhook(oldNtTerminateProcess, TERMINATEPROCESS_INDEX);
	unhook(oldNtDelayExecution, DELAYEXECUTION_INDEX);
	unhook(oldNtQueryAttributesFile, QUERYATTRIBUTESFILE_INDEX);
	unhook(oldNtResumeThread, RESUMETHREAD_INDEX);
	unhook(oldNtLoadDriver, LOADDRIVER_INDEX);
	unhook(oldNtClose, CLOSE_INDEX);
	unhook(oldNtCreateUserProcess, CREATEUSERPROCESS_INDEX);
	unhook(oldNtCreateFile, CREATEFILE_INDEX);
	unhook(oldNtReadFile, READFILE_INDEX);
	unhook(oldNtWriteFile, WRITEFILE_INDEX);
	unhook(oldNtReadVirtualMemory, READVIRTUALMEMORY_INDEX);
	unhook(oldNtWriteVirtualMemory, WRITEVIRTUALMEMORY_INDEX);
	unhook(oldNtSetInformationFile, SETINFORMATIONFILE_INDEX);
	unhook(oldNtQueryInformationFile, QUERYINFORMATIONFILE_INDEX);
	unhook(oldNtDeviceIoControlFile, DEVICEIOCONTROLFILE_INDEX);
	unhook(oldNtQueryValueKey, QUERYVALUEKEY_INDEX);
	unhook(oldNtCreateSection, CREATESECTION_INDEX);
	unhook(oldNtOpenFile, OPENFILE_INDEX);
	unhook(oldNtQueueApcThread, QUEUEAPCTHREAD_INDEX);
	unhook(oldNtSystemDebugControl, SYSTEMDEBUGCONTROL_INDEX);
	unhook(oldNtMapViewOfSection, MAPVIEWOFSECTION_INDEX);
	unhook(oldNtCreateProcess, CREATEPROCESS_INDEX);
	unhook(oldNtCreateProcessEx, CREATEPROCESSEX_INDEX);
	unhook(oldNtCreateThread, CREATETHREAD_INDEX);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		install SSDT hooks
//	Parameters :
//		None
//	Return value :
//		None
//	Process :
//		Retrieve SSDT address, end of ntoskrnl .text section and hook SSDT table
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID hook_ssdt()
{
	PULONG KiServiceTable;
	PVOID pStartSearchAddress;
	PVOID kernelBase;
	
	KeServiceDescriptorTable = (pServiceDescriptorTableEntry)GetKeServiceDescriptorTable64();
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "KeServiceDescriptorTable : %llx\n", KeServiceDescriptorTable));	
	#endif
	
	KiServiceTable = KeServiceDescriptorTable->ServiceTableBase;
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "KiServiceTable : %llx\n", KiServiceTable));	
	#endif
	
	kernelBase = getKernelBase();
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "KernelBaseAddr : %llx\n", kernelBase));	
	#endif
	
	pStartSearchAddress = getEndOfTextSection(kernelBase);
	
	pStartSearchAddress = install_hook((PVOID)newNtSetContextThread, (PVOID*)&oldNtSetContextThread, SETCONTEXTTHREAD_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtDebugActiveProcess, (PVOID*)&oldNtDebugActiveProcess, DEBUGACTIVEPROCESS_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtOpenProcess, (PVOID*)&oldNtOpenProcess, OPENPROCESS_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtOpenThread, (PVOID*)&oldNtOpenThread, OPENTHREAD_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtQuerySystemInformation, (PVOID*)&oldNtQuerySystemInformation, QUERYSYSTEMINFORMATION_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtDeleteFile, (PVOID*)&oldNtDeleteFile, DELETEFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtCreateMutant, (PVOID*)&oldNtCreateMutant, CREATEMUTANT_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtTerminateProcess, (PVOID*)&oldNtTerminateProcess, TERMINATEPROCESS_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtDelayExecution, (PVOID*)&oldNtDelayExecution, DELAYEXECUTION_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtQueryAttributesFile, (PVOID*)&oldNtQueryAttributesFile, QUERYATTRIBUTESFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtResumeThread, (PVOID*)&oldNtResumeThread, RESUMETHREAD_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtLoadDriver, (PVOID*)&oldNtLoadDriver, LOADDRIVER_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtClose, (PVOID*)&oldNtClose, CLOSE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtCreateUserProcess, (PVOID*)&oldNtCreateUserProcess, CREATEUSERPROCESS_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtCreateFile, (PVOID*)&oldNtCreateFile, CREATEFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtReadFile, (PVOID*)&oldNtReadFile, READFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtWriteFile, (PVOID*)&oldNtWriteFile, WRITEFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtReadVirtualMemory, (PVOID*)&oldNtReadVirtualMemory, READVIRTUALMEMORY_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtWriteVirtualMemory, (PVOID*)&oldNtWriteVirtualMemory, WRITEVIRTUALMEMORY_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtSetInformationFile, (PVOID*)&oldNtSetInformationFile, SETINFORMATIONFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtQueryInformationFile, (PVOID*)&oldNtQueryInformationFile, QUERYINFORMATIONFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtDeviceIoControlFile, (PVOID*)&oldNtDeviceIoControlFile, DEVICEIOCONTROLFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtQueryValueKey, (PVOID*)&oldNtQueryValueKey, QUERYVALUEKEY_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtCreateSection, (PVOID*)&oldNtCreateSection, CREATESECTION_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtOpenFile, (PVOID*)&oldNtOpenFile, OPENFILE_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtQueueApcThread, (PVOID*)&oldNtQueueApcThread, QUEUEAPCTHREAD_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtSystemDebugControl, (PVOID*)&oldNtSystemDebugControl, SYSTEMDEBUGCONTROL_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtMapViewOfSection, (PVOID*)&oldNtMapViewOfSection, MAPVIEWOFSECTION_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtCreateProcess, (PVOID*)&oldNtCreateProcess, CREATEPROCESS_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtCreateProcessEx, (PVOID*)&oldNtCreateProcessEx, CREATEPROCESSEX_INDEX, pStartSearchAddress, KiServiceTable);
	pStartSearchAddress = install_hook((PVOID)newNtCreateThread, (PVOID*)&oldNtCreateThread, CREATETHREAD_INDEX, pStartSearchAddress, KiServiceTable);
	
	// doesn't work yet...
	//pStartSearchAddress = install_hook((PVOID)newNtCreateThreadEx, (PVOID*)&oldNtCreateThreadEx, CREATETHREADEX_INDEX, pStartSearchAddress, KiServiceTable);

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
NTSTATUS newNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
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
	statusCall = ((NTOPENTHREAD)(oldNtOpenThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ClientID);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call NtOpenThread\n"));
		#endif
	
		if(NT_SUCCESS(statusCall))
		{
			__try 
			{
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
					ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
					ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
					ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
					
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
NTSTATUS newNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID)
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
	statusCall = ((NTOPENPROCESS)(oldNtOpenProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ClientID);
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{   	
	
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwOpenProcess\n"));
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		targetProcessName.Length = 0;
		targetProcessName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
		targetProcessName.Buffer = ExAllocatePoolWithTag(NonPagedPool, targetProcessName.MaximumLength, PROCNAME_TAG);
		
		if(NT_SUCCESS(statusCall))
		{
			__try 
			{
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
					ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
					ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
					ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
					
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
NTSTATUS newNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetThreadId, i;
	USHORT log_lvl = LOG_ERROR;
	PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = NULL, pPrev = NULL;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = ((NTQUERYSYSTEMINFORMATION)(oldNtQuerySystemInformation))(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwQuerySystemInformation\n"));
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
NTSTATUS newNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetProcessId;
	ULONG log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTREADVIRTUALMEMORY)(oldNtReadVirtualMemory))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwReadVirtualMemory\n"));
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
NTSTATUS newNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetProcessId;
	ULONG log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTWRITEVIRTUALMEMORY)(oldNtWriteVirtualMemory))(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwWriteVirtualMemory\n"));
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
NTSTATUS newNtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugHandle)
{
	NTSTATUS statusCall;
	ULONG targetProcessId, currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTDEBUGACTIVEPROCESS)(oldNtDebugActiveProcess))(ProcessHandle, DebugHandle);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{		
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwDebugActiveProcess\n"));
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
NTSTATUS newNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
	NTSTATUS statusCall;
	ULONG currentProcessId;
	POBJECT_NAME_INFORMATION filename;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTCREATESECTION)(oldNtCreateSection))(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{		
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateSection\n"));
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
NTSTATUS newNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, childProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	HANDLE kProcessHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTCREATEPROCESS)(oldNtCreateProcess))(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateProcess\n"));
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try 
		{
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
NTSTATUS newNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE InheritFromProcessHandle, BOOLEAN InheritHandles, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, HANDLE dunno)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, childProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	HANDLE kProcessHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTCREATEPROCESSEX)(oldNtCreateProcessEx))(ProcessHandle, DesiredAccess, ObjectAttributes, InheritFromProcessHandle, InheritHandles, SectionHandle, DebugPort, ExceptionPort, dunno);	 
		
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateProcessEx\n"));
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try 
		{
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
NTSTATUS newNtQueueApcThread(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetThreadId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTQUEUEAPCTHREAD)(oldNtQueueApcThread))(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwQueueApcThread\n"));
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
NTSTATUS newNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientID, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId, createdThreadId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	HANDLE kThreadHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	targetProcessId = getPIDByHandle(ProcessHandle);	// faster than placing it after the monitored process check
	statusCall = ((NTCREATETHREAD)(oldNtCreateThread))(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, ThreadContext, InitialTeb, CreateSuspended);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateThread\n"));
		#endif
		
		if(NT_SUCCESS(statusCall) && targetProcessId)
			startMonitoringProcess(targetProcessId);	// <-- RACE CONDITION
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		_try
		{
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
NTSTATUS newNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartAddress, PVOID Parameter, BOOLEAN CreateSuspended, ULONG StackZeroBits, ULONG SizeOfStackCommit, ULONG SizeOfStackReserve, PVOID BytesBuffer)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, targetProcessId, createdThreadId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	HANDLE kThreadHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	targetProcessId = getPIDByHandle(ProcessHandle);	// faster than placing it after the monitored process check
	statusCall = ((NTCREATETHREADEX)(oldNtCreateThreadEx))(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartAddress, Parameter, CreateSuspended, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, BytesBuffer);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateThreadEx\n"));
		#endif
		
		if(NT_SUCCESS(statusCall) && targetProcessId)
			startMonitoringProcess(targetProcessId);	// <-- RACE CONDITION
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		_try
		{
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
NTSTATUS newNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	NTSTATUS statusCall;
	ULONG targetProcessId, currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTMAPVIEWOFSECTION)(oldNtMapViewOfSection))(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{		
		targetProcessId = getPIDByHandle(ProcessHandle);
		
		if(currentProcessId != targetProcessId)
		{
			#ifdef DEBUG
			KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwMapViewOfSection\n"));
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
NTSTATUS newNtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetThreadId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTSETCONTEXTTHREAD)(oldNtSetContextThread))(ThreadHandle, Context);
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwSetContextThread\n"));
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
NTSTATUS newNtSystemDebugControl(SYSDBG_COMMAND Command, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength)
{
	NTSTATUS statusCall;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTSYSTEMDEBUGCONTROL)(oldNtSystemDebugControl))(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ReturnLength);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwSystemDebugControl\n"));
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
//		Logs file opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/bb432381(v=vs.85).aspx
//  Return value :
//		See http://msdn.microsoft.com/en-us/library/bb432381(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
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

	statusCall = ((NTOPENFILE)(oldNtOpenFile))(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwOpenFile\n"));
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		kObjectName.Buffer = NULL;
		
		__try
		{

			ProbeForRead(FileHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		
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
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,sssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,ShareAccess->ERROR,OpenOptions->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwOpenFile", parameter);
			else 
				sendLogs(currentProcessId ,L"ZwOpenFile", L"0,-1,sssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,ShareAccess->ERROR,OpenOptions->ERROR");
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
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,sssss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x,ShareAccess->%d,OpenOptions->%d", kFileHandle,&full_path, DesiredAccess, ShareAccess, OpenOptions)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,sssss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x,ShareAccess->%d,OpenOptions->%d", statusCall, kFileHandle, &full_path, DesiredAccess, ShareAccess, OpenOptions)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwOpenFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwOpenFile", L"0,-1,sssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,ShareAccess->ERROR,OpenOptions->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwOpenFile", L"1,0,sssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,ShareAccess->ERROR,OpenOptions->ERROR");
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
//		Logs file creation and/or file opening.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566424(v=vs.85).aspx
//	Process :
//		Copies arguments, handles the non-NULL ObjectAttributes->RootDirectory parameter case (concat.
//		of RootDirectory and ObjectName) then log.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, returnLength;
	USHORT log_lvl = LOG_ERROR;
	UNICODE_STRING full_path;
	PWCHAR parameter = NULL;
	BOOLEAN handle_to_add;
	POBJECT_NAME_INFORMATION nameInformation = NULL;

	HANDLE kRootDirectory, kFileHandle;
	UNICODE_STRING kObjectName;
	
	full_path.Buffer = NULL;
	kObjectName.Buffer = NULL;
	
	handle_to_add = FALSE;
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	if((CreateOptions & FILE_DELETE_ON_CLOSE) && (DesiredAccess & DELETE))
	{
		CreateOptions -= FILE_DELETE_ON_CLOSE;
		DesiredAccess -= DELETE;
		if(DesiredAccess == 0)
			DesiredAccess = 1;
		handle_to_add = TRUE;
	}
	
	statusCall = ((NTCREATEFILE)(oldNtCreateFile))(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateFile\n"));
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		kObjectName.Buffer = NULL;
		
		__try
		{

			ProbeForRead(FileHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		
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
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR,Status->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwCreateFile", parameter);
			else 
				sendLogs(currentProcessId ,L"ZwCreateFile", L"0,-1,ssssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR,Status->ERROR");
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
		// if CreateOptions == FILE_DELETE_ON_CLOSE && DesiredAccess == DELETE), add the handle to the linked list and remove the flags
		if(handle_to_add)
			addHandleInMonitoredList(kFileHandle);
			
			log_lvl = LOG_SUCCESS;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ssssssss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x,CreateDisposition->%d,CreateOptions->%d,FileAttributes->%d,ShareAccess->%d,Status->%d", kFileHandle,&full_path, DesiredAccess, CreateDisposition, CreateOptions, FileAttributes, ShareAccess, IoStatusBlock->Information)))
				log_lvl = LOG_PARAM;
		}
		else
		{
			log_lvl = LOG_ERROR;
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE,  L"0,%d,ssssssss,FileHandle->0x%08x,FileName->%wZ,DesiredAccess->0x%08x,CreateDisposition->%d,CreateOptions->%d,FileAttributes->%d,ShareAccess->%d,Status->%d", statusCall, kFileHandle, &full_path, DesiredAccess, CreateDisposition, CreateOptions, FileAttributes, ShareAccess, IoStatusBlock->Information)))
				log_lvl = LOG_PARAM;
		}
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwCreateFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwCreateFile", L"0,-1,ssssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR,Status->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwCreateFile", L"1,0,ssssssss,FileHandle->ERROR,FileName->ERROR,DesiredAccess->ERROR,CreateDisposition->ERROR,CreateOptions->ERROR,FileAttributes->ERROR,ShareAccess->ERROR,Status->ERROR");
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
NTSTATUS newNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, returnLength;
	USHORT log_lvl = LOG_ERROR;
	POBJECT_NAME_INFORMATION nameInformation = NULL;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTREADFILE)(oldNtReadFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwReadFile\n"));
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
NTSTATUS newNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, returnLength;
	USHORT log_lvl = LOG_ERROR;
	POBJECT_NAME_INFORMATION nameInformation = NULL;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTWRITEFILE)(oldNtWriteFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwWriteFile\n"));
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	UNICODE_STRING kObjectName;
	UNICODE_STRING file_to_dump;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwDeleteFile\n"));
		#endif
		
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		__try
		{
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);
		
			kObjectName.Length = ObjectAttributes->ObjectName->Length;
			kObjectName.MaximumLength = ObjectAttributes->ObjectName->Length;
			kObjectName.Buffer = ExAllocatePoolWithTag(NonPagedPool, kObjectName.MaximumLength, BUFFER_TAG);
			
			if(kObjectName.Buffer)
				RtlCopyUnicodeString(&kObjectName, ObjectAttributes->ObjectName);
			else
			{
				sendLogs(currentProcessId ,L"ZwDeleteFile", L"0,-1,ss,FileName->ERROR,FileToDump->ERROR");
				if(parameter)
					ExFreePool(parameter);
				return ((NTDELETEFILE)(oldNtDeleteFile))(ObjectAttributes);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			exceptionCode = GetExceptionCode();
			if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ss,FileName->ERROR,FileToDump->ERROR", exceptionCode)))
				sendLogs(currentProcessId, L"ZwDeleteFile", parameter);
			else 
				sendLogs(currentProcessId ,L"ZwDeleteFile", L"0,-1,ss,FileName->ERROR,FileToDump->ERROR");
			if(parameter)
				ExFreePool(parameter);
			if(kObjectName.Buffer)
				ExFreePool(kObjectName.Buffer);
			return ((NTDELETEFILE)(oldNtDeleteFile))(ObjectAttributes);
		}
		
		// dump file
		// we need to move the file straight away (:
		if(kObjectName.Buffer)
		{
			// move the file which is about to be deleted to cuckoo directory
			file_to_dump.Length = 0;
			file_to_dump.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
			file_to_dump.Buffer = ExAllocatePoolWithTag(NonPagedPool, file_to_dump.MaximumLength, 'jKsA');
			if(!NT_SUCCESS(dump_file(kObjectName, &file_to_dump)))
				RtlInitUnicodeString(&file_to_dump, L"ERROR");
		}
		
		log_lvl = LOG_SUCCESS;
		if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,ss,FileName->%wZ,FileToDump->%wZ", &kObjectName, &file_to_dump)))
			log_lvl = LOG_PARAM;
		
		switch(log_lvl)
		{
			case LOG_PARAM:
				sendLogs(currentProcessId, L"ZwDeleteFile", parameter);
			break;
			case LOG_SUCCESS:
				sendLogs(currentProcessId, L"ZwDeleteFile", L"0,-1,ss,FileName->ERROR,FileToDump->ERROR");
			break;
			default:
				sendLogs(currentProcessId, L"ZwDeleteFile", L"1,0,ss,FileName->ERROR,FileToDump->ERROR");
			break;
		}
		if(kObjectName.Buffer)
			ExFreePool(kObjectName.Buffer);
		if(parameter)
			ExFreePool(parameter);
			
		return STATUS_SUCCESS;
	}
	return ((NTDELETEFILE)(oldNtDeleteFile))(ObjectAttributes);
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
NTSTATUS newNtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	UNICODE_STRING full_path;
	UNICODE_STRING file_to_dump;
	POBJECT_NAME_INFORMATION originalNameInformation = NULL;
	PWCHAR parameter = NULL;
	
	BOOLEAN kDeleteFile;
	IO_STATUS_BLOCK iosb;
	ULONG kFileNameLength;
	PFILE_RENAME_INFORMATION kFileRenameInformation = NULL;
	PWCHAR kFileName = NULL;
	HANDLE kRootDirectory = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();

	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwSetInformationFile\n"));
		#endif
	
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		// CHANGE FILE DISPOSITION INFORMATION CASE
		if(FileInformationClass == FileDispositionInformation)
		{
			__try 
			{
				ProbeForRead(FileInformation, sizeof(FILE_DISPOSITION_INFORMATION), 1);
				kDeleteFile = ((PFILE_DISPOSITION_INFORMATION)FileInformation)->DeleteFile;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				exceptionCode = GetExceptionCode();
				if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"0,%d,ssss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR,FileToDump->ERROR", exceptionCode)))
					sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", parameter);
				else
					sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", L"0,-1,ssss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR,FileToDump->ERROR");
				if(parameter)
					ExFreePool(parameter);
				return ((NTSETINFORMATIONFILE)(oldNtSetInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
			}
			
			if(kDeleteFile == TRUE)
			{
				originalNameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
				if(originalNameInformation && parameter)
					ZwQueryObject(FileHandle, ObjectNameInformation, originalNameInformation, MAXSIZE, NULL);
				
				// we need to move the file straight away (:
				if(originalNameInformation->Name.Buffer)
				{			
					// move the file which is about to be deleted to cuckoo directory
					ZwClose(FileHandle);
					file_to_dump.Length = 0;
					file_to_dump.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
					file_to_dump.Buffer = ExAllocatePoolWithTag(NonPagedPool, file_to_dump.MaximumLength, 'jKlA');
					if(!NT_SUCCESS(dump_file(originalNameInformation->Name, &file_to_dump)))
					RtlInitUnicodeString(&file_to_dump, L"ERROR");
				}
				
				log_lvl = LOG_SUCCESS;
				if(parameter && originalNameInformation && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,ssss,FileHandle->0x%08x,FileName->%wZ,FileInformationClass->%d,FileToDump->%wZ", STATUS_SUCCESS, FileHandle, &(originalNameInformation->Name), FileInformationClass, &file_to_dump)))
					log_lvl = LOG_PARAM;
				
				switch(log_lvl)
				{
					case LOG_PARAM:
						sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", parameter);
					break;
					case LOG_SUCCESS:
						sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", L"1,0,ssss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR,FileToDump->ERROR");
					break;
					default:
						sendLogs(currentProcessId, L"ZwSetInformationFile (Delete)", L"0,0,ssss,FileHandle->ERROR,FileName->ERROR,FileInformationClass->ERROR,FileToDump->ERROR");
					break;
				}
				if(originalNameInformation)
					ExFreePool(originalNameInformation);
				if(parameter)
					ExFreePool(parameter);
					
				// returns SUCCESS to trick the malware
				return STATUS_SUCCESS;
			}
			else
				return ((NTSETINFORMATIONFILE)(oldNtSetInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
		}
		
		statusCall = ((NTSETINFORMATIONFILE)(oldNtSetInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
		
		// RENAME FILE CASE
		if(FileInformationClass == FileRenameInformation)
		{
			__try 
			{
				ProbeForRead(FileInformation, sizeof(FILE_RENAME_INFORMATION), 1);
				ProbeForRead(((PFILE_RENAME_INFORMATION)FileInformation)->FileName, ((PFILE_RENAME_INFORMATION)FileInformation)->FileNameLength, 1);
				
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
				ZwQueryObject(FileHandle, ObjectNameInformation, originalNameInformation, MAXSIZE, NULL);
			
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
		return statusCall;	
	}
	else
		return ((NTSETINFORMATIONFILE)(oldNtSetInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
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
NTSTATUS newNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTQUERYINFORMATIONFILE)(oldNtQueryInformationFile))(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwQueryInformationFile\n"));
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
NTSTATUS newNtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	HANDLE kMutantHandle;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	kObjectName.Buffer = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTCREATEMUTANT)(oldNtCreateMutant))(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{	
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateMutant\n"));
		#endif
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try
		{
			ProbeForRead(MutantHandle, sizeof(HANDLE), 1);
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
			ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
			ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);

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
NTSTATUS newNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OuputBuffer, ULONG OutputBufferLength)
{
	NTSTATUS statusCall;
	ULONG currentProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTDEVICEIOCONTROLFILE)(oldNtDeviceIoControlFile))(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OuputBuffer, OutputBufferLength);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwDeviceIoControlFile\n"));
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
NTSTATUS newNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	NTSTATUS statusCall;
	ULONG currentProcessId, targetProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	targetProcessId = getPIDByHandle(ProcessHandle);
	
	statusCall = ((NTTERMINATEPROCESS)(oldNtTerminateProcess))(ProcessHandle, ExitStatus);
	
	if((isProcessMonitoredByPid(currentProcessId) || isProcessMonitoredByPid(targetProcessId)) && ExGetPreviousMode() != KernelMode)
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwTerminateProcess\n"));
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
NTSTATUS newNtResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, kSuspendCount;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = ((NTRESUMETHREAD)(oldNtResumeThread))(ThreadHandle, SuspendCount);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwResumeThread\n"));
		#endif
		
		__try 
		{
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
NTSTATUS newNtLoadDriver(PUNICODE_STRING DriverServiceName)
{	
	NTSTATUS exceptionCode;
	UNICODE_STRING kDriverServiceName;
	PWCHAR parameter = NULL;
	ULONG currentProcessId;
	
	#ifdef DEBUG
	KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwLoadDriver\n"));
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
NTSTATUS newNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
{
	NTSTATUS exceptionCode;
	ULONG currentProcessId;
	ULONG ms;
	PWCHAR parameter = NULL;
	LARGE_INTEGER kDelayInterval;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();

	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
	
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwDelayExecution\n"));
		#endif
		
		__try 
		{
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
			return ((NTDELAYEXECUTION)(oldNtDelayExecution))(Alertable, DelayInterval);
		}
		
		ms = (ULONG)(-kDelayInterval.QuadPart / 10000);
		
		if(parameter && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,0,s,DelayInterval->%d", ms)))
			sendLogs(currentProcessId, L"ZwDelayExecution", parameter);
			
		if(parameter)
				ExFreePool(parameter);
	}
	
	return ((NTDELAYEXECUTION)(oldNtDelayExecution))(Alertable, DelayInterval);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Logs process creation.
//	Parameters :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//	Return value :
//		See http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/ (lulz)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PVOID CreateInfo, PVOID AttributeList)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId, childProcessId;
	USHORT log_lvl = LOG_ERROR;
	PWCHAR parameter = NULL;
	HANDLE kProcessHandle, kThreadHandle;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTCREATEUSERPROCESS)(oldNtCreateUserProcess))(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwCreateUserProcess\n"));
		#endif
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		__try
		{
			ProbeForRead(ProcessHandle, sizeof(HANDLE), 1);
			ProbeForRead(ThreadHandle, sizeof(HANDLE), 1);
			
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
NTSTATUS newNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	NTSTATUS statusCall, status;
	ULONG currentProcessId, len;
	ULONG sizeNeeded = 0;
	PKEY_NAME_INFORMATION nameInfo = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	statusCall = ((NTQUERYVALUEKEY)(oldNtQueryValueKey))(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
		
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwQueryValueKey\n"));
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
NTSTATUS newNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileInformation)
{
	NTSTATUS statusCall, exceptionCode;
	ULONG currentProcessId;
	PWCHAR parameter = NULL;
	UNICODE_STRING kObjectName;
	
	kObjectName.Buffer = NULL;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	statusCall = ((NTQUERYATTRIBUTESFILE)(oldNtQueryAttributesFile))(ObjectAttributes, FileInformation);

	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
		
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwQueryAttributesFile\n"));
		#endif
		
		if(NT_SUCCESS(statusCall))
		{
			__try
			{
				ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);
				ProbeForRead(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length, 1);	
			
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
ULONG newNtUserCallOneParam(ULONG Param, ULONG Routine)
{
	ULONG currentProcessId;
	PWCHAR parameter = NULL;
		
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		if(Routine == 0x34)
		{
			#ifdef DEBUG
			KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwUserCallOneParam\n"));
			#endif
			
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
	return ((NTUSERCALLONEPARAM)(oldNtUserCallOneParam))(Param, Routine);
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
ULONG newNtUserCallNoParam(ULONG Routine)
{
	ULONG currentProcessId;
	PWCHAR parameter = NULL;
		
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	
	if(isProcessMonitoredByPid(currentProcessId) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwUserCallNoParam\n"));
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
	return ((NTUSERCALLNOPARAM)(oldNtUserCallNoParam))(Routine);
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//  	Dumps files which are about to be deleted (FILE_DELETE_ON_CLOSE)
//  Parameters :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566417%28v=vs.85%29.aspx
//  Return value :
//  	See http://msdn.microsoft.com/en-us/library/windows/hardware/ff566417%28v=vs.85%29.aspx
// 	Process :
//		if Handle is on the handle monitored list, retrieve filename from handle and move the file 
// 		to cuckoo directory before the syscall
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS newNtClose(HANDLE Handle)
{
	ULONG currentProcessId;
	UNICODE_STRING file_to_dump;
	PWCHAR parameter = NULL;
	POBJECT_NAME_INFORMATION originalNameInformation = NULL;
	NTSTATUS status;
	
	currentProcessId = (ULONG)PsGetCurrentProcessId();
	if(isProcessMonitoredByPid(currentProcessId) && isHandleInMonitoredList(Handle) && ExGetPreviousMode() != KernelMode)
	{
		#ifdef DEBUG
		KdPrintEx(( DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL, "call ZwClose\n"));
		#endif
		
		// retrieve filename from handle
		originalNameInformation = ExAllocatePoolWithTag(NonPagedPool, MAXSIZE, BUFFER_TAG);
		if(originalNameInformation)
			ZwQueryObject(Handle, ObjectNameInformation, originalNameInformation, MAXSIZE, NULL);
					
		// we need to move the file straight away (:
		if(originalNameInformation->Name.Buffer)
		{			
			// move the file which is about to be deleted to cuckoo directory
			ZwClose(Handle);
			
			file_to_dump.Length = 0;
			file_to_dump.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
			file_to_dump.Buffer = ExAllocatePoolWithTag(NonPagedPool, file_to_dump.MaximumLength, 'jKlA');
			if(!NT_SUCCESS(dump_file(originalNameInformation->Name, &file_to_dump)))
				RtlInitUnicodeString(&file_to_dump, L"ERROR");
			
			parameter = ExAllocatePoolWithTag(NonPagedPool, (MAXSIZE+1)*sizeof(WCHAR), PROC_POOL_TAG);
			if(parameter && originalNameInformation && NT_SUCCESS(RtlStringCchPrintfW(parameter, MAXSIZE, L"1,%d,sss,FileHandle->0x%08x,FileName->%wZ,FileToDump->%wZ", STATUS_SUCCESS, Handle, &(originalNameInformation->Name), &file_to_dump)))
				sendLogs(currentProcessId, L"ZwClose (FILE_DELETE_ON_CLOSE)", parameter);	
			else
				sendLogs(currentProcessId, L"ZwClose (FILE_DELETE_ON_CLOSE)", L"0,-1,sss,FileHandle->ERROR,FileName->ERROR,FileToDump->ERROR");
			ExFreePool(parameter);	
		}
		if(originalNameInformation)
			ExFreePool(originalNameInformation);

		removeHandleInMonitoredList(Handle);	
		return ((NTCLOSE)(oldNtClose))(Handle);
	}	
	else
		return ((NTCLOSE)(oldNtClose))(Handle);
}
