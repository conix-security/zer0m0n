////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n DRIVER
//
//  Copyright 2014 Conix Security, Nicolas Correia, Adrien Chevalier, Cyril Moreau
//
//  This file is part of zer0m0n.
//
//  Zer0m0n is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Zer0m0n is distibuted in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Zer0m0n.  If not, see <http://www.gnu.org/licenses/>.
//
//
//	File :		stack_unwind.c
//	Abstract :	Stack unwinding
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia & Cyril Moreau
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr cyril.moreau@conix.fr
//	Date :		2014-08-22	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#include "query_information.h"
#include "module.h"
#include "main.h"
#include "include/nt/structures/PEB_LDR_DATA.h"
#include "include/nt/structures/LDR_DATA_TABLE_ENTRY.h"
#include "include/nt/structures/SYSTEM_MODULE_INFORMATION.h"
#include "include/nt/structures/PEB.h"


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Allocate and fill a PMODULE_INFORMATION_TABLE structure depending of the information given in the PEB
//		It also retrieves information from the system modules and add them to the table
//	Parameters :
//		IN ULONG Pid	The targeted process ID
//		IN PPEB pPeb	An allocated PEB pointer
//	Return value :
//		PMODULE_INFORMATION_TABLE	An allocated PMODULE_INFORMATION_TABLE containing the information about the modules
//	Process :
//		Read the PEB structure
//		Count the number of modules loaded
//		Add the count of system modules
//		Allocate the module information table with the correct size
//		Fill the table with each entry of user modules
//		Fill the table with each entry of system modules
//		Add the module information table in the global list
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PMODULE_INFORMATION_TABLE
CreateModuleInformation (
	IN ULONG Pid,
	IN PPEB pPeb
) {
	ULONG Count = 0;
	ULONG CurCount = 0;
	ULONG SystemIndex = 0;
	ANSI_STRING AnsiString;
	PLIST_ENTRY pEntry = NULL;
	UNICODE_STRING UnicodeString;
	PLIST_ENTRY pHeadEntry = NULL;
	PPEB_LDR_DATA pLdrData = NULL;
	PMODULE_ENTRY CurModule = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
	PSYSTEM_MODULE_ENTRY pSystemModule = NULL;
	PMODULE_INFORMATION_TABLE pModuleInformationTable = NULL;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = NULL;

	pLdrData = pPeb->LdrData;
	pHeadEntry = &pLdrData->InMemoryOrderModuleList;

	// Count user modules : iterate through the entire list
	pEntry = pHeadEntry->Flink;
	while (pEntry != pHeadEntry) {
		Count++;
		pEntry = pEntry->Flink;
	}

	// Get the kernel modules list
	if ((pSystemModuleInformation = QuerySystemInformation (SystemModuleInformation)) == NULL) {
		Dbg ("QuerySystemInformation(SystemModuleInformation) failed.");
		return NULL;
	}

	Count += pSystemModuleInformation->ModulesCount;

	// Allocate a MODULE_INFORMATION_TABLE
	if ((pModuleInformationTable = ExAllocatePoolWithTag (NonPagedPool, sizeof (MODULE_INFORMATION_TABLE), 'CMI')) == NULL) {
		Dbg ("Cannot allocate a MODULE_INFORMATION_TABLE.");
		// Cleaning
		ExFreePool (pSystemModuleInformation);
		return NULL;
	}

	// Allocate the correct amount of memory depending of the modules count
	if ((pModuleInformationTable->Modules = ExAllocatePoolWithTag (
			NonPagedPool, Count * sizeof (MODULE_ENTRY), 'CMI2')
		) == NULL) {
		Dbg ("Cannot allocate a MODULE_INFORMATION_TABLE.");
		// Cleaning
		ExFreePool (pModuleInformationTable);
		ExFreePool (pSystemModuleInformation);
		return NULL;
	}

	// Fill the basic information of MODULE_INFORMATION_TABLE
	pModuleInformationTable->ModuleCount = Count;
	pModuleInformationTable->ImageModule = NULL;
	pModuleInformationTable->Pid = Pid;

	// Fill all the modules information in the table
	pEntry = pHeadEntry->Flink;
	while (pEntry != pHeadEntry)
	{
		// Retrieve the current MODULE_ENTRY
		CurModule = &pModuleInformationTable->Modules[CurCount++];

		// Retrieve the current LDR_DATA_TABLE_ENTRY
		pLdrEntry = CONTAINING_RECORD (pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);

		// Fill the MODULE_ENTRY with the LDR_DATA_TABLE_ENTRY information
		RtlCopyMemory (&CurModule->BaseName,    &pLdrEntry->BaseDllName, sizeof (CurModule->BaseName));
		RtlCopyMemory (&CurModule->FullName,    &pLdrEntry->FullDllName, sizeof (CurModule->FullName));
		RtlCopyMemory (&CurModule->SizeOfImage, &pLdrEntry->SizeOfImage, sizeof (CurModule->SizeOfImage));
		RtlCopyMemory (&CurModule->BaseAddress, &pLdrEntry->DllBase,     sizeof (CurModule->BaseAddress));
		RtlCopyMemory (&CurModule->EntryPoint,  &pLdrEntry->EntryPoint,  sizeof (CurModule->EntryPoint));
		CurModule->IsSystemModule = FALSE;

		// Check if the module is not the current module of the process
		if (CurModule->BaseAddress == pPeb->ImageBaseAddress) {
			pModuleInformationTable->ImageModule = CurModule;
		}

		// Check if the module is the ntdll module
		if (_wcsicmp(CurModule->BaseName.Buffer, L"ntdll.dll") == 0) {
			pModuleInformationTable->NtdllModule = CurModule;
		}

		// Iterate to the next entry
		pEntry = pEntry->Flink;
	}

	// Store all the kernel modules information in the table
	Count -= CurCount; // Reset index to 0 -> SystemModuleCountMax
	for (SystemIndex = 0; SystemIndex < Count; SystemIndex++)
	{
		// Retrieve the current MODULE_ENTRY
		CurModule = &pModuleInformationTable->Modules[CurCount++];

		// Retrieve the current MODULE_ENTRY
		pSystemModule = &pSystemModuleInformation->Modules[SystemIndex];

		// Fill the MODULE_ENTRY with the MODULE_ENTRY information
		// ASCII to UNICODE conversion for BaseName
		RtlInitAnsiString (&AnsiString, (PCSZ) (pSystemModule->ModuleName + pSystemModule->ModuleNameOffset));
		RtlAnsiStringToUnicodeString (&UnicodeString, &AnsiString, TRUE);
		RtlCopyMemory (&CurModule->BaseName, &UnicodeString, sizeof (UnicodeString));

		// ASCII to UNICODE conversion for FullName
		RtlInitAnsiString (&AnsiString, (PCSZ) &pSystemModule->ModuleName);
		RtlAnsiStringToUnicodeString (&UnicodeString, &AnsiString, TRUE);
		RtlCopyMemory (&CurModule->FullName, &UnicodeString, sizeof (CurModule->FullName));

		RtlCopyMemory (&CurModule->SizeOfImage, &pSystemModule->ModuleSize, 		sizeof (pSystemModule->ModuleSize));
		RtlCopyMemory (&CurModule->BaseAddress, &pSystemModule->ModuleBaseAddress,	sizeof (pSystemModule->ModuleBaseAddress));

		CurModule->EntryPoint = 0;
		CurModule->IsSystemModule = TRUE;
	
		// Check if the module is not the current module of the process
		if (CurModule->BaseAddress == pPeb->ImageBaseAddress) {
			pModuleInformationTable->ImageModule = CurModule;
		}
	}

	// ImageModule should have been detected from this point, check it
	if (pModuleInformationTable->ImageModule == NULL) {
		Dbg ("No ImageBaseAddress detected from the modules list.");
		// Cleaning
		FreeModuleInformationTable (pModuleInformationTable);
		ExFreePool (pSystemModuleInformation);
		return NULL;
	}
	
	// Cleaning
	ExFreePool (pSystemModuleInformation);

	return pModuleInformationTable;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Find the module name of a given address
//
//	Parameters :
//		IN DWORD Address										An address located in a known module
//		IN PMODULE_INFORMATION_TABLE ModuleInformationTable		A pointer to an allocated MODULE_INFORMATION_TABLE
//	Return value :
//		PMODULE_ENTRY	A pointer to the PMODULE_ENTRY depending of the address given
//							Returns NULL if the module hasn't been found.
//	Process :
//		Parse for each entry the base address and the size of the module
//		Check if the given address is in bound of the module
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PMODULE_ENTRY
GetModuleTableEntry (
	IN DWORD Address,
	IN PMODULE_INFORMATION_TABLE ModuleInformationTable
) {
	ULONG Index = 0;

	for (Index = 0; Index < ModuleInformationTable->ModuleCount; Index++) {
		if (AddressInModuleTableEntry (Address, &ModuleInformationTable->Modules[Index])) {
			// Address in bound, result found
			return &ModuleInformationTable->Modules[Index];
		}
	}

	// Nothing found
	return NULL;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Checks if the given address is in the given module
//
//	Parameters :
//		IN DWORD Address							An address to check
//      IN PMODULE_ENTRY pModuleTableEntry          A pointer to an allocated MODULE_ENTRY
//	Return value :
//		PMODULE_ENTRY	A pointer to the PMODULE_ENTRY depending of the address given
//							Returns NULL if the module hasn't been found.
//	Process :
//		Check if the given address is in bound of the module
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN
AddressInModuleTableEntry (
	IN DWORD Address,
	IN PMODULE_ENTRY pModuleTableEntry
) {
	return ((pModuleTableEntry != NULL)
	    &&  (Address >=  (DWORD) pModuleTableEntry->BaseAddress)
		&&  (Address <= ((DWORD) pModuleTableEntry->BaseAddress + pModuleTableEntry->SizeOfImage))
	);
}


/**
 *	Memory deallocation functions 
 **/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Deallocate the memory reserved for a MODULE_INFORMATION_TABLE
//
//	Parameters :
//		IN PMODULE_INFORMATION_TABLE pModuleInformationTable	An allocated pointer to a MODULE_INFORMATION_TABLE
//	Return value :
//		Nothing (should never fail)
//	Process :
//		Deallocate the sub structure before deallocating the structure
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID
FreeModuleInformationTable (
	IN PMODULE_INFORMATION_TABLE pModuleInformationTable
) {
	ULONG Index;
	PMODULE_ENTRY curModule = NULL;

	ExFreePool (pModuleInformationTable->Modules);
	ExFreePool (pModuleInformationTable);
}


/**
 *	Debugging functions 
 **/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Debug a PMODULE_ENTRY
//
//	Parameters :
//		PMODULE_ENTRY pModuleTableEntry		An address located in a known module
//	Return value :
//		Nothing
//	Process :
//		Dump every member of the structure in the console
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID
DebugModuleTableEntry (
	PMODULE_ENTRY pModuleTableEntry
) {
	Dbg ("--- pModuleTableEntry Debug 0x%08X ---", pModuleTableEntry);
	Dbg ("BaseName = %ws", pModuleTableEntry->BaseName.Buffer);
	Dbg ("FullName = %ws", pModuleTableEntry->FullName.Buffer);
	Dbg ("SizeOfImage = %x", pModuleTableEntry->SizeOfImage);
	Dbg ("BaseAddress = %x", pModuleTableEntry->BaseAddress);
	Dbg ("EntryPoint = %x", pModuleTableEntry->EntryPoint);
	Dbg ("IsSystemModule = %x", pModuleTableEntry->IsSystemModule);
}