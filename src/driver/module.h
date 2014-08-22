#ifndef __MODULE_INFORMATION_H
#define __MODULE_INFORMATION_H

#include <fltkernel.h>
#include <ntddk.h>
#include <windef.h>

/**
 *	MODULE_ENTRY contains basic information about a module
 */
typedef struct _MODULE_ENTRY
{
	UNICODE_STRING BaseName;			// BaseName of the module
	UNICODE_STRING FullName;			// FullName of the module
	
    ULONG SizeOfImage;					// Size in bytes of the module
    PVOID BaseAddress;					// Base address of the module

    PVOID EntryPoint;					// Entrypoint of the module
	
	BOOLEAN IsSystemModule;				// TRUE if the module is a system module
	
}	MODULE_ENTRY, *PMODULE_ENTRY;


/**
 *	MODULE_INFORMATION_TABLE contains basic information about all the modules of a given process
 */
typedef struct _MODULE_INFORMATION_TABLE
{
	ULONG Pid;							// PID of the process
	ULONG ModuleCount;					// Modules count for the above pointer
	PMODULE_ENTRY Modules;				// Pointer to 0...* modules
	PMODULE_ENTRY ImageModule;			// Pointer to the current executable module
	PMODULE_ENTRY NtdllModule;			// Pointer to the ntdll module

}	MODULE_INFORMATION_TABLE, *PMODULE_INFORMATION_TABLE;


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
);


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
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Checks if the given address is in the given module
//
//	Parameters :
//		IN DWORD Address										An address to check
//		IN PMODULE_INFORMATION_TABLE ModuleInformationTable		A pointer to an allocated MODULE_INFORMATION_TABLE
//	Return value :
//		PMODULE_ENTRY	A pointer to the PMODULE_ENTRY depending of the address given
//							Returns NULL if the module hasn't been found.
//	Process :
//		Parse for each entry the base address and the size of the module
//		Check if the given address is in bound of the module
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN
AddressInModuleTableEntry (
	IN DWORD Address,
	IN PMODULE_ENTRY pModuleTableEntry
);


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
);


/**
 * Debugging functions 
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
);

#endif