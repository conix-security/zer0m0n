#ifndef __QUERY_INFORMATION_H
#define __QUERY_INFORMATION_H

#include <fltkernel.h>
#include <ntddk.h>
#include <windef.h>

#include "module.h"
#include "hook.h" // SYSTEM_INFORMATION_CLASS definition

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QuerySystemInformation is a wrapper around ZwQuerySystemInformation.
// 		Return a pointer to a structure information of the current process, depending of the SystemInformationClass requested
//
//	Parameters :
//		IN SYSTEM_INFORMATION_CLASS SystemInformationClass		The information class requested
//	Return value :
//		PVOID :	An information structure pointer retrieved with ZwQuerySystemInformation depending of the class requested
//	Process :
//		Request the requested structure size
//		Allocate the memory for the requested structure
//		Fill the requested structure
//		Check the structure size requested with the one returned by ZwQuerySystemInformation
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID QuerySystemInformation (
	SYSTEM_INFORMATION_CLASS SystemInformationClass
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		QueryProcessInformation is a wrapper around ZwQueryInformationProcess.
// 		Return a pointer to a structure information of the current process, depending of the ProcessInformationClass requested
//
//	Parameters :
//		IN HANDLE Process								The process targeted
//		IN PROCESSINFOCLASS ProcessInformationClass		The information class requested
//	Return value :
//		PVOID :	An information structure pointer retrieved with ZwQueryInformationProcess depending of the class requested
//	Process :
//		Request the requested structure size
//		Allocate the memory for the requested structure
//		Fill the requested structure
//		Check the structure size requested with the one returned by ZwQueryInformationProcess
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID 
QueryProcessInformation (
	IN HANDLE Process, 
	IN PROCESSINFOCLASS ProcessInformationClass, 
	IN DWORD ProcessInformationLength
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		Get the entire module information table from the current process
//
//	Parameters :
//		Nothing
//	Return value :
//		PMODULE_INFORMATION_TABLE : 	A pointer to an allocated module information table
//	Process :
//		Wrapper around GetPebProcess, reads and store the result into a MODULE_INFORMATION_TABLE structure
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PMODULE_INFORMATION_TABLE
QueryModuleInformationCurrentProcess (
	VOID
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		Retrieve the entire PEB structure of the current process
//
//	Parameters :
//	Return value :
//		PPEB :		A pointer to the PEB structure of the current process, or NULL if error
//	Process :
//		Calls QueryProcessInformation with a ProcessBasicInformation class to retrieve a PROCESS_BASIC_INFORMATION pointer
//		Read the PROCESS_BASIC_INFORMATION.PebAddress to retrieve the address of the PEB structure before returning it
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PPEB
GetPebCurrentProcess (
	VOID
);

#endif