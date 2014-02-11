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
//	File :		main.h
//	Abstract :	Main header for Cuckoo Zero Driver
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//
//	TODO : 
//		- rename removed files to dump them
//		- handle shutdown case
//		- logs registries callbacks returns (or move ot SSDT hooks)
//		- hide processes by PID (get them at startup with cuckoo)
/////////////////////////////////////////////////////////////////////////////

#ifndef __MAIN_H
#define __MAIN_H

#include <fltkernel.h>
#include <ntstrsafe.h>


/////////////////////////////////////////////////////////////////////////////
// DEFINES
/////////////////////////////////////////////////////////////////////////////

// Uncomment to enable kernel debugging output
//#define DEBUG

// Memory tags
#define PROC_POOL_TAG 		'prcT'
#define THREAD_CALLBACK_TAG 	'thrT'
#define PROC_CALLBACK_TAG 	'pRcT'
#define PPROC_CALLBACK_TAG 	'pPrc'
#define BUF_POOL_TAG 		'bufP'
#define MONIT_POOL_TAG 		'monP'
#define BUFFER_TAG 		'mmoP'
#define TEMP_TAG 		'Yeii'
#define PROCNAME_TAG 		'giaL'
				
// Generic defines
#define MAXSIZE 			1024
#define ObjectNameInformation 		1

// log mode
#define LOG_ERROR 	0	// log a failed call (without params)
#define LOG_SUCCESS	1	// log a successed call (without params)
#define LOG_PARAM 	2	// log a call along with the parameters, return value, etc.

// Generic error message
#define GENERIC_ERROR_MESSAGE L"1,0,s,ERROR";
// Generic success message
#define GENERIC_SUCCESS_MESSAGE L"0,-1,s,ERROR";

enum OS_VER
{
	xp,
	seven
} os_version;

/////////////////////////////////////////////////////////////////////////////
// STRUCTS
/////////////////////////////////////////////////////////////////////////////

typedef NTSTATUS (*ZWQUERYINFORMATIONPROCESS)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (*ZWQUERYINFORMATIONTHREAD)(HANDLE,ULONG,PVOID,ULONG,PULONG);

// specific imports
ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess;
ZWQUERYINFORMATIONTHREAD ZwQueryInformationThread;


/////////////////////////////////////////////////////////////////////////////
// GLOBALS 
/////////////////////////////////////////////////////////////////////////////


// registry callback cookie
LARGE_INTEGER cookie;

// userland communication mutex
KMUTEX mutex;

// Filter communication stuff
PFLT_FILTER filter;
PFLT_PORT serverPort;
PFLT_PORT clientPort;

// Dos device driver name
UNICODE_STRING usDosDeviceName;


/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Driver entry point, initializes communication, callbacks and hooks.
//	Parameters : 
//	Return value :
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Driver unload callback. Removes hooks, callbacks, and communication stuff.
//	Parameters :
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Unload(PDRIVER_OBJECT pDriverObject);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//		Unregisters the minifilter.
//	Parameters :
//	Return value :
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS UnregisterFilter(FLT_FILTER_UNLOAD_FLAGS flags);



#endif

