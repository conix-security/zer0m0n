////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n 
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
//	File :		monitor.h
//	Abstract :	Monitored processes list handling
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#ifndef __MONITOR_H
#define __MONITOR_H

#include "main.h"

/////////////////////////////////////////////////////////////////////////////
// STRUCTS
/////////////////////////////////////////////////////////////////////////////

// Monitored process linked list 		
typedef struct _MONITORED_PROCESS_ENTRY {
		ULONG pid;
		int g_sock;
		PVOID flink;
} MONITORED_PROCESS_ENTRY,*PMONITORED_PROCESS_ENTRY;

/////////////////////////////////////////////////////////////////////////////
// GLOBALS
/////////////////////////////////////////////////////////////////////////////

PMONITORED_PROCESS_ENTRY monitored_process_list;

/////////////////////////////////////////////////////////////////////////////
// FUNCTIONS
/////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Adds "pid" process in the monitored list and its associated socket id(starts monitoring this process).
//	Parameters :
//		_in_ ULONG new_pid : Process Identifier.
//		_in_ int new_sock : socket associated with this pid
//	Return value :
//		int : 1 if no error was encountered, otherwise, returns -1.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int startMonitoringProcess(ULONG new_pid, int new_sock);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Returns TRUE if pid is in the monitored list (if it is actually monitored).
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//	Return value :
//		BOOLEAN : TRUE if found, FALSE if not.
//	Process :
//		Walks through the linked list, returns TRUE if "pid" is found.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN isProcessMonitoredByPid(ULONG pid);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Returns socket identifier associated with the pid given in parameter
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//	Return value :
//		int : Socket Identifier
//	Process :
//		Walks through the linked list, returns the socket id if "pid" is found.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int getSockIdFromPid(ULONG pid);

#endif