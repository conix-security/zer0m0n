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
//	File :		monitor.c
//	Abstract :	Monitored processes list handling
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#include "monitor.h"
#include "main.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Removes all of the monitored list entries (stops monitoring).
//	Parameters :
//		None
//	Return value :
//		int : 1 if no error was encountered, otherwise, returns -1.	
//	Process :
//		Walks through the linked list and removes each entry.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int cleanMonitoredProcessList()
{
	PMONITORED_PROCESS_ENTRY currentMember, tempMember;
	
	if(monitored_process_list == NULL)
		return 1;
	
	currentMember = monitored_process_list;
	tempMember = NULL;
	while(currentMember != NULL)
	{
		tempMember = currentMember;
		currentMember = (PMONITORED_PROCESS_ENTRY)(currentMember->flink);
		free(tempMember);
	}
	
	monitored_process_list = NULL;
	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Adds "pid" process in the monitored list and its associated socket id(starts monitoring this process).
//	Parameters :
//		_in_ ULONG new_pid : Process Identifier.
//		_in_ int new_sock : socket associated with this pid
//	Return value :
//		int : 1 if no error was encountered, otherwise, returns -1.
//	Process :
//		Checks if the PID is not on the list. If not, add it to the linked list with its associated socket
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int startMonitoringProcess(ULONG new_pid, int new_sock)
{
	PMONITORED_PROCESS_ENTRY new_entry;
	if(new_pid == 0)
		return -1;
	if(isProcessMonitoredByPid(new_pid) == 0)
		return 1;

	new_entry = (PMONITORED_PROCESS_ENTRY)malloc(sizeof(MONITORED_PROCESS_ENTRY));
	
	if(new_entry == NULL)
		return -1;
		
	new_entry->pid = new_pid;
	new_entry->g_sock = new_sock;
	new_entry->flink = monitored_process_list;
	monitored_process_list = new_entry;
	
	return 1;
}

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
int isProcessMonitoredByPid(ULONG pid)
{
	PMONITORED_PROCESS_ENTRY ptr;
	
	if(pid == 0)
		return -1;
		
	ptr = monitored_process_list;
	while(ptr != NULL)
	{
		if(ptr->pid == pid)
			return 0;	
		ptr = (PMONITORED_PROCESS_ENTRY)(ptr->flink);
	}
	return -1;
}

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
int getMonitoredProcessSocket(ULONG pid)
{
	PMONITORED_PROCESS_ENTRY ptr;

	if(pid == 0)
		return -1;

	ptr = monitored_process_list;
	while(ptr != NULL)
	{
		if(ptr->pid == pid)
			return ptr->g_sock;
		
		ptr = (PMONITORED_PROCESS_ENTRY)(ptr->flink);
	}
	return -1;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Updates a PID-related socket
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//		_in_ int new_sock : Socket
//	Return value :
//		int : 0 if success, -1 if not.
//	Process :
//		Walks through the linked list, updates the socket if "pid" is found.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int setMonitoredProcessSocket(ULONG pid, int new_sock)
{
	PMONITORED_PROCESS_ENTRY ptr;

	if(pid == 0)
		return -1;

	ptr = monitored_process_list;
	while(ptr != NULL)
	{
		if(ptr->pid == pid)
		{
			ptr->g_sock = new_sock;
			return 0;
		}
		ptr = (PMONITORED_PROCESS_ENTRY)(ptr->flink);
	}
	return -1;
}
