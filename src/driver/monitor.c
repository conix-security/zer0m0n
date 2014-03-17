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
//		Adds "pid" process in the monitored list (starts monitoring this process).
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.
//	Process :
//		Checks if the PID is not on the list. If not, add it to the linked list.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS startMonitoringProcess(ULONG new_pid)
{
	PMONITORED_PROCESS_ENTRY new_entry;
	
	if(new_pid == 0)
		return STATUS_INVALID_PARAMETER;
	if(isProcessMonitoredByPid(new_pid))
		return STATUS_SUCCESS;
	
	new_entry = (PMONITORED_PROCESS_ENTRY)ExAllocatePoolWithTag(NonPagedPool,sizeof(MONITORED_PROCESS_ENTRY),MONIT_POOL_TAG);
	if(new_entry == NULL)
		return STATUS_NO_MEMORY;
		
	new_entry->pid = new_pid;
	new_entry->flink = monitored_process_list;
	monitored_process_list = new_entry;
	//#ifdef DEBUG
	DbgPrint("New PID : %d\n",new_pid);
	//#endif
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Adds "pid" process in the hidden processes list.
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.
//	Process :
//		Checks if the PID is not on the list. If not, add it to the linked list.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS addHiddenProcess(ULONG new_pid)
{
	PHIDDEN_PROCESS new_entry;
	if(new_pid == 0)
		return STATUS_INVALID_PARAMETER;
	if(isProcessHiddenByPid(new_pid))
		return STATUS_SUCCESS;

	//#ifdef DEBUG
	DbgPrint("adding pid to hide : %d\n", new_pid);	
	//#endif
	
	new_entry = (PHIDDEN_PROCESS)ExAllocatePoolWithTag(NonPagedPool,sizeof(HIDDEN_PROCESS),MONIT_POOL_TAG);
	if(new_entry == NULL)
		return STATUS_NO_MEMORY;
		
	new_entry->pid = new_pid;
	new_entry->flink = hidden_process_list;
	hidden_process_list = new_entry;
	
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Removes "pid" from the monitored list (stops monitoring this process).
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//	Return value :
//		NTSTATUS :  STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.
//	Process :
//		Checks if the PID is on the list. If yes, remove it.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS stopMonitoringProcess(ULONG existing_pid)
{
	PMONITORED_PROCESS_ENTRY currentMember, prevMember;
	if(existing_pid == 0)
		return STATUS_INVALID_PARAMETER;
		
	prevMember = NULL;
	currentMember = monitored_process_list;
	while(currentMember != NULL)
	{
		if(currentMember->pid == existing_pid)
		{
			if(prevMember == NULL)
			{
				monitored_process_list = (PMONITORED_PROCESS_ENTRY)(currentMember->flink);
				ExFreePoolWithTag(prevMember,MONIT_POOL_TAG);
				currentMember = monitored_process_list;
			}
			else
			{
				prevMember->flink = currentMember->flink;
				ExFreePoolWithTag(currentMember,MONIT_POOL_TAG);
				currentMember = (PMONITORED_PROCESS_ENTRY)(prevMember->flink);
				
			}
		}
		else
		{
			prevMember = currentMember;
			currentMember = (PMONITORED_PROCESS_ENTRY)(currentMember->flink);
		}
	}
	
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Removes all of the monitored list entries (stops monitoring).
//	Parameters :
//		None
//	Return value :
//		NTSTATUS :  STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.	
//	Process :
//		Walks through the linked list and removes each entry.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS cleanMonitoredProcessList()
{
	PMONITORED_PROCESS_ENTRY currentMember, tempMember;
	
	if(monitored_process_list == NULL)
		return STATUS_SUCCESS;
	
	currentMember = monitored_process_list;
	tempMember = NULL;
	while(currentMember != NULL)
	{
		tempMember = currentMember;
		currentMember = (PMONITORED_PROCESS_ENTRY)(currentMember->flink);
		ExFreePoolWithTag(tempMember,MONIT_POOL_TAG);
	}
	
	monitored_process_list = NULL;
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Removes all of the hidden processes list entries.
//	Parameters :
//		None
//	Return value :
//	Process :
//		Walks through the linked list and removes each entry.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS cleanHiddenProcessList()
{
	PHIDDEN_PROCESS currentMember, tempMember;
	
	if(hidden_process_list == NULL)
		return STATUS_SUCCESS;
	
	currentMember = hidden_process_list;
	tempMember = NULL;
	while(currentMember != NULL)
	{
		tempMember = currentMember;
		currentMember = (PHIDDEN_PROCESS)(currentMember->flink);
		ExFreePoolWithTag(tempMember,MONIT_POOL_TAG);
	}
	
	hidden_process_list = NULL;
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Returns TRUE if pid is in the monitored list (if it is actually monitored).
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//	Return value :
//		BOOLEAN : TRUE if found, FALSE if not.
//	Process :
//		Walks through the linked list, eturns TRUE if "pid" is found.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN isProcessMonitoredByPid(ULONG pid)
{
	PMONITORED_PROCESS_ENTRY ptr;
	if(pid == 0)
		return FALSE;
		
	ptr = monitored_process_list;
	while(ptr != NULL)
	{
		if(ptr->pid == pid)
			return TRUE;
		
		ptr = (PMONITORED_PROCESS_ENTRY)(ptr->flink);
	}
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Returns TRUE if pid is in the hidden processes list.
//	Parameters :
//		_in_ ULONG pid : Process Identifier.
//	Return value :
//		BOOLEAN : TRUE if found, FALSE if not.
//	Process :
//		Walks through the linked list, eturns TRUE if "pid" is found.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOLEAN isProcessHiddenByPid(ULONG pid)
{
	PHIDDEN_PROCESS ptr;
	
	if(pid == 0)
		return FALSE;
		
	ptr = hidden_process_list;
	while(ptr != NULL)
	{
		if(ptr->pid == pid)
			return TRUE;
		
		ptr = (PHIDDEN_PROCESS)(ptr->flink);
	}
	
	return FALSE;

}
