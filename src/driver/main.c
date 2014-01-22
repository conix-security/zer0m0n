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
//	File :		main.c
//	Abstract :	Main function for Cuckoo Zero Driver
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//		
/////////////////////////////////////////////////////////////////////////////
#include "main.h"
#include "comm.h"
#include "monitor.h"
#include "utils.h"
#include "reg.h"
#include "callbacks.h"
#include "hook.h"

// filter callbacks struct
FLT_REGISTRATION registration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
	NULL,
	NULL,
	UnregisterFilter,
	NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : initializes the driver and the filter port, registers driver and registry callbacks.
//
//	Parameters : 
//		_in_ PDRIVER_OBJECT pDriverObject :	Data structure used to represent the driver.
//		_in_ PUNICODE_STRING pRegistryPath :	Registry location where the information for the driver
//							was stored.
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if the driver initialization has been well completed
//	Process :
//		Defines hidden / blocked processes names.
//		Creates the device driver and its symbolic link.
//		Sets IRP callbacks.
//		Creates filter communication port to send logs from the driver to the userland process.
//		Creates logs mutex.
//		Hooks SSDT.
//		Register image load and registry callbacks.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	PVOID adrFunc;
	PDEVICE_OBJECT pDeviceObject;
	UNICODE_STRING usDriverName;
	UNICODE_STRING filterPortName;
	OBJECT_ATTRIBUTES objAttr;
	PSECURITY_DESCRIPTOR securityDescriptor;
	NTSTATUS status;
	ULONG i;
	 
	RtlInitUnicodeString(&usDriverName, L"\\Device\\DriverSSDT");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\DriverSSDT"); 

	status = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
	
	if(NT_SUCCESS(status))
    {
		#ifdef DEBUG
        DbgPrint("[+] Device driver created\n");
		#endif
		
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
		
		for(i=0; i<IRP_MJ_MAXIMUM_FUNCTION; i++)
			pDriverObject->MajorFunction[i] = ioctl_NotSupported;
        	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctl_DeviceControl;
	}

	monitored_process_list = NULL;
	hidden_process_list = NULL;
	
   	status = FltRegisterFilter(pDriverObject,&registration,&filter);
	if(NT_SUCCESS(status))
    {
		RtlInitUnicodeString(&filterPortName, L"\\FilterPort");
		FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
		InitializeObjectAttributes(&objAttr, &filterPortName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, securityDescriptor); 
		status = FltCreateCommunicationPort(filter, &serverPort, &objAttr, NULL, ConnectCallback, DisconnectCallback, NULL, 1);
		if(!NT_SUCCESS(status))
		{
			#ifdef DEBUG
			DbgPrint("FltCreateCommunicationPort() failed ! : 0x%08x\n", status);
			#endif
			return status;
		}
		FltFreeSecurityDescriptor(securityDescriptor);
	}
	else
	{
		#ifdef DEBUG
		DbgPrint("FltRegisterFilter failed : 0x%08x\n", status);
		#endif
		return status;
	}
	
	KeInitializeMutex(&mutex, 0);

	hook_ssdt_entries();
	
	status = CmRegisterCallback(regCallback, NULL, &cookie);
	
	status = PsSetLoadImageNotifyRoutine(imageCallback);
	
	pDriverObject->DriverUnload = Unload;
	
	return STATUS_SUCCESS;
}
 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Driver unload callback. Removes hooks, callbacks, and communication stuff.
//	Parameters :
//	Process :
//		Removes hooks, callbacks, device driver symbolic link / device, and cleans the monitored
//		processes linked list.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID Unload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("Unload() called\n");
	unhook_ssdt_entries();
	
	CmUnRegisterCallback(cookie);
	PsRemoveLoadImageNotifyRoutine(imageCallback);

	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(pDriverObject->DeviceObject);
	
	cleanMonitoredProcessList();	
	cleanHiddenProcessList();
}
 
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Description :
//	Unregisters the minifilter.
//	Parameters :
//	Return value :
//	Process :
//		Closes filter communication port and unregisters the filter.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS UnregisterFilter(FLT_FILTER_UNLOAD_FLAGS flags)
{
	DbgPrint("UnloadFilter() called\n");
	FltCloseCommunicationPort(serverPort);

	if(filter!=NULL)
		FltUnregisterFilter(filter);
	
	return STATUS_FLT_DO_NOT_DETACH;
}
