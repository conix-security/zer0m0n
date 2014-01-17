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
//	File :		comm.c
//	Abstract :	Kernel/Userland communications handling.
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//
////////////////////////////////////////////////////////////////////////////
#include "comm.h"
#include "main.h"
#include "utils.h"
#include "monitor.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication connection callback.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Process :
//		Sets the global variable "clientPort" with the supplied client port communication.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ConnectCallback(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie)
{
	if(ClientPort == NULL)
		return STATUS_INVALID_PARAMETER;

	clientPort = ClientPort;
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication disconnection callback.
//	Parameters : 
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		None
//	Process :
//		Might be used to notify cuckoo while shutting down. In the future.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID DisconnectCallback(PVOID ConnectionCookie)
{
	// computer is being shutting down
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Generates a message using "pid", "message" and "parameter" and sends it back to userland throught
//		a filter communication port.
//	Parameters :
//		_in_opt_ ULONG pid :		Process ID from which the logs are produced.
//		_in_opt_ PWCHAR message :	Message (function name most of the time).
//		_in_opt_ PWCHAR parameter :	Function args.
//	Return value :
//		NTSTATUS : FltSendMessage return value.
//	Process :
//		- Retrieves the process name from the pid and saves the whole data into an ANSI string.
//		- Generates an ANSI string with the message, with the process name, pid, and function name, and the
//		- generic "parameter" parameter. The resulting output will basically follow this scheme:
//			"pid","process_name","function_name","FAILED/SUCCESS/BLOCKED(0/1/2)","return_value","number_of_arguments","argument1->value","argument2->value"...
//		- Uses the "mutex" mutex to avoid concurrency when using the FltSendMessage() function.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS sendLogs(ULONG pid, PWCHAR message, PWCHAR parameter)
{
	NTSTATUS status;
	CHAR buf[MAXSIZE];
	UNICODE_STRING processName;
	ULONG sizeBuf;
	
	processName.Length = 0;
	processName.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
	processName.Buffer = ExAllocatePoolWithTag(NonPagedPool, processName.MaximumLength, PROCNAME_TAG);
	if(processName.Buffer != NULL)
		status = getProcNameByPID(pid, &processName);
	

	status = STATUS_SUCCESS;
	if(NT_SUCCESS(RtlStringCbPrintfA(buf, MAXSIZE, "%d,%wZ,%ws,%ws\n", pid, &processName, message, parameter)))
	{
		RtlStringCbLengthA(buf, MAXSIZE, &sizeBuf);
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(filter, &clientPort, buf, sizeBuf, NULL, 0, NULL);
	}
	else
	{
		KeWaitForMutexObject(&mutex, Executive, KernelMode, FALSE, NULL);
		status = FltSendMessage(filter, &clientPort, "0,error,error,error", 19, NULL, 0, NULL);
	}
	
	KeReleaseMutex(&mutex, FALSE);

	if(processName.Buffer != NULL)
		ExFreePool(processName.Buffer);

	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsupported IRP generic handler. Just completes the request with STATUS_SUCCESS code.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		NTSTATUS : STATUS_SUCCESS
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ioctl_NotSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	if(Irp == NULL || DeviceObject == NULL)
		return STATUS_INVALID_PARAMETER;

	((*Irp).IoStatus).Status = STATUS_SUCCESS;
	((*Irp).IoStatus).Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS parse_pids(PCHAR pids)
{
	PCHAR start,current,data;
	ULONG len, pid;
	BOOLEAN first_pid=TRUE;
	NTSTATUS status;
	
	RtlStringCbLengthA(pids, MAXSIZE, &len);
	data = ExAllocatePoolWithTag(NonPagedPool, len+1, TEMP_TAG);
	if(data == NULL)
		return -1;
	if(!NT_SUCCESS(RtlStringCbPrintfA(data, len+1, "%s", pids)))
	{
		ExFreePool(data);
		return -1;
	}
	
	start = data;
	current = data;
	
	while(*current != 0x00)
	{
		if(*current == '_' && current!=start)
		{
			*current = 0x00;
			status = RtlCharToInteger(start, 10, &pid);
			if(NT_SUCCESS(status) && pid!=0)
			{
				if(first_pid)
				{
					startMonitoringProcess(pid);
					first_pid=FALSE;
				}
				else
					addHiddenProcess(pid);
			}
			start = current+1;
		}
		current++;
	}
	
	if(start != current)
	{
		status = RtlCharToInteger(start, 10, &pid);
		if(NT_SUCCESS(status) && pid!=0)
		{
			if(first_pid)
				startMonitoringProcess(pid);
			else
				addHiddenProcess(pid);
		}	
	}	
	ExFreePool(data);
	
	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		DEVICE_IO_CONTROL IRP handler. Used for getting the monitored process PID.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		NTSTATUS : STATUS_SUCCESS if no error was encountered, otherwise, relevant NTSTATUS code.
//	Process :
//		Handles IRP_MJ_CONTROL IOCTLs. Adds the pid to the monitored list and then destroys the driver
//		symbolic name for security (we don't want someone to interact with the driver).
//	Notes :
//		RtlCharToInteger is used to convert the received char* to int because there is no way to send
//		directly an integer using DeviceIoControl() in python :
//		http://docs.activestate.com/activepython/2.5/pywin32/win32file__DeviceIoControl_meth/html
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ioctl_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackIrp;
	PCHAR outputBuffer;
	DWORD sizeBuf;
	ULONG pid;

	if(Irp == NULL || DeviceObject == NULL)
		return STATUS_INVALID_PARAMETER;
	
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	switch(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_PID:
			#ifdef DEBUG
			DbgPrint("IOCTL_PID received : %s!\n", Irp->AssociatedIrp.SystemBuffer);
			#endif DEBUG
							
			// parse the pids received from cuckoo
			status = parse_pids(Irp->AssociatedIrp.SystemBuffer);
		
			Irp->IoStatus.Status = status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			
			if(NT_SUCCESS(status))
			{
				status = IoDeleteSymbolicLink(&usDosDeviceName);
				#ifdef DEBUG
				if(!NT_SUCCESS(status))
					DbgPrint("IoDeleteSymbolicLink error.\n");
				#endif DEBUG

				IoDeleteDevice(DeviceObject);
			}
			
		break;
		
		default:
		break;
	}
	return status; 
}
