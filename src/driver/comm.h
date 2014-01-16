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
//	File :		comm.h
//	Abstract :	Kernel/Userland communications handling.
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#ifndef __COMM_H
#define __COMM_H

#include <fltkernel.h>

// receive monitored PID from cuckoo's analyzer.py script
#define IOCTL_PID \
		CTL_CODE (FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication connection callback.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ConnectCallback(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Filter communication disconnection callback.
//	Parameters : 
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff541931(v=vs.85).aspx
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID DisconnectCallback(PVOID ConnectionCookie);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		DEVICE_IO_CONTROL IRP handler. Used for getting the monitored process PID.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ioctl_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Generates a message using "pid", "message" and "parameter" and sends it back to userland throught
//		a filter communication port.
//	Parameters :
//		_in_opt_ ULONG pid :		Process ID from which the logs are produced.
//		_in_ PWCHAR message :		Message (function name most of the time).
//		_in_opt_ PWCHAR parameter :	Function args.
//	Return value :
//		NTSTATUS : FltSendMessage return value.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS sendLogs(ULONG pid, PWCHAR message, PWCHAR parameter);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Unsupported IRP generic handler. Just completes the request with STATUS_SUCCESS code.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//	Return value :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff543287(v=vs.85).aspx
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS ioctl_NotSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif
