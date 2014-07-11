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
//	File :		callbacks.h
//	Abstract :	Various callbacks handlers.
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#ifndef __CALLBACKS_H
#define __CALLBACKS_H

#include <fltkernel.h>

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  	Description :
//		Image load callback. Allows being notified when a PE image is loaded into kernel space.
//	Parameters :
//		See http://msdn.microsoft.com/en-us/library/windows/hardware/ff559957(v=vs.85).aspx
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID imageCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

#endif
