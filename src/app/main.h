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
//	File :		main.h
//	Abstract :	Main header for zer0m0n
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//		
/////////////////////////////////////////////////////////////////////////////
#ifndef __MAIN_H
#define __MAIN_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fltuser.h>

#define NUMBER_OF_THREADS 1

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
 
typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _KERNEL_MESSAGE
{
	FILTER_MESSAGE_HEADER MessageHeader;
	char message[1024];
	OVERLAPPED Ovlp;
} KERNEL_MESSAGE, *PKERNEL_MESSAGE;

typedef struct _THREAD_CONTEXT
{
	HANDLE hPort;
	HANDLE completion;
} THREAD_CONTEXT, *PTHREAD_CONTEXT;

typedef VOID(WINAPI *RTLINITUNICODESTRING)(PUNICODE_STRING,PCWSTR);

RTLINITUNICODESTRING RtlInitUnicodeString;
CRITICAL_SECTION l_mutex;
int init;

VOID parse_logs(LPVOID p);

#endif