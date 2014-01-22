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
//	File :		main.c
//	Abstract :	Main function for zer0m0n 
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//		
/////////////////////////////////////////////////////////////////////////////

#include "main.h"
#include "monitor.h"
#include "bson.h"
#include "parsing.h"
#include "config.h"
#include "pipe.h"
#include "file.h"
#include "log.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : initializes the driver and the filter port, registers driver and registry callbacks.
//
//	Parameters : 
//	Return value :
//	Process :
//		Gets the main cuckoo parameters.
//		Connects to filter communication port then loops while receiving data from the zer0m0n driver.
//		When a new process is detected, analyzer.py is notified and the new PID is added to the
//		monitored processes list along with a new socket, which will be used for this PID.
//		Logs are parsed, then directly sent to the Cuckoo host.
//		Sockets states are regularly checked to avoid connection issues.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
	HANDLE hPort;
	KERNEL_MESSAGE msg;
	LOG log;
	int size, i, ptr_msg;
	int init = 0;
	int error = 0;
	int error_len = sizeof(error);
	PUNICODE_STRING us_pathfile = NULL;
	PWCHAR pw_pathfile = NULL;
	
	log.funcname = NULL;
	log.procname = NULL;
	log.fmt = NULL;
	log.arguments = NULL;
	
	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(LoadLibrary("ntdll.dll"), "RtlInitUnicodeString");
	if(RtlInitUnicodeString == NULL)
		return -1;
	
	// initialization
	file_init();
	
	FilterConnectCommunicationPort(L"\\FilterPort", 0, NULL, 0, NULL, &hPort);
	if(hPort == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "cannot connect to filter communication port\n");
		exit(0);
	}
	printf("[+] connected to filter communication port\n");
	
	while(1)
	{
		if(FilterGetMessage(hPort,(PFILTER_MESSAGE_HEADER)&msg, sizeof(KERNEL_MESSAGE), NULL) == S_OK)
		{
			// 0x0A : message delimiter
			i=0;
			while(msg.message[i] != 0x0A)
				i++;
			msg.message[i] = 0x0;
		
			// initialize pointer to the beginning of the log
			ptr_msg = 0;
			
			// get PID
			size = getsize(0, msg.message, 0x2C);
			log.pid = retrieve_int(msg.message, size);
			ptr_msg = size+1;

			if(isProcessMonitoredByPid(log.pid) == -1)
			{
				printf("[+] NEW PID: %d\n", log.pid); 
				if(!init)
				{
					read_config(log.pid);
					g_pipe_name = g_config.pipe_name;
					init = 1;
				}

				// notifies analyzer.py
				pipe("KPROCESS:%d", log.pid);
				
				// create socket / new struct
				log.g_sock = log_init(g_config.host_ip, g_config.host_port, 0);
				if(startMonitoringProcess(log.pid, log.g_sock) == -1)
					printf("[!] Could not add %d\n",log.pid);

				if(connect(log.g_sock, (struct sockaddr *) &addr, sizeof(addr)))
					printf("[!] Could not connect %d\n",WSAGetLastError());
			
				announce_netlog(log.pid, log.g_sock);
				
				// get process name
				size = getsize(ptr_msg, msg.message, 0x2C);
				log.procname = malloc(size+1);
				log.procname[size] = 0x0;
				memcpy(log.procname, msg.message+ptr_msg, size);
				ptr_msg += size+1;
				
				log_new_process(log.pid, log.procname, log.g_sock);
				log_new_thread(log.pid, log.g_sock);
			}
			else
			{
				// skip process name
				size = getsize(ptr_msg, msg.message, 0x2C);
				ptr_msg += size+1;
				
				// get socket
				log.g_sock = getMonitoredProcessSocket(log.pid);
				
				// connection status ?
				getsockopt(log.g_sock, SOL_SOCKET, SO_ERROR, (char*)&error, &error_len);
				if(error == WSAECONNABORTED || error == WSAECONNRESET || error == WSAENOTCONN || error == WSAENETRESET || error == WSAETIMEDOUT)
				{
					// software error
					printf("[!] Reconnecting socket...");
					closesocket(log.g_sock);
					log.g_sock = log_init(g_config.host_ip, g_config.host_port, 0);
					if(connect(log.g_sock, (struct sockaddr *) &addr, sizeof(addr)) == 0)
						printf(" OK\n");
					else
						printf(" ERROR %d\n",WSAGetLastError());
					announce_netlog(log.pid, log.g_sock);
					setMonitoredProcessSocket(log.pid, log.g_sock);
				}
			}
			
			// retrieve function name
			size = getsize(ptr_msg, msg.message, 0x2C);
			log.funcname = malloc(size+1);
			log.funcname[size] = 0x0;
			memcpy(log.funcname, msg.message+ptr_msg, size);
			
			// retrieve success status
			ptr_msg += size+1;
			log.success = retrieve_int(msg.message+ptr_msg, 1);
			
			// retrieve return value
			ptr_msg += 2;
			size = getsize(ptr_msg, msg.message, 0x2C);
			log.ret = retrieve_int(msg.message+ptr_msg, size);
			
			// retrieve format parameters 
			ptr_msg += size+1;
			size = getsize(ptr_msg, msg.message, 0x2C);
			log.fmt = malloc(size+1);
			log.fmt[size] = 0x0;
			memcpy(log.fmt, msg.message+ptr_msg, size);
			
			// retrieve arguments
			log.nb_arguments = strlen(log.fmt);
			if(log.nb_arguments)
				log.arguments = (PARAMETERS*)malloc(log.nb_arguments * sizeof(PARAMETERS));
			
			// for the moment, we only have 3 arguments/values maximum to log
			switch(log.nb_arguments)
			{
				case 0:
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,"");
				break;
				
				case 1:
					retrieve_parameters(log.nb_arguments, msg.message, ptr_msg, size, log.arguments);
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,log.fmt,log.arguments[0].arg,log.arguments[0].value);
				break;
				
				case 2:
					retrieve_parameters(log.nb_arguments, msg.message, ptr_msg, size, log.arguments);
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,log.fmt,log.arguments[0].arg,log.arguments[0].value,log.arguments[1].arg,log.arguments[1].value);
				break;
				
				case 3:
					retrieve_parameters(log.nb_arguments, msg.message, ptr_msg, size, log.arguments);
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,log.fmt,log.arguments[0].arg,log.arguments[0].value,log.arguments[1].arg,log.arguments[1].value,log.arguments[2].arg,log.arguments[2].value);
				
				case 4:
					retrieve_parameters(log.nb_arguments, msg.message, ptr_msg, size, log.arguments);
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,log.fmt,log.arguments[0].arg,log.arguments[0].value,log.arguments[1].arg,log.arguments[1].value,log.arguments[2].arg,log.arguments[2].value,log.arguments[3].arg,log.arguments[3].value);
				
				case 5:
					retrieve_parameters(log.nb_arguments, msg.message, ptr_msg, size, log.arguments);
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,log.fmt,log.arguments[0].arg,log.arguments[0].value,log.arguments[1].arg,log.arguments[1].value,log.arguments[2].arg,log.arguments[2].value,log.arguments[3].arg,log.arguments[3].value,log.arguments[4].arg,log.arguments[4].value);
				
				case 6:
					retrieve_parameters(log.nb_arguments, msg.message, ptr_msg, size, log.arguments);
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,log.fmt,log.arguments[0].arg,log.arguments[0].value,log.arguments[1].arg,log.arguments[1].value,log.arguments[2].arg,log.arguments[2].value,log.arguments[3].arg,log.arguments[3].value,log.arguments[4].arg,log.arguments[4].value,log.arguments[5].arg,log.arguments[5].value);
				
				case 7:
					retrieve_parameters(log.nb_arguments, msg.message, ptr_msg, size, log.arguments);
					i = log_resolve_index(log.funcname, 0);
					loq(log.g_sock,i,log.funcname,log.success,log.ret,log.fmt,log.arguments[0].arg,log.arguments[0].value,log.arguments[1].arg,log.arguments[1].value,log.arguments[2].arg,log.arguments[2].value,log.arguments[3].arg,log.arguments[3].value,log.arguments[4].arg,log.arguments[4].value,log.arguments[5].arg,log.arguments[5].value,log.arguments[6].arg,log.arguments[6].value);
			
				default:
					break;
			}			
			
			// if the log contains "ZwWriteFile" as function name, notifies cuckoo that a file has to be dumpped
			if(!strcmp(log.funcname, "ZwWriteFile") && !log.ret)
			{ 
				us_pathfile = (PUNICODE_STRING)malloc(1024*sizeof(UNICODE_STRING));
				pw_pathfile = (PWCHAR)malloc(1024*sizeof(WCHAR));
				mbstowcs(pw_pathfile, log.arguments[1].value, strlen(log.arguments[1].value)+1);
				RtlInitUnicodeString(us_pathfile, pw_pathfile);
				new_file(us_pathfile);
				free(us_pathfile);
				free(pw_pathfile);
			}
			
			// TODO
			if(!strcmp(log.funcname, "ZwDeleteFile") && !log.ret)
			{
				//pipe("FILE_DEL:%s", log.arguments[0].value);
			}
			if(log.procname)
			{
				free(log.procname);
				log.procname = NULL;
			}
			if(log.funcname)
			{
				free(log.funcname);
				log.funcname = NULL;
			}
			if(log.fmt)
			{
				free(log.fmt);
				log.fmt = NULL;
			}
			if(log.arguments)
			{
				free(log.arguments);
				log.arguments = NULL;
			}
		}
	}
}
