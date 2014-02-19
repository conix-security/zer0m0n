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
//	File :		parsing.c
//	Abstract :	logs parsing helpers
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr
//	Date :		2013-12-26	  
//	Notes : 	
//		
/////////////////////////////////////////////////////////////////////////////
#include <windows.h>
#include <stdlib.h>
#include "parsing.h"

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve size of the next string to be parsed in a log string
//	Parameters :
//		_in_ int index : position of the string in the log
//		_in_ char *msg : the log retrieved from the driver
//		_in_ char delimited : the character which determines the end of the string
//	Return value :
//		int : size of the string
//	Process :
//		count the number of characters of the string from its position until the delimited is found
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int getsize(int index, char *msg, char delimiter)
{
	int n=0;

	while(*(msg+index) != delimiter)
	{
		n++;	
		index++;
	}
	return n;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve each parameters/values from the log
//	Parameters :
//		_in_ int nb_arguments : number of arguments containing in the log
//		_in_ char *msg : the log retrieved from the driver
//		_in_ int ptr_msg : pointer to the format parameters strings
//		_in_ int size : size of format parameters strings
//	Return value :
//		PARAMETERS* :  structure with the arguments/values containing in the log
//	Process :
//		for each argument, retrieve the argument, its parameter and store them to a structure
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
void retrieve_parameters(int nb_arguments, char *msg, int ptr_msg, int size, PARAMETERS* tmp)
{
	int i = 0;

	for(i=0; i<nb_arguments; i++)
	{
		ptr_msg += size+1;
		size = getsize(ptr_msg, msg, 0x3E);
		tmp[i].arg = malloc(size);
		tmp[i].arg[size-1] = 0x0;
		memcpy(tmp[i].arg, msg+ptr_msg, size-1);
		ptr_msg += size+1;
		if( i == nb_arguments-1)
			size = getsize(ptr_msg, msg, 0x00);
		else
			size = getsize(ptr_msg, msg, 0x2C);
		tmp[i].value = malloc(size+1);
		tmp[i].value[size] = 0x0;
		memcpy(tmp[i].value, msg+ptr_msg, size);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Retrieve value of the next integer to be parsed in the log
//	Parameters :
//		_in_ char *msg : the log retrieved from the driver
//		_in_ int size : size of the string containing the integer
//	Return value :
//		int : the integer
//	Process :
//		convert the string (containing the integer to retrieved) to an integer and returns it
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
int retrieve_int(char *msg, int size)
{
	PCHAR tmp = NULL;
	DWORD n;
	tmp = malloc(size+1);
	memcpy(tmp, msg, size);
	tmp[size] = 0x0;
	n = atoi(tmp);
	free(tmp);
	return n;
}
