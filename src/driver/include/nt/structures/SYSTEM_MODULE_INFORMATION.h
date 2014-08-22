#pragma once

#include "SYSTEM_MODULE_ENTRY.h"

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG               	ModulesCount;
	SYSTEM_MODULE_ENTRY		Modules[0];
	
} 	SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
