#pragma once

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
     WORD Type;
     WORD CreatorBackTraceIndex;
     PVOID CriticalSection;
     LIST_ENTRY ProcessLocksList;
     ULONG EntryCount;
     ULONG ContentionCount;
     ULONG Flags;
     WORD CreatorBackTraceIndexHigh;
     WORD SpareUSHORT;

} 	RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION
{
     PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
     LONG LockCount;
     LONG RecursionCount;
     PVOID OwningThread;
     PVOID LockSemaphore;
     ULONG SpinCount;
	 
} 	RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;