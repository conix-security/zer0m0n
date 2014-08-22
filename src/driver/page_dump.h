#ifndef __PAGE_DUMP_H
#define __PAGE_DUMP_H

#include <fltkernel.h>
#include <ntddk.h>
#include <windef.h>

/**
 *	PHYSICAL_PAGE_ENTRY is a structure containing the base address of the pages dumped
 *	Its purpose is to avoid dumping multiple times the same pages on the disk
 *	Everytime a page is dumped, an new entry is created and added to a list of these entries
 */
typedef struct _PHYSICAL_PAGE_ENTRY
{
	LIST_ENTRY Entry;
	PHYSICAL_ADDRESS PagePhysicalBaseAddress;

}	PHYSICAL_PAGE_ENTRY, *PPHYSICAL_PAGE_ENTRY;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Dump an entire physical page (size = PAGE_SIZE) containing a given virtual address
//
//	Parameters :
//		IN PVOID VirtualAddress					The virtual address contained by the page to dump
//		OUT PVOID *Buffer						A pointer to an unalloced piece of memory which will contain the page
//		OUT OPTIONAL PULONG BytesWritten		Number of bytes written
//	Return value :
//		PVOID : An allocated memory of 4KB containing the page dumped
//	Process :
//		Retrieve the physical base address of the page containing a given virtual address
//		Dump PAGE_SIZE bytes of memory starting at this address
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS
MapPhysicalPage (
	IN PVOID VirtualAddress,
	OUT PVOID *Buffer
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Save a physical page to the disk in a file
//
//	Parameters :
//		IN PVOID PhysicalPageData				An allocated buffer of PAGE_SIZE bytes containing the page to write in a file
//		IN PUNICODE_STRING FullPathDumpFile		The cuckoo file path name
//	Return value :
//		STATUS_SUCCESS if the file has been correctly created, otherwise return an error message
//	Process :
//		Open a file depending of the given filename
//		Write in this file the physical page given in the first argument
//		Close the file gracefully
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS
SavePhysicalPage (
	IN PVOID PhysicalPageData,
	IN PUNICODE_STRING FullPathDumpFile
);


/** Memory management functions **/
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Allocate a new physical page entry
//	Parameters :
//		IN PHYSICAL_ADDRESS PhysicalAddress		A physical address associated with the new entry
//	Return value :
//		PPHYSICAL_PAGE_ENTRY		An allocated PHYSICAL_PAGE_ENTRY, or NULL if an error occured
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PPHYSICAL_PAGE_ENTRY
AllocatePhysicalPageEntry (
	IN PHYSICAL_ADDRESS PhysicalAddress
);



//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Deallocate an already allocated physical page entry
//	Parameters :
//		IN PPHYSICAL_PAGE_ENTRY pPhysicalPageEntry		An allocated physical page entry to free
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID
FreePhysicalPageEntry (
	IN PPHYSICAL_PAGE_ENTRY pPhysicalPageEntry
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Deallocate an entire allocated physical pages list
//	Parameters :
//		Nothing
//	Return value :
//		None
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID
FreePhysicalPageList (
	VOID
);

#endif