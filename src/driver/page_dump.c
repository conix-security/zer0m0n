////////////////////////////////////////////////////////////////////////////
//
//	zer0m0n DRIVER
//
//  Copyright 2014 Conix Security, Nicolas Correia, Adrien Chevalier, Cyril Moreau
//
//  This file is part of zer0m0n.
//
//  Zer0m0n is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  Zer0m0n is distibuted in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with Zer0m0n.  If not, see <http://www.gnu.org/licenses/>.
//
//
//	File :		page_dump.c
//	Abstract :	Physical page dumping to a file
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia & Cyril Moreau
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr cyril.moreau@conix.fr
//	Date :		2014-08-22	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#include "page_dump.h"
#include "main.h"

// List head of the physical pages dumped
PLIST_ENTRY pPhysicalPageListHead = NULL;

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
) {
	PMDL pMdl;
	PHYSICAL_ADDRESS PhysicalAddress;

	// Check the validity of the virtual address
	if (!MmIsAddressValid (VirtualAddress)) {
		Dbg ("MmIsAddressValid failed (0x%08X)", VirtualAddress);
		return STATUS_UNSUCCESSFUL;
	}

	/* A 32 bits virtual address is composed by the following components on x86 systems :
		[       10 bits      ] [     10 bits    ] [    12 bits    ]
	    [Page directory index] [Page table index] [  Byte index   ]
		Thus we know that the physical base address of that page is localised at the byte index 0.
		Instead of zeroing the last 3 bytes, we retrieve the virtual base address of that page in the "StartVa" _MDL structure member
	*/
	pMdl = IoAllocateMdl (VirtualAddress, PAGE_SIZE, FALSE, FALSE, NULL);
	PhysicalAddress = MmGetPhysicalAddress (pMdl->StartVa);
	IoFreeMdl (pMdl);

	// Map the physical memory to a kernel buffer
	if ((*Buffer = MmMapIoSpace (PhysicalAddress, PAGE_SIZE, MmCached)) == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Save a physical page to the disk in a file
//
//	Parameters :
//		IN PVOID PhysicalPageData				An allocated buffer containing the data to write in a file
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
) {
	NTSTATUS Status;
	OBJECT_ATTRIBUTES ObjectAttributes = {0};
	IO_STATUS_BLOCK IoStatusBlock = {0};
	HANDLE hFile   = NULL;

	Dbg ("Attempting to dump %ws ...", FullPathDumpFile->Buffer);
	
	InitializeObjectAttributes (&ObjectAttributes, FullPathDumpFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		
	// Open file
	if (!NT_SUCCESS (Status = ZwCreateFile (
		&hFile,	SYNCHRONIZE | GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE,
		&ObjectAttributes, &IoStatusBlock, NULL, 
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, 
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT, 
		NULL, 0))
	) {
		Dbg ("ZwCreateFile failed (%ws) (0x%08X)", FullPathDumpFile->Buffer, Status);
		return Status;
	}

	// Write file
	if (!NT_SUCCESS (Status = ZwWriteFile (
		hFile, NULL, NULL, NULL, &IoStatusBlock,
		PhysicalPageData,			// Write the physical page data received as argument
		PAGE_SIZE, NULL, NULL))
	) {
		Dbg ("ZwWriteFile failed (%ws) (0x%08X)\n", FullPathDumpFile->Buffer, Status);
		return Status;
	}

	// Close file
	if (!NT_SUCCESS (Status = ZwClose (hFile))) {
		Dbg ("ZwClose failed (%ws) (0x%08X)\n", FullPathDumpFile->Buffer, Status);
		return Status;
	}

	Dbg ("Physical page dumped !");
	
	return STATUS_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
//		Try to add a physical address to the list of physical address dumped.
//		Doesn't do anything if the physical address already exists in the list
//	Parameters :
//		IN PHYSICAL_ADDRESS PhysicalAddress			The physical address to check
//	Return value :
//		TRUE if the entry didn't already exist, and it has been correctly added in the list.
//		Otherwise, return FALSE if the entry already exists or if an error occured
//	Process :
//		Allocate a new PHYSICAL_PAGE_ENTRY
//		Iterate through the PHYSICAL_PAGE_ENTRY list to check if the given physical address already exist
//		If it doesn't, add the new entry to the list
//		If it does, do nothing
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL
AddPhysicalPageToList (
	IN PHYSICAL_ADDRESS PhysicalAddress
) {
	PLIST_ENTRY pListEntry;
	PPHYSICAL_PAGE_ENTRY pCurEntry, pPhysicalPageEntry;

	if (pPhysicalPageListHead == NULL) {
		// Head entry undifined, initialize the pPhysicalPageListHead to the last allocated entry
		if ((pPhysicalPageEntry = AllocatePhysicalPageEntry (PhysicalAddress)) != NULL) {
			InitializeListHead (&pPhysicalPageEntry->Entry);
			pPhysicalPageListHead = &pPhysicalPageEntry->Entry;
		} else {
			return FALSE;
		}
	} else {
		// Verify if the entry doesn't already exist, if it does, return an error
		// Iterate through the PHYSICAL_PAGE_ENTRY list :
		pListEntry = pPhysicalPageListHead->Flink;
		do {
			pCurEntry = CONTAINING_RECORD (pListEntry, PHYSICAL_PAGE_ENTRY, Entry);
			if ((pCurEntry->PagePhysicalBaseAddress.HighPart == PhysicalAddress.HighPart)
			&&  (pCurEntry->PagePhysicalBaseAddress.LowPart  == PhysicalAddress.LowPart)
			) {
				// It already exists : return false
				return FALSE;
			}

			// Iterate to the next entry
			pListEntry = pListEntry->Flink;
			
		} while (pListEntry != pPhysicalPageListHead);
		
		// It doesn't exist, add the new entry to the head of the list
		if ((pPhysicalPageEntry = AllocatePhysicalPageEntry (PhysicalAddress)) != NULL) {
			InsertHeadList (pPhysicalPageListHead, &pPhysicalPageEntry->Entry);
		} else {
			return FALSE;
		}
	}

	return TRUE;
}


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
) {
	PPHYSICAL_PAGE_ENTRY pPhysicalPageEntry = NULL;
	
	// Memory allocation
	if ((pPhysicalPageEntry = ExAllocatePoolWithTag (NonPagedPool, sizeof (PHYSICAL_PAGE_ENTRY), 'APPE')) == NULL) {
		Dbg ("ExAllocatePoolWithTag failed\n");
		return NULL;
	}

	pPhysicalPageEntry->PagePhysicalBaseAddress = PhysicalAddress;

	return pPhysicalPageEntry;
}


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
) {
	ExFreePool (pPhysicalPageEntry);
}


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
) {
	PLIST_ENTRY pListEntry, pNextEntry;
	PPHYSICAL_PAGE_ENTRY pCurEntry;
	
	// Check if the list is not empty
	if (pPhysicalPageListHead != NULL) {
		// Iterate through the PHYSICAL_PAGE_ENTRY list
		pListEntry = pPhysicalPageListHead->Flink;
		do {
			pCurEntry = CONTAINING_RECORD (pListEntry, PHYSICAL_PAGE_ENTRY, Entry);
			pNextEntry = pListEntry->Flink;
			
			FreePhysicalPageEntry (pCurEntry);
			
			// Iterate to the next entry
			pListEntry = pNextEntry;

		} while (pListEntry != pPhysicalPageListHead);

		pPhysicalPageListHead = NULL;
	}
}

