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
//	File :		stack_unwind.c
//	Abstract :	Stack unwinding
//	Revision : 	v1.0
//	Author :	Adrien Chevalier & Nicolas Correia & Cyril Moreau
//	Email :		adrien.chevalier@conix.fr nicolas.correia@conix.fr cyril.moreau@conix.fr
//	Date :		2014-08-22	  
//	Notes : 	
//
/////////////////////////////////////////////////////////////////////////////
#include "stack_unwind.h"
#include "module.h"
#include "query_information.h"
#include "page_dump.h"
#include "hook.h"
#include "main.h"
#include "comm.h"

#include <ntstrsafe.h>

/**
 *    Indexes of the values read on the stack
 **/
enum ValuesIndex 
{
    STACK_SFP,					// Saved EBP pushed on the stack by a push ebp instruction
    STACK_RET_EIP,				// Saved instruction address pushed by a call instruction
    STACK_KITRAP_MARKER,		// Marker set on the stack by a nt!KiTrap* (mov dword ptr [ebp+8], 0xbadb0d00)
    STACK_KFS_CALLER,			// Address pushed by the call [edx] in the Nt* functions before the sysenter

    STACK_INDEXES_COUNT			// Keep STACK_INDEXES_COUNT always at the end of this enum list
};

/**
 *    Structure containing information about the current inspected frame
 *    Everytime the stack is unwinded, this structure is filled with new information
 */
typedef struct _STACK_FRAME_INFORMATION
{
    DWORD Values [STACK_INDEXES_COUNT];      // Values of the stack in the current frame
    PMODULE_ENTRY ModuleEntry;               // Module associated with the current frame
    DWORD LastRetEip;                        // Value of the last valid EIP read on the current frame

}    STACK_FRAME_INFORMATION, *PSTACK_FRAME_INFORMATION;

/**
 *    Structure containing general information of the stack unwinding process
 */
typedef struct _STACK_UNWIND_INFORMATION 
{
    PMODULE_INFORMATION_TABLE pModuleInformationTable;   // Information concerning all the modules of the current process
    STACK_FRAME_INFORMATION Frame;                       // Information concerning the current frame unwinded

    BOOLEAN InKernelModule;                              // TRUE if the current module unwinded is a kernel module
    BOOLEAN JustEnteredInUserModule;                     // TRUE if the current module is a user module and the previous one 
                                                         // is a kernel module
}	STACK_UNWIND_INFORMATION, *PSTACK_UNWIND_INFORMATION;

// Static prototypes
static BOOLEAN ReadStack (IN PSTACK_UNWIND_INFORMATION StackUnwindInformation, IN DWORD StackFrameBase, IN ULONG Size);
static BOOLEAN TrustedCallChain (IN PSTACK_UNWIND_INFORMATION StackUnwindInformation);
static BOOLEAN VmModuleDetect (IN PSTACK_UNWIND_INFORMATION StackUnwindInformation);
static STACK_UNWIND_STATUS UpdateStackUnwindInformation (IN PSTACK_UNWIND_INFORMATION StackUnwindInformation, IN DWORD StackFrameBase);
static void DebugStackFrame (IN PSTACK_FRAME_INFORMATION Frame);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Description : 
//        Check if the call chain is legit
//    Parameters :    
//        IN PSTACK_UNWIND_INFORMATION StackUnwindInformation        Information about the stack unwinding
//    Return value :
//        TRUE if the call chain is legit, FALSE otherwise
//    Process :
//        Check if the current frame is created from a user module and the previous one from a kernel module
//        In that case, read the retEIP pushed on the stack by the system call (Nt*) before KiFastSystemCall
//		  If the module containing this IP is not ntdll.dll, raise an alert
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
static BOOLEAN
TrustedCallChain (
    IN PSTACK_UNWIND_INFORMATION StackUnwindInformation
) {
    DWORD Sfp          = StackUnwindInformation->Frame.Values[STACK_SFP];
    DWORD RetEip       = StackUnwindInformation->Frame.Values[STACK_RET_EIP];
	DWORD KiTrap       = StackUnwindInformation->Frame.Values[STACK_KITRAP_MARKER];
	DWORD KfsCaller    = StackUnwindInformation->Frame.Values[STACK_KFS_CALLER];
    DWORD ModuleOffset = StackUnwindInformation->Frame.Values[STACK_RET_EIP] 
					   - (DWORD) StackUnwindInformation->Frame.ModuleEntry->BaseAddress;
    PMODULE_ENTRY ModuleEntry = StackUnwindInformation->Frame.ModuleEntry;
	DWORD SysCaller;
	DWORD OldValue;
	PMODULE_ENTRY SysCallerModule;

    if (StackUnwindInformation->JustEnteredInUserModule)
	{
		OldValue = StackUnwindInformation->Frame.Values[0];

		// Read on the stack a DWORD at (KfsCaller - 8), corresponding to the system call caller
		if (!ReadStack (StackUnwindInformation, KfsCaller - (2 * sizeof(DWORD)), 1)) {
			Dbg ("Invalid KfsCaller = 0x%08X.", KfsCaller);
			return FALSE;
		}

		SysCaller = StackUnwindInformation->Frame.Values[0];
		StackUnwindInformation->Frame.Values[0] = OldValue;

		// Get the module information of the system caller
		if ((SysCallerModule = GetModuleTableEntry (SysCaller, StackUnwindInformation->pModuleInformationTable)) == NULL) {
			Dbg ("KfsCaller module not found = 0x%08X.", SysCaller);
			StackUnwindInformation->Frame.LastRetEip = SysCaller;
			return FALSE;
		}

		// Check if the system caller is ntdll (it should be)
		if (SysCallerModule != StackUnwindInformation->pModuleInformationTable->NtdllModule) {
			Dbg ("SysCallerModule should be ntdll.");
			StackUnwindInformation->Frame.LastRetEip = SysCaller;
			DebugModuleTableEntry (SysCallerModule);
			return FALSE;
		}
    }

    return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Description : 
//        Attemp to detect VM modules
//    Parameters :
//        IN PSTACK_UNWIND_INFORMATION StackUnwindInformation        Information about the stack unwinding
//    Return value :
//        BOOLEAN 	TRUE if a VM module is detected, FALSE otherwise
//    Process :
//        Return the result of the DLL name string comparison for a .NET module
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
static BOOLEAN
VmModuleDetect (
    IN PSTACK_UNWIND_INFORMATION StackUnwindInformation
) {
    PMODULE_ENTRY ModuleEntry = StackUnwindInformation->Frame.ModuleEntry;

    // Detect .NET modules (case insensitive string comparison)
    if ((_wcsicmp(ModuleEntry->BaseName.Buffer, L"mscoree.dll") == 0)
    ||  (_wcsicmp(ModuleEntry->BaseName.Buffer, L"mscorwks.dll") == 0)
    ||  (_wcsicmp(ModuleEntry->BaseName.Buffer, L"mscorlib.ni.dll") == 0)
    ||  (_wcsicmp(ModuleEntry->BaseName.Buffer, L"System.ni.dll") == 0)
    ||  (_wcsicmp(ModuleEntry->BaseName.Buffer, L"Microsoft.VisualBasic.ni.dll") == 0)
    ||  (_wcsicmp(ModuleEntry->BaseName.Buffer, L"System.Windows.Forms.ni.dll") == 0)
    ) {
        return TRUE;
    }

    return FALSE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Description : 
//        Read a portion of the current process stack
//    Parameters :
//        IN OUT PSTACK_UNWIND_INFORMATION StackUnwindInformation        Information about the stack unwinding
//        IN DWORD StackFrameBase                                        The stack address to read
//    	  IN ULONG Size													 Number of elements to read
//    Return value :
//        BOOLEAN        TRUE if the stack has been correctly read, FALSE otherwise
//    Process :
//        Read the stack values according to the parameters in the current process
//        Return a boolean success or failure
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
static BOOLEAN
ReadStack (
    IN PSTACK_UNWIND_INFORMATION StackUnwindInformation,
    IN DWORD StackFrameBase,
	IN ULONG Size
) {
    //                     |    ...    |
    //    StackFrameBase = |    SFP    | <--- Values[STACK_SFP]
    //                     |    EIP    | <--- Values[STACK_RET_EIP]
    //                     |    ...    |
    __try {
        // Check the readability of this user-mode buffer
        if (StackFrameBase < MmUserProbeAddress) {
            // Raise an EXCEPTION_EXECUTE_HANDLER on error
            ProbeForRead ((CONST PVOID) StackFrameBase, Size, sizeof (DWORD));
        }

        if (!MmIsAddressValid ((void *) StackFrameBase)) {
            // StackFrameBase is invalid and shouldn't be read
            Dbg ("The stack address 0x%08X is invalid and may cause a PAGE_FAULT_IN_NONPAGED_AREA error.", StackFrameBase);
            return FALSE;
        }

        // The address is valid, proceed to read the values
        RtlCopyMemory (StackUnwindInformation->Frame.Values, (void *) StackFrameBase, Size * sizeof (DWORD));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // ProbeForRead failed, StackFrameBase is invalid and shouldn't be read
        Dbg ("Stack reading failed (0x%08X).", StackFrameBase);
        return FALSE;
    }

    return TRUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Description : 
//        Update the states of the STACK_UNWIND_INFORMATION structure
//    Parameters :
//        IN PSTACK_UNWIND_INFORMATION StackUnwindInformation            Information about the stack unwinding
//        IN DWORD StackBase                                             Stack base address of the current frame
//    Return value :
//        STACK_UNWIND_STATUS     	Status of the stack unwinding of the current frame
//    Process :
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
static STACK_UNWIND_STATUS
UpdateStackUnwindInformation (
    IN PSTACK_UNWIND_INFORMATION StackUnwindInformation,
    IN DWORD StackFrameBase
) {
    // Check if the bottom of the stack has been reached 
    // The bottom of the stack generally contains 0x00000000 or 0x00000030
    if (StackFrameBase == 0x00 || StackFrameBase == 0x30) {
        return STACK_UNWIND_BOTTOM_REACHED;
    }

    // Read the values from the stack
    if (!ReadStack (StackUnwindInformation, StackFrameBase, STACK_INDEXES_COUNT)) {
        return STACK_UNWIND_INVALID_SFP;
    }

    // Check if the bottom of the stack has been reached 
    // The returned EIP is egal to 0 in some cases
    if (StackUnwindInformation->Frame.Values[STACK_RET_EIP] == 0x00) {
        return STACK_UNWIND_BOTTOM_REACHED;
    }

	// Update the last valid RetEIP
	StackUnwindInformation->Frame.LastRetEip = StackUnwindInformation->Frame.Values[STACK_RET_EIP];

    // Check the if the current module is still a kernel module
    if (StackUnwindInformation->InKernelModule) {
        if (StackUnwindInformation->Frame.Values[STACK_SFP] < MmUserProbeAddress) {
            // We've just entered in a user module, update the states accordingly
            StackUnwindInformation->InKernelModule = FALSE;
            StackUnwindInformation->JustEnteredInUserModule = TRUE;
        }
    } else {
        StackUnwindInformation->JustEnteredInUserModule = FALSE;
    }

    // Check if the EIP returned is a valid address
    if (!MmIsAddressValid ((void *) StackUnwindInformation->Frame.Values[STACK_RET_EIP])) {
		Dbg ("Invalid RetEip : 0x%08X", StackUnwindInformation->Frame.Values[STACK_RET_EIP]);
        return STACK_UNWIND_INVALID_RET_EIP;
    }

    // Retrieve information about the current module entry
    // If the address isn't contained in any known module and is contains a valid content, stop the unwinding
    if (!(StackUnwindInformation->Frame.ModuleEntry = GetModuleTableEntry (
        StackUnwindInformation->Frame.Values[STACK_RET_EIP], 
        StackUnwindInformation->pModuleInformationTable))
    ) {
		if (StackUnwindInformation->Frame.Values[STACK_RET_EIP] < MmUserProbeAddress) {
			// Check the readability of this user-mode buffer
			__try {
				ProbeForRead ((CONST PVOID) StackUnwindInformation->Frame.Values[STACK_RET_EIP], 1, sizeof (DWORD));
				// The content is valid thus the module is unknown, an alert must be returned
				return STACK_UNWIND_UNKNOWN_MODULE;
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// ProbeForRead failed
				return STACK_UNWIND_INVALID_RET_EIP;
			}
		} else {
			// The unknown module is detected as a system module.
			// We cannot test its readability since kernel buffers are always trusted
			// Assume it is an unknown module just in case it isn't a false positive
			return STACK_UNWIND_UNKNOWN_MODULE;
		}
    }
    
    // Detect legit VM modules
    // If a VM is detected, stop the unwinding
    if (VmModuleDetect (StackUnwindInformation)) {
        return STACK_UNWIND_VM_DETECTED;
    }

    // Check if the call chain is trusted
    // If an untrusted call chain is met, stop the unwinding
    if (!TrustedCallChain (StackUnwindInformation)) {
        return STACK_UNWIND_UNTRUSTED_CALLCHAIN;
    }

    // Detect if the address is located in the base image module
    // In that case, stop the unwinding successfully
    if (AddressInModuleTableEntry (
        StackUnwindInformation->Frame.Values[STACK_RET_EIP], 
        StackUnwindInformation->pModuleInformationTable->ImageModule)
    ) {
        return STACK_UNWIND_SUCCESS;
    }

    // Print the information of the current frame
	// DebugStackFrame (&StackUnwindInformation->Frame);
	
    return STACK_UNWIND_CONTINUE;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Description : 
//        Read the current process call stack, and detect if an address is outside of the modules
//
//    Parameters :
//        OPT OUT PDWORD LastRetEip    Pointer to the value of the last RET_EIP encountered on the stack, or NULL 
//                                     if not necessary
//    Return value :
//        STACK_UNWIND_STATUS          The status of the stack unwinding (see the definition of STACK_UNWIND_STATUS enum)
//    Process :
//        Get the module information of the current process
//        Read the stack value given in parameter in the current process
//        Loop until the current executable, an unknown module or the bottom of the stack have been reached
//        Return a status code according to the case encountered
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
STACK_UNWIND_STATUS
StackUnwind (
    OUT PDWORD LastRetEip
) {
    /**
    *    Principle of the stack unwinding process with a demonstration of a simple instance :
    *    Below, the state of the stack when a "NtOpenProcess" is hooked from the kernel from a legit software.
    *    The EBP initial value is f760ad4c.
    *
    *      Stack      Value
    *    f760ad4c-->f760ad64---. <----- SFP pushed by nt!NtClose+0x3
    *    f760ad50 | 8053d638   | <----- EIP pushed by nt!KiFastCallEntry+0xf6
    *    f760ad54 | 0022ff28   |
    *    f760ad58 | 001f0fff   |
    * .------------------------'
    * |  f760ad5c | 0022fef8
    * |  f760ad60 | 0022ff10
    * `->f760ad64-->0022ff18---.
    *    f760ad68 | 7c90e4f4   | <----- EIP pushed by the SYSENTER (KiFastSystemCall) in ntdll.dll | KERNEL SPACE
    *             |            |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+- - - - - - -
    * .------------------------'                                                                   |   USER SPACE
    * |           |
    * `->0022FF18-->0022FF48---.
    *    0022FF1C | 0040145E   |        RETURN from kernel32.OpenProcess to 0040145E
    *    0022FF20 | 001F0FFF   |        Access = PROCESS_ALL_ACCESS
    *    0022FF24 | 00000000   |        InheritHandle = FALSE
    *    0022FF28 | 000004E4   V        ProcessID = 4E4
    *                        [...]
    *
    *    0040145E = We reached the module base image, stop the unwinding and return a success status
    */

    STACK_UNWIND_INFORMATION StackUnwindInformation;
	STACK_UNWIND_STATUS UnwindStatus = STACK_UNWIND_CONTINUE;
    DWORD StackFrameBase;

	// Initialize STACK_UNWIND_INFORMATION structure
    // Assume that the current module is a kernel module
    StackUnwindInformation.InKernelModule = TRUE;
    StackUnwindInformation.JustEnteredInUserModule = FALSE;

    // Get the module information of the current process
    if (!(StackUnwindInformation.pModuleInformationTable = QueryModuleInformationCurrentProcess())) {
        return STACK_UNWIND_INVALID_MODULE_INFORMATION;
    }

    // Start the unwinding with the current EBP value
    __asm {mov StackFrameBase, ebp};

    // Loop until the current executable module, an unknown module or the bottom of the stack has been reached
    while (UnwindStatus == STACK_UNWIND_CONTINUE) 
    {
        // Update the information concerning the current frame
		UnwindStatus = UpdateStackUnwindInformation (&StackUnwindInformation, StackFrameBase);

		// Iterate to the next frame
		StackFrameBase = StackUnwindInformation.Frame.Values[STACK_SFP];
    }

    // Cleaning
    FreeModuleInformationTable (StackUnwindInformation.pModuleInformationTable);

    // Return results
    *LastRetEip = StackUnwindInformation.Frame.LastRetEip;
	
    return UnwindStatus;
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//    Description : 
//        Generic stack unwinding handler
//
//    Parameters :
//        IN OPT PCHAR FunctionName        The name of the function calling the stack unwinding
//    Return value :
//        Nothing
//    Process :
//        Checks if the hooked process is one of the processes monitored
//        Call StackUnwind and handle the status code returned
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
VOID
GenericStackUnwind (
    IN PCHAR FunctionName
) {
    DWORD LastRetEip;
	STACK_UNWIND_STATUS UnwindStatus;
	
	// Optional function name parameter
	if (FunctionName == NULL) {
		FunctionName = "(UnknownFunc)";
	}

	switch (UnwindStatus = StackUnwind (&LastRetEip)) 
	{
		case STACK_UNWIND_SUCCESS :
			Dbg ("%s called by 0x%08X.", FunctionName, LastRetEip);
		break;

		case STACK_UNWIND_UNKNOWN_MODULE :
			// The function has been called from an unknown module
			Dbg ("%s was called from an unknown module (RetEip=0x%08X).", 
				FunctionName, LastRetEip);
			// Handle this event
			UnknownModuleHandler (LastRetEip);
		break;

		case STACK_UNWIND_VM_DETECTED:
			Dbg ("%s called by a .NET module in 0x%08X.", FunctionName, LastRetEip);
		break;

		case STACK_UNWIND_UNTRUSTED_CALLCHAIN:
			Dbg ("%s called by an untrusted call chain (RetEip=0x%08X).", 
				FunctionName, LastRetEip);
			// Handle this event the same way than an unknown module
			UnknownModuleHandler (LastRetEip);
		break;

		case STACK_UNWIND_INVALID_SFP :
		case STACK_UNWIND_INVALID_RET_EIP :
		case STACK_UNWIND_INVALID_MODULE_INFORMATION :
			// The stack unwinding failed because a value on the stack is invalid
			Dbg ("The stack unwinding of \"%s\" failed (RetEip=0x%08X) (Status=%x)", 
				FunctionName, LastRetEip, UnwindStatus);
		break;

		case STACK_UNWIND_BOTTOM_REACHED :
			Dbg ("%s called by 0x%08X. Stack bottom reached.", FunctionName, LastRetEip);
		break;

		default:
			Dbg ("/!\\ Unknown stack unwinding state encountered. /!\\");
		break;
	}
}


#define DUMP_FULL_PATH			L"%s\\0x%08X-0x%08X.dump"
#define DUMP_FULL_PATH_SIZE		(MAX_PATH + sizeof("\\0x00000000-0x00000000.dump"))
#define DUMP_LOG_PARAM			L"1,0,s,FileName->%ws"
#define	DUMP_LOG_PARAM_SIZE		(MAX_PATH + sizeof("1,0,s,FileName->"))
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		Handle the event when a unknown module is encountered
//
//	Parameters :
//		IN DWORD ModuleAddress		An EIP value positionned on the stack of the unknown module
//	Return value :
//		NTSTATUS	STATUS_SUCCESS on success, otherwise it returns an error status
//	Process :
//		Map the physical page to a kernel buffer, depending of the ModuleAddress parameter
//		Allocate a file path string
//		Save the kernel buffer to the disk
//		Format the log parameter and send a log about the event
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS
UnknownModuleHandler (
	IN DWORD ModuleAddress
) {
	NTSTATUS Status;
	PVOID PhysicalPageData;
	UNICODE_STRING FullpathUnicode;
	WCHAR FullPathWide [DUMP_FULL_PATH_SIZE + 1];
	WCHAR LogParameter [DUMP_LOG_PARAM_SIZE + 1];

	// Map physical page -> kernel buffer (PhysicalPageData)
	if (!NT_SUCCESS (Status = MapPhysicalPage ((PVOID) ModuleAddress, &PhysicalPageData))) {
		Dbg ("DumpPhysicalPage 0x%08X failed.", ModuleAddress);
		return Status;
	}

	// Format the path of the destination file
	RtlStringCchPrintfW (FullPathWide, MAX_PATH, DUMP_FULL_PATH, cuckooPath, ModuleAddress, ModuleAddress + PAGE_SIZE);
	RtlInitUnicodeString (&FullpathUnicode, FullPathWide);

	// Save the physical page to the disk
	if (!NT_SUCCESS (Status = SavePhysicalPage (PhysicalPageData, &FullpathUnicode))) {
		Dbg ("SavePhysicalPage failed. (@=0x%08X, code=0x%08X)", ModuleAddress, Status);

		// Cleaning
		MmUnmapIoSpace (PhysicalPageData, PAGE_SIZE);
		return Status;
	}

	// Cleaning
	MmUnmapIoSpace (PhysicalPageData, PAGE_SIZE);
	Dbg ("Page dumped. (@=0x%08X)", ModuleAddress);

	// Format the parameter sent to the logs
	if (!NT_SUCCESS (Status = RtlStringCchPrintfW (LogParameter, MAX_PATH, DUMP_LOG_PARAM, FullpathUnicode.Buffer))) {
		Dbg ("RtlStringCchPrintfW failed. (%s)", FullpathUnicode.Buffer);
		return Status;
	}

	// Send logs
	if (!NT_SUCCESS (Status = sendLogs ((ULONG) PsGetCurrentProcessId(), L"DumpPage", LogParameter))) {
		Dbg ("sendLogs failed. (%s)", LogParameter);
		return Status;
	}

	return STATUS_SUCCESS;
}
#undef DUMP_FULL_PATH
#undef DUMP_FULL_PATH_SIZE
#undef DUMP_LOG_PARAM
#undef DUMP_LOG_PARAM_SIZE


/// Debugging function
static void
DebugStackFrame (
	IN PSTACK_FRAME_INFORMATION Frame
) {
	Dbg ("0x%08X [%ws+0x%X]",
		Frame->Values[STACK_RET_EIP],
		(Frame->ModuleEntry != NULL) ? 
			Frame->ModuleEntry->BaseName.Buffer : L"?????",
		(Frame->ModuleEntry != NULL) ? 
			Frame->Values[STACK_RET_EIP] - (DWORD) Frame->ModuleEntry->BaseAddress : 0
	);
}
	
