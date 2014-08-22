#pragma once

#include <fltkernel.h>
#include <ntddk.h>
#include <windef.h>

/**
 * Enumeration of the status error returned by a stack unwinding
 **/
typedef enum 
{
	// Expected behaviors :
	STACK_UNWIND_SUCCESS = 0,					// The stack unwinding succeeded without any error
	STACK_UNWIND_UNKNOWN_MODULE,				// The stack unwinding succeeded, but encountered an unknown module
	STACK_UNWIND_VM_DETECTED,					// A call from a VM module has been detected on the stack
	STACK_UNWIND_UNTRUSTED_CALLCHAIN,			// The call chain on the stack is abnormal and shouldn't be trusted
	STACK_UNWIND_BOTTOM_REACHED,				// The bottom of the stack has been reached

	// Errors during stack unwinding :
	STACK_UNWIND_INVALID_SFP,				 	// An invalid SFP address has been encountered, the stack unwinding stopped
	STACK_UNWIND_INVALID_RET_EIP,			 	// An invalid ret EIP address has been encountered, the stack unwinding stopped
	STACK_UNWIND_INVALID_MODULE_INFORMATION,	// The current process module information failed to be retrieved.
	
	// Internal states that shouldn't be returned
	STACK_UNWIND_CONTINUE,						// The stack unwinding is processing and not finished, request to continue
	
}	STACK_UNWIND_STATUS;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
//		Read the current process call stack, and detect if an address is outside of the modules
//
//	Parameters :
//		OUT PDWORD LastRetEip									Pointer to the value of the last RET_EIP encountered on the stack
//	Return value :
//		STACK_UNWIND_STATUS		The status of the stack unwinding (see the definition of STACK_UNWIND_STATUS enum)
//	Process :
//		
//		Read the stack value given in parameter in the current process
//		Loop until the current executable, an unknown module or the bottom of the stack have been reached
//		Return a status code according to the case encountered
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
STACK_UNWIND_STATUS
StackUnwind (
	OUT PDWORD LastRetEip
);


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description : 
// 		Handle the event when a unknown module is encountered
//
//	Parameters :
//		IN DWORD ModuleAddress		An EIP value positionned on the stack of the unknown module
//	Return value :
//		NTSTATUS	STATUS_SUCCESS on success, otherwise it returns an error status
//	Process :
//		
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
NTSTATUS
UnknownModuleHandler (
	IN DWORD ModuleAddress
);


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
);