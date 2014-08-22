#pragma once


typedef struct RTL_DRIVE_LETTER_CURDIR
{
    USHORT              Flags;
    USHORT              Length;
    ULONG               TimeStamp;
    UNICODE_STRING      DosPath;
	
} 	RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
