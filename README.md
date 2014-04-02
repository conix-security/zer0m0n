zer0m0n v0.6 (DEVELOPMENT BRANCH)
=================================

To-do :
+ Eliminate bugs :]
+ Cr0 reg trick => multiprocessor issues.
+ Use inverted IRP calls with kernel buffer instead of filter comm. ports :]
+ Add monitored functions/events
+ x64 support (get rid of SSDT hooks)
+ fix random socket desynch
+ etc.

v0.6 changes :
+ handle files deletion (through NtDeleteFile(), NtCreateFile()/NtClose() via FILE_DELETE_ON_CLOSE and NtSetInformationFile()

v0.5 changes :
+ bug fixes
+ win7 support
+ NtCreateUserProcess() hook 
+ NtUserCallNoParam() hook 
+ NtCreateThreadEx() hook 

v0.4 changes :
+ more anti VM detection features
+ log new loaded modules through NtCreateSection hook 
+ handle shutdown attempt through ExitWindowsEx() in hooking NtUserCallOneParam() (shadow ssdt) => abort analysis

v0.3 changes :
+ fix minor bugs
+ fix NtTerminateProcess race condition (notify analyzer.py of process termination)
+ fix hook NtDelayExecution => log the call before executing it
+ Signatures :]
+ some anti VM (virtualbox) detection features (based on pafish PoC)
+ NtReadVirtualMemory hook
+ NtResumeThread hook
+ handle driver execution (abort analysis)

v0.2 changes :
+ NtDeviceIoControlFile hook
+ NtCreateMutant hook
+ NtDelayExecution hook
+ NtTerminateProcess hook
+ Fixed deadlock issue (FltSendMessage infinite wait switched to 100ms timeout)
+ Fixed performance issues (drop) using userland app multithreading
