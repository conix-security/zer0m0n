zer0m0n v0.5 (DEVELOPMENT BRANCH)
=================================

To-do :
+ Eliminate bugs :]
+ Cr0 reg trick => multiprocessor issues.
+ Use inverted IRP calls with kernel buffer instead of filter comm. ports :]
+ Add monitored functions/events
+ Handle file deletion
+ x64 support (get rid of SSDT hooks)
+ Handle SSDT hooks race conditions (perform legitimate calls with copied parameters)
+ fix random socket desynch
+ etc.

v0.5 changes :
+ fix bugs
+ windows 7 support
+ ZwCreateUserProcess() hook (win7)
+ ZwUserCallNoParam() hook (win7)
+ ZwCreateThreadEx() hook (win7)

v0.4 changes :
+ more anti VM detection features
+ log new loaded modules through ZwCreateSection hook 
+ handle shutdown attempt through ExitWindowsEx() in hooking NtUserCallOneParam() (shadow ssdt) => abort analysis

v0.3 changes :
+ fix minor bugs
+ fix ZwTerminateProcess race condition (notify analyzer.py of process termination)
+ fix hook ZwDelayExecution => log the call before executing it
+ Signatures :]
+ some anti VM (virtualbox) detection features (based on pafish PoC)
+ ZwReadVirtualMemory hook
+ ZwResumeThread hook
+ handle driver execution (abort analysis)

v0.2 changes :
+ ZwDeviceIoControlFile hook
+ ZwCreateMutant hook
+ ZwDelayExecution hook
+ ZwTerminateProcess hook
+ Fixed deadlock issue (FltSendMessage infinite wait switched to 100ms timeout)
+ Fixed performance issues (drop) using userland app multithreading
