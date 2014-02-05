zer0m0n v0.3 (DEVELOPMENT BRANCH)
=================================

To-do :
+ Eliminate bugs :]
+ Cr0 reg trick => multiprocessor issues.
+ Get ZwCreateProcess* filename parameter
+ Use inverted IRP calls with kernel buffer instead of filter comm. ports :]
+ Add anti-detection features (cuckoo/VM files/process/reg/connections)
+ Hide thread listing
+ Handle machine poweroff
+ Handle driver execution (abort analysis)
+ Add monitored functions/events
+ Handle file deletion
+ Log registry callbacks return values
+ win7 x86 support
+ x64 support (get rid of SSDT hooks)
+ Handle SSDT hooks race conditions (perform legitimate calls with copied parameters)
+ etc.

v0.3 changes :
+ fix ZwTerminateProcess race condition (notify analyzer.py of process termination)
+ fix hook ZwDelayExecution => log the call before executing it
+ Signatures :]

v0.2 changes :
+ ZwDeviceIoControlFile hook
+ ZwCreateMutant hook
+ ZwDelayExecution hook
+ ZwTerminateProcess hook
+ Fixed deadlock issue (FltSendMessage infinite wait switched to 100ms timeout)
+ Fixed performance issues (drop) using userland app multithreading
