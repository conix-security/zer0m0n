zer0m0n v0.2 (DEVELOPMENT BRANCH)
=================================

Changes :
+ ZwDeviceIoControlFile hook
+ ZwCreateMutant hook
+ ZwDelayExecution hook
+ ZwTerminateProcess hook
+ Fixed deadlock issue (FltSendMessage infinite wait switched to 100ms timeout)
+ Fixed performance issues (drop) using userland app multithreading

Todo :
+ Use inverted IRP calls with kernel buffer instead of filter comm. ports :]
