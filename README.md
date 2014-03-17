zer0m0n v0.5
============

zer0m0n is a driver for Cuckoo Sandbox, it will perform kernel analysis during the execution of a malware. There are many ways for a malware author to bypass Cuckoo detection, he can detect the hooks, hardcodes the Nt* functions to avoid the hooks, detect the virtual machine... The goal of this driver is to offer the possibility for the user to choose between the classical userland analysis or a kernel analysis, which will be harder to detect or bypass.

Actually, it only works for XP 32 bit Windows machines, because of SSDT hooks usage ( :] ), but we plan supporting other OSes.

CHANGELOG
=========

v0.5
+ bug fixes
+ win7 support
+ ZwCreateUserProcess hook 
+ ZwUserCallNoParam hook
+ ZwCreateThreadEx hook

v0.4
+ bug fixes
+ more anti VM detection features
+ log new loaded modules through ZwCreateSection() hook
+ shadow ssdt hook
+ handle shutdown attempt through ExitWindowsEx() => abort analysis

v0.3
+ fix minor bugs
+ fix ZwTerminateProcess race condition (notify analyzer.py of process termination)
+ fix hook ZwDelayExecution (log the call before executing it)
+ signatures
+ some anti VM (virtualbox) detection features (based on pafish PoC)
+ ZwReadVirtualMemory hook
+ ZwResumeThread hook
+ handle driver execution (abort analysis)


v0.2
+ added ZwDeviceIoControlFile, ZwCreateMutant, ZwDelayExecution & ZwTerminateProcess SSDT hooks
+ fixed deadlock bug (inifinte wait on FltSendMessage)
+ fixed performance issues (drop => patched using multithreading in logs_dispatcher)

How it works
============

The driver logs kernel activity during a malware execution in hooking the SSDT, overwriting the pointers to new functions in order to log the calls and the parameters. It also takes advantage of the callbacks provided by the windows API to log registry operations and kernel components loading (drivers).

When submitting a new file to cuckoo and choosing the kernel analysis, Cuckoo (analyzer.py script) will start the process in a suspended state and send the PID to be monitored to the driver using an IOCTL. The driver will add it to its list of monitored processes and Cuckoo will then resume the execution of the malware.

For each activity traced by the driver (through the SSDT / callbacks) a log is produced and sent to a userland process ("logs_dispatcher.exe") using filter communication port. This one will be in charge of parsing the logs and send them to Cuckoo (analyzer.py) in bson format.

Code injections techniques are monitored by the driver: if a monitored process performs a known code-injection technique into another process, this process will be added to the monitored processes list.

DISCLAIMER
==========

As you must have seen (especially if you looked at the code), we're not really "production" driver developpers :]. This is an alpha release, and there are still several bugs. We're actually tracking and correcting them, and as soon as a critical bug (vuln or BSOD) is corrected, a Master commit is performed.

Thus, if you find:
- bugs
- bypassing techniques
- vulnerabilities
- new functions to monitor (or parameters)
- generic remarks about driver development
- beer

Please just let us know !!! :]

INSTALL/USE
===========

To patch cuckoo, you will need the files in the "bin" directory to patch cuckoo and prepare the host.

 1- First patch cuckoo using the .patch file, in order to support the driver.

    - copy "cuckoo.patch" to your cuckoo root directory
  
    - run "patch -p1 < ./cuckoo.patch"
  
    - copy the "logs_dispatcher.exe" and "zer0m0n.sys" files into your /cuckoo/analyzer/windows/dll/ folder
   
 2- Open your virtual machine, it MUST run a "Windows XP x86" OS

 3- Install ActivePython 2.7 (http://www.activestate.com/activepython/downloads)

 4- Run the "agent.py" script as usual

 5- Snapshot the VM

While submitting a new analysis, choose "kernelland" option on the Web interface, or use the option "kernel_analysis=yes" on commandline.

Updating zer0m0n: edit then use the /bin/update_cuckoo.sh to update your cuckoo+zer0m0n installation :]

SIGNATURES
==========

Signatures patterns have changed:

- for registry operations, handles are not logged anymore (use of callbacks instead of hooks). The full path of accessed keys is now logged and may be used directly, including on values operations
- for windows operations, there is no logging anymore
- for IOCTLs operations (including Winsock operations), ZwDeviceIoControlFile hook will be implemented soon (only userland calls) :]
- several other functions are not actually hooked and will be added later
- signatures based on "global" results (registry / files / mutexes / networking / ...) still work fine

COMPILATION
===========

Compile the driver sources with the Windows Driver Kit (WDK).
For the application, we use Visual C++ 2008 Express Edition, but you should be able to use other ones :]. Don't forget to include WDK librairies to be able to use the Filter Communication Port features.

FAQ
===

Q: Which injections techniques are handled by the driver ?

A: Known injection techniques are:

    - Process memory modification techniques (ZwWriteVirtualMemory, ZwMapViewOfSection)
    - Debugging techniques (ZwSetContextThread, ZwDebugActiveProcess)
    - New process/thread creation (ZwCreateProcess, ZwCreateThread)

Q: How do you "hide" cuckoo ?

A: For now, several processes are hidden/blocked, by pid filtering:

    - "python.exe" (cuckoo processes, analyzer.py / agent.py)
    - "logs_dispatcher.exe" (userland app, randomized name)

The zer0m0n driver is not hidden (its name is randomized), the service cannot be unloaded using ZwUnloadDriver (MiniFIlter driver spec).

Q: How do you handle the case where a malware will load a driver (and then be at the same level of your driver) and would possibly subvert the analysis ?

A: Well, this is in the to-do list :D. we can log when a new driver is loaded during the malware execution through PsSetLoadImageNotifyRoutine(), we planned to stop the analysis when we detect this behavior.

Q: How do you handle cukoo bypassing / VM detection techniques ?

A : There are really MANY ways to detect cuckoo or a virtual machine... Our thought is to handle known (and used into the wild) techniques, and to build post-analysis signatures to detect generic detection techniques and warn the user about possible detection/bypass. There must be also some ways to bypass zer0m0n and we'd want to block them all (we believe we can detect we're detected). Please try to bypass zer0m0n, this could be a really interresting cat&mouse game :]

TODO LIST
=========

It's a first release, and there are still a lof of improvements to do and features to implement.
You'll find a list of such improvements to come in our development branch.

Authors
=======
- Nicolas Correia
- Adrien Chevalier
