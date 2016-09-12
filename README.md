# basic-rootkit
I posted this *very basic* rootkit (and old) on github only for *educational* purpose and is no longer usable on modern linux system.


In the first part the rootkit just sets parameter for creating a characters driver. 

In the second part (most interesting) the rootkit is reading the System.map-* file for getting memory address of the sys_call_table symbol. When found, a hook is set on the syscall __NR_open (after disabling cr0 bit).

Then, if a userland process call the "open" function with the adequate parameter (in my case it's /tmp/pwn), so the process gain root privileges. 
