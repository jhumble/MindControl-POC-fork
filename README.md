![MindControl](Screenshots/mindcontrol.png)

# MindControl-POC
Abusing RtlRemoteCall to control a victim process into performing local shellcode injection.

---

## Credits
A big part of this proof-of-concept is the use of the ApiReeKall technique taught in Reenz0h's [Sektor7 Institute](https://institute.sektor7.net/) MalDev Advanced Vol. 1 course. I can't recommend those courses enough!

---
## Idea
After learning how RtlRemoteCall works and how Reenz0h was able to abuse it to perform any API calls regardless of how many arguments need to be passed (by default RtlRemoteCall only allows 4 arguments), I started playing around with it to see what else could be done. A few late nights later, I was able to successfully use RtlRemoteCall to instruct a process to perform local shellcode injection.

---

## How it works

```
RtlRemoteCall (
    HANDLE Process,
    HANDLE Thread,
    PVOID CallSite,
    ULONG ArgumentCount,
    PULONG_PTR Arguments,
    BOOLEAN PassContext,
    BOOLEAN AlreadySuspended
    )
```

The ApiReeKall technique subverts the typical usage of RtlRemoteCall by passing a memory buffer containing a large amount of API calls stored within a struct into the `PULONG_PTR Arguments` argument. Once the RtlRemoteCall executes, the APIs and their corresponding arguments placed in that memory buffer are executed. This allows us to execute multiple APIs with a single RtlRemoteCall.

The APIs executed by the victim process from RtlRemoteCall in this POC are listed below in order:
 - VirtualAlloc: Create an empty memory buffer that will hold the self-injected shellcode
 - OpenProcess: Using this to open a handle to the original implant process
 - ReadProcessMemory: Instead of injecting the final calc shellcode payload to the process, I wanted to try having the process read the shellcode from my implant's process instead.
 - CreateThread: Executes the calc payload shellcode
 - Sleep: Give it a second to execute the shellcode
 - CloseHandle: Closes handle to the implant process
 - VirtualFree: Frees the memory buffer containing the shellcode
 - CloseHandle: CloseHandle to the shellcode thread that executed
 - NtContinue: Continue the hijacked thread to keep the main program running like nothing happened
