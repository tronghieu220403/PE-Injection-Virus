# PE Injection Virus
 
Welcome to the "PE Injection Virus" repository! This is an open-source project that aims to provide a virus which will inject malicious code into all Portable Executable (PE) files.

- [Introdution](#introduction)
- [Techniques](#techniques)
- [Folder structure](#folder-structure)
- [References](#references)
- [Requirements](#requirements)

Introduction
----------------
The Portable Executable (PE) format is a commonly used file format in the Windows operating system. It includes executable files (.exe), dynamic-link libraries (.dll), and other system files.

The PE injection virus works by injecting its code into files on the disk, thereby causes the program to launch malicious code when the computer execute that PE files.

Techniques
----------------

### Get Function Addresses of "kernel32.dll"

There are speacial registers in Assembly in Windows (MASM), they are fs and gs register. Both of them point to the current value of the [Thread Information Block (TIB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) structure. In x86 mode FS:\[0\] points to the start of the TIB, in X64 it's GS:\[0\]. The TIB structure contains a pointer to [Process Environment Block (PEB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb). In PEB, there is an pointer to [PPEB_LDR_DATA structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data), which contains information about the loaded modules for the process. 

In **PPEB_LDR_DATA** structure, there is a field named **InMemoryOrderModuleList** - the head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an **LDR_DATA_TABLE_ENTRY** structure. We will query this doubly-linked list to find the **kernel32.dll** base address then get all the needed functions through Export Address Table.

### Create Virus Section

### Add virus section to victim file

### Modify victim's entry point

### Modify bytes code of the virus section

Folder structure
----------------
```
.                           
│   │
├── main
│   │
│   └── virus.c
│   └── firstvirus.cpp
│   └── getvirussection.cpp
│   └── sideinfo.cpp
│   │
├── inlucde
│   └── pe
│   │   └── pe.h
│   └── virus
│   │   └── virus.h
│   └── ulti
│   │   └── everything.h
│   │
├── file
│   └── virusbody
│   │   └── virus_code_section
│   └── virusexe
│   │   └── x86
│   │   │   └── virus.exe
│   │   └── x64
│   │   │   └── virus.exe
│   │
────────────	
```

References
----------------
[MSDN - PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
[Stack Overflow - What is the GS register used for on Windows?](https://stackoverflow.com/questions/39137043/what-is-the-gs-register-used-for-on-windows)
Requirements
---
* C++ 17
* Supported Operating Systems (64-bit)
  * Windows
