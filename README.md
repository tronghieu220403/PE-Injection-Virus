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

There are speacial registers in Windows Assembly (MASM), they are fs and gs register. Both of them point to the current value of the [Thread Information Block (TIB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) structure. In x86 mode FS:\[0\] points to the start of the TIB, in X64 it's GS:\[0\]. The TIB structure contains a pointer to [Process Environment Block (PEB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb). In PEB, there is an pointer to [PPEB_LDR_DATA structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data), which contains information about the loaded modules for the process. 

In **PPEB_LDR_DATA** structure, there is a field named **InMemoryOrderModuleList** - the head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an **LDR_DATA_TABLE_ENTRY** structure. We will query this doubly-linked list to find the **kernel32.dll** base address then get all the needed functions through it's Export Address Table.

### Create Virus Section

We will write a virus code in C `virus.c` and then compiler it into 2 version: x86 and x64. Next, we will get content of the `.text` section of these excutables and save them into a file. Here, I saved it into `file/virusbody/virus_code_section`. In the file, x86 section begin from 0x00 to 0x1e00 offset, while x64 section begin from 0x1e00 to 0x1e00 + 0x2400 (end of the file, 0x1e00 bytes is the size of x86 section, 0x2400 bytes is the size for x64).

The position of entry point from the beginning of the `virus_code_section` is **0x0ca0** for x86, in x64 it's **0x28f0**.

### Add virus section to victim file

We will add an entry into section table. There are something to notice:

- Each section header (section table entry) has a total of 40 bytes.

- The number of entries in the section table is given by the **NumberOfSections** field in the file header. Hence, we need to increase the value of that field by 1 for our virus sections.

- In an image file, the VAs for sections must be assigned by the linker so that they are in ascending order and adjacent, and they must be a multiple of the **SectionAlignment** value in the optional header. It means that the RVA of virus section must be the largest among all sections.

- We should the round up old victim file size to be a multiple of **FileAlignment** then append the virus section to the end of it. 

### Modify victim's entry point

The new entry point of the victim file will be `RVA of virus section + 0x0ca0` for x86 and`RVA of virus section + 0x28f0` for x64.

### Modify bytes code of the virus section

In Windows Assembly (MASM), bytes code of `call` instruction is `0xe9 0x?? 0x?? 0x?? 0x??`, where `0x?? 0x?? 0x?? 0x??` is the distance between the end of that instruction and the address of the called function. In `main` function of `virus.c`, I called to an "EmptyFunction" function so we will modify bytes code in that call instruction to call back to the original victim entry point.

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
