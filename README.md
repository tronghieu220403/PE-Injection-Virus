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

Requirements
---
* C++ 17
* Supported Operating Systems (64-bit)
  * Windows
