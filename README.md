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

## Get Function Addresses of "kernel32.dll"



## Create Virus Section

## Add virus section to victim file

## Modify victim's entry point

## Modify bytes code of the virus section

Folder structure
----------------
```
.
├── pe-reader.exe                                        
│   │
├── main.cpp
│   │
├── inlucde
│   │
│   └── pestructure
│   │   │ 
│   │   └── fileheader
│   │   │   └── dosheader.h
│   │   │   └── ntheader.h
│   │   │   └── cofffileheader.h
│   │   │   └── optionalheader.h
│   │   │ 
│   │   └── datadirectories
│   │   │   └── datadirectorytable.h
│   │   │   └── datadirectory.h
│   │   │ 
│   │   └── sectionheaders
│   │   │   └── sectiontable.h
│   │   │   └── sectionheader.h
│   │   │ 
│   │   └── importdirectory
│   │   │   └── importdirectorytable.h
│   │   │   └── importdirectoryentry.h
│   │   │   └── importlookuptable.h
│   │   │   └── importlookupentry.h
│   │   │   └── hintnametable.h
│   │   │   └── hintnameentry.h
│   │   │ 
│   │   └── exportdirectory
│   │   │   └── exportdirectorytable.h
│   │   │   └── exportaddressentry.h
│   │   │ 
│   │   └── rsrcsection
│   │   │   └── resourcedirectorytable.h
│   │   │   └── resourcedirectorynameentry.h
│   │   │   └── resourcedirectoryidentry.h
│   │   │   └── resourcedirectorynameentry.h
│   │   │   └── resourcedirectorystring.h
│   │   │ 
│   │   └── peconstants.h
│   │
│   └── ulti
│   │   └── everything.h
│   │
────────────	
```

References
----------------
[MSDN - PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

Requirements
---
* C++ 20
* Supported Operating Systems (64-bit)
  * Windows
