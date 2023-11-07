# Disclaimer

The following technique, explanation, or information provided herein is intended for educational and informational purposes only. By accessing or utilizing the technique, you acknowledge and agree to the terms and conditions outlined in this disclaimer.

## Educational Purpose

The Technique is intended to provide educational insights, promote understanding, and encourage responsible usage of technology. It is not intended to endorse or facilitate any malicious or illegal activities.

## Prohibited Use 

You expressly agree not to use the technique, or any part thereof, for any malicious, harmful, or illegal purposes. This includes, but is not limited to, unauthorized access, damage, disruption, or misuse of computer systems, networks, or personal data. Any use of the technique for such purposes is strictly prohibited.

## Legal and Ethical Considerations

The technique may involve technical concepts, tools, or methodologies. It is your responsibility to ensure compliance with all applicable laws, regulations, and ethical guidelines when using the technique. Unauthorized or malicious use of the technique is strictly prohibited.

## External Links and References

The Technique may contain links or references to external websites, resources, or third-party content. We do not endorse or assume any responsibility for the accuracy, reliability, or content of such external sources.

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

The PE injection virus works on both 32-bit and 64-bit PE files by adding its code into files on the disk, thereby causes the program to launch malicious code when the computer execute that PE files.

**Notice**
Many executable files have their own **integrity checks**, so viruses will not work on that file. You will receive a message like "installer integrity check has failed..." when executing that file.

Techniques
----------------

### Get Function Addresses of "kernel32.dll"

There are speacial registers in Windows Assembly (MASM), they are `FS` and `GS` register. Both of them point to the current value of the [Thread Information Block (TIB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb) structure. In x86 mode `FS:[0]` points to the start of the TIB, in X64 it's `GS:[0]`. The TIB structure contains a pointer to [Process Environment Block (PEB)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb). In PEB, there is an pointer to [PPEB_LDR_DATA structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data), which contains information about the loaded modules for the process. 

In **PPEB_LDR_DATA** structure, there is a field named **InMemoryOrderModuleList** - the head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an **LDR_DATA_TABLE_ENTRY** structure. We will query this doubly-linked list to find the **kernel32.dll** base address then get all the needed functions through it's Export Address Table.

### Check if the file has been injected

There are some fields in the PE structure that are no longer used by Windows. We can assign a specific value to one of those fields to indicate that the file has been injected. It will be very efficient for later checks. In here, I will assign a value for `OptionalHeader.LoaderFlags`.

### Create Virus Section

We will write a virus code in C `virus.cpp` and then compiler it into 2 version: x86 and x64. Next, we will get content of the `.text` section of these excutables and save them into a file. Here, I saved it into `file/virusbody/virus_code_section`. 

Moreover, I saved the position of entry points as 2 DWORD for x86 and x64 in the fisrt 8 bytes of the `virus_code_section`, respectively.

### Add virus section to victim file

We will add an entry into section table. There are something to notice:

- Each section header (section table entry) has a total of 40 bytes.

- The number of entries in the section table is given by the **NumberOfSections** field in the file header. Hence, we need to increase the value of that field by 1 for our virus sections.

- In an image file, the VAs for sections must be assigned by the linker so that they are in ascending order and adjacent, and they must be a multiple of the **SectionAlignment** value in the optional header. It means that the RVA of virus section must be the largest among all sections.

- We should the round up old victim file size to be a multiple of **FileAlignment** then **append the virus section to the end of PE header**. If the file has Overlays part, shift it to prevent dataloss and make sure that the Overlays part is always the last part of the file. 

- The virus section must have the following section flags in the **Characteristics** field: `IMAGE_SCN_CNT_CODE`, `IMAGE_SCN_CNT_INITIALIZED_DATA`, `IMAGE_SCN_MEM_READ`, `IMAGE_SCN_MEM_EXECUTE`.

### Modify victim's entry point

The new entry point of the victim file will be `RA of virus section in the victim file` plus the first DWORD in virus section for x86 or the second DWORD for x64, depend on the victim's architecture.

### Modify bytes code of the virus section

In Windows Assembly (MASM), bytecode of `call` instruction is `0xe8 0x?? 0x?? 0x?? 0x??`, where `0x?? 0x?? 0x?? 0x??` is the distance between the end of that instruction and the address of the called function. In `main` function of `virus.cpp`, I called to an `EmptyFunction` function so we will modify bytecode in that call instruction to call back to the original victim entry point. 

Nevertheless, in x86 code, we have to modify the `push offset InfectUserProfile` so that it will push to the exact offset of InfectUserProfile in the victim file.

Folder structure
----------------
```
.                           
│   │
├── main
│   │
│   └── virus.c				# the virus source code
│   └── firstvirus.cpp			# the code to trigger the virus
│   └── getvirussection.cpp		# the code to add virus section to the Pe-First-Virus.exe
│   └── sideinfo.cpp			
│   │
├── inlucde
│   └── pe
│   │   └── pe.h
│   │   └── pecpp.h
│   └── virus
│   │   └── virus.h
│   │   └── viruscpp.h
│   └── ulti
│   │   └── everything.h
│   │
├── file
│   └── virusbody
│   │   └── virus_code_section
│   └── virusexe
│   │   └── x86
│   │   │   └── PE-Virus.exe
│   │   └── x64
│   │   │   └── PE-Virus.exe
│   └── firstvirus
│   │   │   └── PE-First-Virus.exe
│   │
────────────	
```

References
----------------

[MSDN - PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

[Rohitab Batra - My first PE infection virus - Zero virus](http://www.rohitab.com/discuss/topic/40857-my-first-pe-infection-virus-zero-virus/)

[Stack Overflow - What is the GS register used for on Windows?](https://stackoverflow.com/questions/39137043/what-is-the-gs-register-used-for-on-windows)


Requirements
---
* C++ 17
* Supported Operating Systems (64-bit)
  * Windows
