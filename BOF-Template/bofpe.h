#pragma once

#include <Windows.h>
#include <stdio.h>

#include "base/helpers.h"

#include "beacon.h"
#include "bof_helpers.h"

#include "common.h"

extern "C" {
    
    typedef enum _MEMORY_INFORMATION_CLASS {
        MemoryBasicInformation
    } MEMORY_INFORMATION_CLASS;

    typedef struct _INVERTED_FUNCTION_TABLE_ENTRY {
        PIMAGE_RUNTIME_FUNCTION_ENTRY FunctionTable;
        PVOID ImageBase;
        ULONG SizeOfImage;
        ULONG SizeOfTable;
    } INVERTED_FUNCTION_TABLE_ENTRY, *PINVERTED_FUNCTION_TABLE_ENTRY;

    typedef struct _RTL_INVERTED_FUNCTION_TABLE {
        ULONG Count;
        ULONG MaxCount;
        ULONG Pad[2];
        INVERTED_FUNCTION_TABLE_ENTRY Entries[0x200];
    } RTL_INVERTED_FUNCTION_TABLE, *PRTL_INVERTED_FUNCTION_TABLE;

    /**
     * Map PE section characteristics to a PAGE_* protection value.
     */
    DWORD mapPeSectionProtect(DWORD characteristics) {

        DWORD protect = PAGE_READONLY;

        if ((characteristics & IMAGE_SCN_CNT_CODE) || (characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                protect = PAGE_EXECUTE_READWRITE;
            }
            else {
                protect = PAGE_EXECUTE_READ;
            }
        }
        else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }
        return protect;
    }

    /**
     * Apply base relocations for a mapped PE image using the delta from preferred base.
     */
    BOOL processPeRelocations(UCHAR* baseAddress, PIMAGE_NT_HEADERS ntHeaders, ULONGLONG delta) {

        PIMAGE_DATA_DIRECTORY relocDir = NULL;
        PIMAGE_BASE_RELOCATION reloc    = NULL;
        DWORD relocSize                 = 0;
        DWORD processed                 = 0;
        WORD* relocEntry                = NULL;
        DWORD entryCount                = 0;
        DWORD idx                       = 0;
        USHORT typeOffset               = 0;
        USHORT type                     = 0;
        USHORT offset                   = 0;
        PBYTE patchAddr                 = NULL;

        relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->VirtualAddress == 0 || relocDir->Size == 0 || delta == 0) {
            return TRUE;
        }

        reloc = (PIMAGE_BASE_RELOCATION)(baseAddress + relocDir->VirtualAddress);
        relocSize = relocDir->Size;
        processed = 0;

        while (processed < relocSize && reloc->SizeOfBlock != 0) {

            relocEntry = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
            entryCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            for (idx = 0; idx < entryCount; idx++) {
                typeOffset = relocEntry[idx];
                type = typeOffset >> 12;
                offset = typeOffset & 0x0FFF;
                patchAddr = baseAddress + reloc->VirtualAddress + offset;

                if (type == IMAGE_REL_BASED_DIR64) {
                    *(ULONGLONG*)patchAddr += delta;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    *(DWORD*)patchAddr += (DWORD)delta;
                }
                else if (type == IMAGE_REL_BASED_HIGH) {
                    *(WORD*)patchAddr = (WORD)((*(WORD*)patchAddr) + HIWORD(delta));
                }
                else if (type == IMAGE_REL_BASED_LOW) {
                    *(WORD*)patchAddr = (WORD)((*(WORD*)patchAddr) + LOWORD(delta));
                }
                else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    /* skip */
                }
                else {
                    BeaconPrintf(CALLBACK_ERROR, "Unsupported relocation type: %u", type);
                    return FALSE;
                }
            }

            processed += reloc->SizeOfBlock;
            reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
        }

        return TRUE;
    }

    /**
     * Resolve and patch import thunks for a mapped PE image.
     */
    BOOL processPeImports(UCHAR* baseAddress, PIMAGE_NT_HEADERS ntHeaders) {

        PIMAGE_DATA_DIRECTORY importDir      = NULL;
        PIMAGE_IMPORT_DESCRIPTOR importDesc  = NULL;
        PIMAGE_THUNK_DATA firstThunk         = NULL;
        PIMAGE_THUNK_DATA origThunk          = NULL;
        HMODULE moduleHandle                 = NULL;
        FARPROC procAddr                     = NULL;

        DFR_LOCAL(KERNEL32, lstrcmpiA)
        DFR_LOCAL(KERNEL32, LoadLibraryA)
        DFR_LOCAL(KERNEL32, GetModuleHandleA)
        DFR_LOCAL(KERNEL32, GetProcAddress)

        importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->VirtualAddress == 0 || importDir->Size == 0) {
            return TRUE;
        }

        importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + importDir->VirtualAddress);

        for (; importDesc->Name != 0; importDesc++) {

             LPCSTR moduleName = (LPCSTR)(baseAddress + importDesc->Name);
            BOOL isBeaconModule = (lstrcmpiA(moduleName, "beacon.dll") == 0);

            if (!isBeaconModule) {
                moduleHandle = LoadLibraryA(moduleName);
                if (moduleHandle == NULL) {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to load import %s", baseAddress + importDesc->Name);
                    return FALSE;
                }
            }
            else {
                moduleHandle = GetModuleHandleA(moduleName);
            }
            if (importDesc->OriginalFirstThunk != 0) {
                origThunk = (PIMAGE_THUNK_DATA)(baseAddress + importDesc->OriginalFirstThunk);
            }
            else {
                origThunk = (PIMAGE_THUNK_DATA)(baseAddress + importDesc->FirstThunk);
            }
            firstThunk = (PIMAGE_THUNK_DATA)(baseAddress + importDesc->FirstThunk);

            for (; origThunk->u1.AddressOfData != 0; origThunk++, firstThunk++) {

                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                    if (isBeaconModule) {
                        BeaconPrintf(CALLBACK_ERROR, "Unsupported ordinal import from Beacon!");
                        return FALSE;
                    }
                    procAddr = GetProcAddress(moduleHandle, (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + origThunk->u1.AddressOfData);
                    if (isBeaconModule) {
                        procAddr = (FARPROC)IF_Get((const char*)importByName->Name);
                        TracingBeaconPrintf(CALLBACK_OUTPUT, "Resolving: %s", importByName->Name);
                    }
                    else {
                        procAddr = GetProcAddress(moduleHandle, (LPCSTR)importByName->Name);
                    }
                }

                if (procAddr == NULL) {
                    BeaconPrintf(CALLBACK_ERROR, "Unresolved import in module %s", baseAddress + importDesc->Name);
                    return FALSE;
                }

                firstThunk->u1.Function = (ULONG_PTR)procAddr;
            }
        }
        return TRUE;
    }

    /**
     * Invoke TLS callbacks for a mapped PE image.
     */
    VOID processPeTls(UCHAR* baseAddress, PIMAGE_NT_HEADERS ntHeaders) {

        PIMAGE_DATA_DIRECTORY tlsDir = NULL;
        PIMAGE_TLS_DIRECTORY tls      = NULL;
        PIMAGE_TLS_CALLBACK* callbacks = NULL;

        tlsDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir->VirtualAddress == 0 || tlsDir->Size == 0) {
            return;
        }

        tls = (PIMAGE_TLS_DIRECTORY)(baseAddress + tlsDir->VirtualAddress);
        callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

        if (callbacks == NULL) {
            return;
        }

        for (; *callbacks != NULL; callbacks++) {
            (*callbacks)((PVOID)baseAddress, DLL_PROCESS_ATTACH, NULL);
        }
    }

    /**
     * Set memory protection on PE sections based on section characteristics.
     */
    BOOL protectPeSections(UCHAR* baseAddress, PIMAGE_NT_HEADERS ntHeaders) {

        PIMAGE_SECTION_HEADER section = NULL;
        WORD sectionCount = 0;
        WORD i = 0;
        DWORD oldProtect = 0;
        DWORD desiredProtect = 0;

        sectionCount = ntHeaders->FileHeader.NumberOfSections;
        section = IMAGE_FIRST_SECTION(ntHeaders);

        for (i = 0; i < sectionCount; i++, section++) {

            if (section->SizeOfRawData == 0) {
                continue;
            }

            desiredProtect = mapPeSectionProtect(section->Characteristics);
            if (!BeaconVirtualProtect(baseAddress + section->VirtualAddress, section->SizeOfRawData, desiredProtect, &oldProtect)) {
                return FALSE;
            }
        }
        return TRUE;
    }

    /**
     * Resolve an exported function address by name from a mapped PE image.
     */
    PVOID resolvePeExport(UCHAR* baseAddress, PIMAGE_NT_HEADERS ntHeaders, CHAR* functionName) {

        PIMAGE_DATA_DIRECTORY exportDir     = NULL;
        PIMAGE_EXPORT_DIRECTORY exportTable = NULL;
        DWORD* nameRvas                     = NULL;
        WORD* ordinals                      = NULL;
        DWORD* functions                    = NULL;
        DWORD i                             = 0;
        CHAR* currentName                   = NULL;

        DFR_LOCAL(KERNEL32, lstrcmpA)

        exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir->VirtualAddress == 0 || exportDir->Size == 0) {
            return NULL;
        }

        exportTable = (PIMAGE_EXPORT_DIRECTORY)(baseAddress + exportDir->VirtualAddress);
        nameRvas = (DWORD*)(baseAddress + exportTable->AddressOfNames);
        ordinals = (WORD*)(baseAddress + exportTable->AddressOfNameOrdinals);
        functions = (DWORD*)(baseAddress + exportTable->AddressOfFunctions);

        for (i = 0; i < exportTable->NumberOfNames; i++) {
            currentName = (CHAR*)(baseAddress + nameRvas[i]);
            if (lstrcmpA(currentName, functionName) == 0) {
                return (PVOID)(baseAddress + functions[ordinals[i]]);
            }
        }
        return NULL;
    }

    /**
     * Retrieve the exception directory (or SEH table on x86) for a mapped PE image.
     */
    BOOL getExceptionDirectory(UCHAR* baseAddress, PIMAGE_NT_HEADERS ntHeaders, PVOID* exceptionDir, DWORD* exceptionSize) {

        PIMAGE_DATA_DIRECTORY excDir          = NULL;
        PIMAGE_LOAD_CONFIG_DIRECTORY32 loadConfig32 = NULL;

        RETURN_FALSE_ON_NULL(exceptionDir);
        RETURN_FALSE_ON_NULL(exceptionSize);

        *exceptionDir = NULL;
        *exceptionSize = 0;

#ifdef _M_IX86
        if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
            return TRUE;
        }

        excDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (excDir->VirtualAddress == 0 || excDir->Size < sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32)) {
            return TRUE;
        }

        loadConfig32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)(baseAddress + excDir->VirtualAddress);
        if (loadConfig32->SEHandlerCount != 0 && loadConfig32->SEHandlerTable != 0) {
            *exceptionDir = (PVOID)loadConfig32->SEHandlerTable;
            *exceptionSize = loadConfig32->SEHandlerCount;
        }
#else
        excDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress != 0 && excDir->Size != 0) {
            *exceptionDir = (PVOID)(baseAddress + excDir->VirtualAddress);
            *exceptionSize = excDir->Size;
        }
#endif
        return TRUE;
    }

    /**
     * Locate ntdll!LdrpInvertedFunctionTable within .mrdata and return its bounds.
     */
    BOOL findLdrpInvertedFunctionTable(PRTL_INVERTED_FUNCTION_TABLE* tableOut, ULONG_PTR* mrDataPtr, DWORD* mrDataSize) {

        DFR_LOCAL(KERNEL32, GetModuleHandleA)
        DFR_LOCAL(KERNEL32, GetCurrentProcess)
        DFR_LOCAL(MSVCRT, memcmp)
        DFR_LOCAL(MSVCRT, memset)

        PVOID ntdllBase                   = NULL;
        PIMAGE_DOS_HEADER dosHeader       = NULL;
        PIMAGE_NT_HEADERS ntdllNt         = NULL;
        PIMAGE_SECTION_HEADER section     = NULL;
        WORD sectionCount                 = 0;
        WORD i                            = 0;
        PBYTE mrdataBase                  = NULL;
        PBYTE mrdataEnd                   = NULL;
        RTL_INVERTED_FUNCTION_TABLE* candidate = NULL;
        MEMORY_BASIC_INFORMATION mbi;
        PVOID exceptionDir                = NULL;
        DWORD exceptionSize               = 0;
        BOOL ok                           = FALSE;

        RETURN_FALSE_ON_NULL(tableOut);
        RETURN_FALSE_ON_NULL(mrDataPtr);
        RETURN_FALSE_ON_NULL(mrDataSize);

        *tableOut = NULL;
        *mrDataPtr = 0;
        *mrDataSize = 0;

        ntdllBase = GetModuleHandleA("ntdll.dll");
        if (ntdllBase == NULL) {
            return FALSE;
        }

        dosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        ntdllNt = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + dosHeader->e_lfanew);
        if (ntdllNt->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }

        section = IMAGE_FIRST_SECTION(ntdllNt);
        sectionCount = ntdllNt->FileHeader.NumberOfSections;

        for (i = 0; i < sectionCount; i++, section++) {
            if (memcmp(section->Name, ".mrdata", 7) == 0) {
                mrdataBase = (PBYTE)ntdllBase + section->VirtualAddress;
                *mrDataPtr = (ULONG_PTR)mrdataBase;
                *mrDataSize = section->SizeOfRawData;
                break;
            }
        }

        if (mrdataBase == NULL || *mrDataSize == 0) {
            return FALSE;
        }

        mrdataEnd = mrdataBase + *mrDataSize;

        while (mrdataBase < mrdataEnd) {

            candidate = (PRTL_INVERTED_FUNCTION_TABLE)mrdataBase;

            if (candidate->MaxCount == 0 || candidate->MaxCount > 512 || candidate->Count == 0 || candidate->Count > candidate->MaxCount) {
                mrdataBase += sizeof(ULONG_PTR);
                continue;
            }

            if ((ULONG_PTR)candidate->Entries[0].FunctionTable < (ULONG_PTR)candidate->Entries[0].ImageBase ||
                (ULONG_PTR)candidate->Entries[0].FunctionTable >= ((ULONG_PTR)candidate->Entries[0].ImageBase + candidate->Entries[0].SizeOfImage)) {
                mrdataBase += sizeof(ULONG_PTR);
                continue;
            }

            memset(&mbi, 0, sizeof(mbi));
            if(BeaconVirtualQuery(candidate->Entries[0].ImageBase, &mbi, sizeof(mbi)) == 0 || 
                (mbi.State & MEM_COMMIT) == 0) {
                mrdataBase += sizeof(ULONG_PTR);
                continue;
            }

            ok = getExceptionDirectory((UCHAR*)candidate->Entries[0].ImageBase, (PIMAGE_NT_HEADERS)((PBYTE)candidate->Entries[0].ImageBase + ((PIMAGE_DOS_HEADER)candidate->Entries[0].ImageBase)->e_lfanew), &exceptionDir, &exceptionSize);
            if (ok == FALSE) {
                mrdataBase += sizeof(ULONG_PTR);
                continue;
            }

            if (exceptionDir == NULL || exceptionSize == 0) {
                mrdataBase += sizeof(ULONG_PTR);
                continue;
            }

            if (candidate->Entries[0].SizeOfImage != ((PIMAGE_NT_HEADERS)((PBYTE)candidate->Entries[0].ImageBase + ((PIMAGE_DOS_HEADER)candidate->Entries[0].ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage) {
                mrdataBase += sizeof(ULONG_PTR);
                continue;
            }

            if ((ULONG_PTR)exceptionDir != (ULONG_PTR)candidate->Entries[0].FunctionTable || exceptionSize != candidate->Entries[0].SizeOfTable) {
                mrdataBase += sizeof(ULONG_PTR);
                continue;
            }

            *tableOut = candidate;
            return TRUE;
        }

        return FALSE;
    }

    /**
     * Insert a runtime function table entry for a mapped image into the inverted function table.
     */
    BOOL RtlpInsertInvertedFunctionTableEntry(PVOID imageBase, ULONG imageSize, PVOID exceptionDirectory, ULONG exceptionDirectorySize) {

        PRTL_INVERTED_FUNCTION_TABLE table = NULL;
        ULONG_PTR mrData                    = 0;
        DWORD mrDataSize                    = 0;
        DWORD oldProtect                    = 0;
        LONG entryIndex                     = 1;
        HMODULE hNtdll                      = NULL;
        PVOID (NTAPI *pfnRtlEncodeSystemPointer)(PVOID) = NULL;

        DFR_LOCAL(MSVCRT, memmove)

        if (!findLdrpInvertedFunctionTable(&table, &mrData, &mrDataSize)) {
            return FALSE;
        }

#ifndef _M_X64
        hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll == NULL) {
            hNtdll = LoadLibraryA("ntdll.dll");
        }
        if (hNtdll != NULL) {
            pfnRtlEncodeSystemPointer = (PVOID (NTAPI *)(PVOID))GetProcAddress(hNtdll, "RtlEncodeSystemPointer");
        }
        if (pfnRtlEncodeSystemPointer == NULL) {
            return FALSE;
        }
#endif

        if (!BeaconVirtualProtect((PVOID)mrData, mrDataSize, PAGE_READWRITE, &oldProtect)) {
            return FALSE;
        }

        if (table->Count == table->MaxCount) {
            table->Pad[1] = 1;
        }
        else {
            InterlockedIncrement((volatile LONG*)table->Pad);
            entryIndex = 1;

            if (table->Count != 1) {
                while (entryIndex < (LONG)table->Count) {
                    if (imageBase < table->Entries[entryIndex].ImageBase) {
                        break;
                    }
                    entryIndex++;
                }
            }

            if (entryIndex != (LONG)table->Count) {
                memmove(&table->Entries[entryIndex + 1],
                    &table->Entries[entryIndex],
                    (table->Count - entryIndex) * sizeof(INVERTED_FUNCTION_TABLE_ENTRY));
            }
        }

        table->Entries[entryIndex].ImageBase = imageBase;
        table->Entries[entryIndex].SizeOfImage = imageSize;
#ifdef _M_X64
        table->Entries[entryIndex].FunctionTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)exceptionDirectory;
#else
        table->Entries[entryIndex].FunctionTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)pfnRtlEncodeSystemPointer(exceptionDirectory);
#endif
        table->Entries[entryIndex].SizeOfTable = exceptionDirectorySize;
        InterlockedIncrement((volatile LONG*)table->Pad);
        table->Count++;

        BeaconVirtualProtect((PVOID)mrData, mrDataSize, oldProtect, &oldProtect);
        return TRUE;
    }

    /**
     * Register exception metadata (RUNTIME_FUNCTION table and inverted function table entry).
     */
    VOID addExceptionSupport(UCHAR* mappedBase, PIMAGE_NT_HEADERS ntHeaders) {
#ifdef _M_X64
        DFR_LOCAL(KERNEL32, RtlAddFunctionTable)
#endif
        PVOID exceptionDir = NULL;
        DWORD exceptionSize = 0;

        if (!getExceptionDirectory(mappedBase, ntHeaders, &exceptionDir, &exceptionSize)) {
            return;
        }

#ifdef _M_X64
        if (exceptionDir != NULL && exceptionSize != 0) {
            RtlAddFunctionTable((PRUNTIME_FUNCTION)exceptionDir, exceptionSize / sizeof(RUNTIME_FUNCTION), (DWORD64)mappedBase);
        }
#endif
        if (exceptionDir != NULL && exceptionSize != 0) {
            RtlpInsertInvertedFunctionTableEntry(mappedBase, ntHeaders->OptionalHeader.SizeOfImage, exceptionDir, exceptionSize);
        }
    }

}
