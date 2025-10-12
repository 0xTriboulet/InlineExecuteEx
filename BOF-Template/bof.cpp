#include <Windows.h>
#include "base\helpers.h"
#include <stdio.h>
#include <intrin.h>
/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"
#include "bof_helpers.h"

    /* Map IMAGE_SECTION_HEADER.Characteristics->PAGE_* protection */
    DWORD secCharsToProtect(DWORD ch)
    {
        BOOL canRead = (ch & IMAGE_SCN_MEM_READ) != 0;
        BOOL canWrite = (ch & IMAGE_SCN_MEM_WRITE) != 0;
        BOOL canExec = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;

        DWORD prot = 0;
        if (canExec) {
            prot = canWrite ? PAGE_EXECUTE_READWRITE
                : canRead ? PAGE_EXECUTE_READ
                : PAGE_EXECUTE;              // rare, but valid
        }
        else {
            prot = canWrite ? PAGE_READWRITE
                : canRead ? PAGE_READONLY
                : PAGE_NOACCESS;            // e.g., purely discardable
        }

        return prot;
    }

    /* Check if symbol is local ( if > 0 symbol is local ) */
    BOOL isSymbolLocallyDefined(PIMAGE_SYMBOL symbol) {
        return symbol->SectionNumber > 0;
    }

    /* Check if symbol is external */
    BOOL isSymbolExternallyDefined(PIMAGE_SYMBOL symbol) {
        return symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL
            || symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
    }

    BOOL startsWith(const char* string, const char* substring) {
        DFR_LOCAL(MSVCRT, strncmp)
        DFR_LOCAL(MSVCRT, strlen)
        return strncmp(string, substring, strlen(substring)) == 0;
    }

    PVOID resolveSymbol(CHAR* symbolName) {

        RETURN_NULL_ON_NULL(symbolName)

        DFR_LOCAL(MSVCRT, strncmp)
        DFR_LOCAL(MSVCRT, strcmp)
        DFR_LOCAL(MSVCRT, strlen)
        DFR_LOCAL(MSVCRT, memcpy)
        DFR_LOCAL(MSVCRT, strtok)

        DFR_LOCAL(KERNEL32, LoadLibraryA)
        DFR_LOCAL(KERNEL32, GetProcAddress)

        PVOID   functionPtr = NULL;

        CHAR*   localLib    = NULL;
        CHAR*   localFunc   = NULL;

        INT     counter     = 0;

        HMODULE hModule     = NULL;

        CHAR  localBuffer[1024];

        __stosb((PBYTE)&localBuffer, 0, sizeof(localBuffer));
        
        memcpy(localBuffer, symbolName, strlen(symbolName)); // We're not copying the null-byte here, doesn't matter though
        if (startsWith(symbolName, PREPENDSYMBOL "Beacon")
            || startsWith(symbolName, PREPENDSYMBOL "toWideChar")
            || startsWith(symbolName, PREPENDSYMBOL "GetProcAddress")
            || startsWith(symbolName, PREPENDSYMBOL "LoadLibraryA")
            || startsWith(symbolName, PREPENDSYMBOL "GetModuleHandleA")
            || startsWith(symbolName, PREPENDSYMBOL "FreeLibrary")
            || strcmp(symbolName, "__C_specific_handler") == 0
            )
        {
            const char* local = symbolName;
            if (strncmp(symbolName, PREPENDSYMBOL, strlen(PREPENDSYMBOL)) == 0)
                local = symbolName + strlen(PREPENDSYMBOL);

            UCHAR* p = IF_Get(local);
            if (p) return p;
            // fall through if not found
        }
        else if (strncmp(symbolName, PREPENDSYMBOL, strlen(PREPENDSYMBOL)) == 0) {
            /* Move pointer past the prepend symbol*/
            localLib = localBuffer + strlen(PREPENDSYMBOL);

            /* Parse until the $ character */
            localLib  = strtok(localLib, "$");

            /* Parse starting from the $ character */
            localFunc = strtok(NULL, "$");
            PRINT("\t\tLibrary: %s\n", localLib);

            localFunc = strtok(localFunc, "@");
            PRINT("\t\tFunction: %s\n", localFunc);
            /* Resolve the symbols here, and set the functionPtr */

            /* Load the lib and resolve the function */
            hModule = LoadLibraryA(localLib);
            if (hModule == NULL) {
                goto Cleanup;
            }
            functionPtr = GetProcAddress(hModule, localFunc);
            if (functionPtr == NULL) {
                goto Cleanup;
            }
            PRINT("\t\Function address: 0x%p\n", functionPtr);
        }

    Cleanup:
        return functionPtr;
    }

    BOOL runCoff(CHAR* functionName, UCHAR* coffData, SIZE_T coffSize, UCHAR* argData, SIZE_T argLen) {

        /* Input validation */
        RETURN_FALSE_ON_NULL(functionName);
        RETURN_FALSE_ON_NULL(coffData);
        RETURN_FALSE_ON_ZERO(coffSize);

        DFR_LOCAL(KERNEL32, GetModuleHandleW)
        DFR_LOCAL(KERNEL32, GetProcAddress)

        DFR_LOCAL(MSVCRT, sprintf)
        DFR_LOCAL(MSVCRT, memcpy)
        DFR_LOCAL(MSVCRT, memset)
        DFR_LOCAL(MSVCRT, malloc)
        DFR_LOCAL(MSVCRT, strlen)
        DFR_LOCAL(MSVCRT, strcmp)
        DFR_LOCAL(MSVCRT, free)

        DFR_LOCAL(MSVCR120, llabs)

        PIMAGE_SECTION_HEADER sectionPtr          = NULL;
        PIMAGE_SECTION_HEADER firstSection        = NULL;
        PIMAGE_FILE_HEADER    coffBase            = NULL;
        PIMAGE_RELOCATION     relocationPtr       = NULL;

        PIMAGE_SYMBOL         coffSymbolPtr       = NULL;
        PIMAGE_SYMBOL         tmpSymbolPtr        = NULL;

        PVOID                 symbolTable         = NULL;
        PVOID                 functionPtr         = NULL;
        PVOID                 tmpPtr              = NULL;

        DWORD                 oldProtect          = 0;

        SIZE_T                counter              = 0;
        SIZE_T                relocationCount      = 0;
        SIZE_T                relocationIterCount  = 0;
        SIZE_T                functionMappingCount = 0;

        UINT64                offsetValue         = 0;

        CHAR*                 symbolName          = NULL;

        VOID**                sectionMapping      = NULL;
        VOID**                functionMapping     = NULL;

        BOOL                  bResult = FALSE;

        CHAR shortNameBuffer[9];
        CHAR functionNameBuffer[MAX_PATH];
        CHAR specificHandlerBuffer[MAX_PATH];

        __stosb((PBYTE)shortNameBuffer, 0, sizeof(shortNameBuffer));
        __stosb((PBYTE)functionNameBuffer, 0, sizeof(functionNameBuffer));
        __stosb((PBYTE)specificHandlerBuffer, 0, sizeof(specificHandlerBuffer));

        PRINT("Entry function name: %s\n", functionName);

        void(__cdecl * go) (CHAR* arg, INT argSize);

        if (!g_if && !InitInternalFunctionsDynamic()) {
            BeaconPrintf(CALLBACK_ERROR, "InternalFunction init failed");
            goto Cleanup;
        }

#ifdef _M_IX86 // Extra steps for 32-bit
        (void)sprintf(functionNameBuffer, "_%s", functionName);
        functionName = functionNameBuffer;
#endif // End 32-bit

#ifdef _DEBUG
        coffBase = (PIMAGE_FILE_HEADER) rawCoff;
#else
        /* Cast the header */
        coffBase = (PIMAGE_FILE_HEADER) coffData;
#endif
        /* Sanity check the BOF */
        if (coffBase->Machine != MACHINE_CODE) {
            BeaconPrintf(CALLBACK_ERROR, "Received invalid BOF: 0x%X", coffBase->Machine);
            return bResult;
        }

        /* Find the symbol table */
        coffSymbolPtr = (PIMAGE_SYMBOL)((ULONG_PTR) coffBase + (ULONG_PTR) coffBase->PointerToSymbolTable);
        symbolTable = (UCHAR*)((ULONG_PTR) coffSymbolPtr + (SIZE_T)(coffBase->NumberOfSymbols * IMAGE_SIZEOF_SYMBOL));

        /* Print debug information */
        PRINT("Machine               : 0x%X\n", coffBase->Machine);
        PRINT("Number of sections    : 0x%X\n", coffBase->NumberOfSections);
        PRINT("TimeDateStamp         : 0x%X\n", coffBase->TimeDateStamp);
        PRINT("PointerToSymbolTable  : 0x%X\n", coffBase->PointerToSymbolTable);
        PRINT("NumberOfSymbols       : 0x%X\n", coffBase->NumberOfSymbols);
        PRINT("OptionalHeaderSize    : 0x%X\n", coffBase->SizeOfOptionalHeader);
        PRINT("Characteristics       : 0x%X\n", coffBase->Characteristics);
        PRINT("\n");

        TracingBeaconPrintf(CALLBACK_OUTPUT, "Allocating sectionMapping");

        sectionMapping = (VOID**) malloc(sizeof(PVOID) * (coffBase->NumberOfSections + 1));
        if (sectionMapping == NULL) {
            PRINT("Failed to allocate sectionMapping\n");
            goto Cleanup;
        }

        __stosb((PBYTE)sectionMapping, 0, sizeof(PVOID) * (coffBase->NumberOfSections + 1));

        /* First section header is right after FILE_HEADER + OptionalHeader */
        firstSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR) coffBase + IMAGE_SIZEOF_FILE_HEADER + coffBase->SizeOfOptionalHeader);

        /* Handle the allocation and copying of the sections */
        for (counter = 0; counter < coffBase->NumberOfSections; counter++) {
            sectionPtr = firstSection + counter;

            PRINT("Name                 : %s\n", sectionPtr->Name);
            PRINT("VirtualSize          : 0x%X\n", sectionPtr->Misc.VirtualSize);
            PRINT("VirtualAddress       : 0x%X\n", sectionPtr->VirtualAddress);
            PRINT("SizeOfRawData        : 0x%X\n", sectionPtr->SizeOfRawData);
            PRINT("PointerToRelocations : 0x%X\n", sectionPtr->PointerToRelocations);
            PRINT("PointerToRawData     : 0x%X\n", sectionPtr->PointerToRawData);
            PRINT("NumberOfRelocations  : %d\n", sectionPtr->NumberOfRelocations);
            relocationCount += sectionPtr->NumberOfRelocations;

            /* Make an allocation for every section */
            sectionMapping[counter] = BeaconVirtualAlloc(NULL, sectionPtr->SizeOfRawData, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
            if (sectionMapping[counter] == NULL) {
                PRINT("Failed to allocate memory\n");
            }

            PRINT("Allocated section %d at %p\n", counter, sectionMapping[counter]);
            if (sectionMapping[counter] != NULL) {
                if (sectionPtr->PointerToRawData != 0) {
                    /* Copy the contents of the section into our allocation */
                    memcpy(sectionMapping[counter], (PVOID)((ULONG_PTR)coffBase + sectionPtr->PointerToRawData), sectionPtr->SizeOfRawData);
                }
                else {
                    /* If our section does not have data, zero out the allocation. This is extra credit since VirtualAlloc should already be 0 init'd */
                    memset(sectionMapping[counter], 0, sectionPtr->SizeOfRawData);
                }
            }
        }

        /* Actually allocate enough for worst case every relocation */
        functionMapping = (VOID**)BeaconVirtualAlloc(NULL, relocationCount * 8, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
        if (functionMapping == NULL) {
            PRINT("Failed to allocation functionMapping");
            goto Cleanup;
        }

        TracingBeaconPrintf(CALLBACK_OUTPUT, "Processing relocations");

        /* We need to iterate through sections again */
        for (counter = 0; counter < coffBase->NumberOfSections; counter++) {
            sectionPtr = firstSection + counter;

            if (sectionPtr->NumberOfRelocations == 0 || sectionPtr->PointerToRelocations == 0) {
                continue;
            }

            relocationPtr = (PIMAGE_RELOCATION)((ULONG_PTR) coffBase + sectionPtr->PointerToRelocations);

            /* Process relocations */
            for (relocationIterCount = 0;
                relocationIterCount < sectionPtr->NumberOfRelocations;
                relocationIterCount++, relocationPtr++)
            {
                PRINT("\tVirtualAddress   : 0x%X\n", relocationPtr->VirtualAddress);
                PRINT("\tSymbolTableIndex : 0x%X\n", relocationPtr->SymbolTableIndex);
                PRINT("\tType             : 0x%X\n", relocationPtr->Type);

                /* Bounds check */
                if (relocationPtr->SymbolTableIndex >= coffBase->NumberOfSymbols) {
                    PRINT("\t[!] Bad SymbolTableIndex\n");
                    continue;
                }

                /* Convenient pointer to make the code less noisey */
                tmpSymbolPtr = &coffSymbolPtr[relocationPtr->SymbolTableIndex];

                /* Long name if N.Name.Short == 0; offset is from start of symbolTable */
                if (tmpSymbolPtr->N.Name.Short == 0) {
                    symbolName = (CHAR*)((ULONG_PTR)symbolTable + (ULONG_PTR)tmpSymbolPtr->N.LongName[1]);
                    PRINT("\t\tSymbol ptr  : %p\n", symbolName);
                    PRINT("\t\tSymbol name : %s\n\n", symbolName);
                }
                else {
                    /* Short 8-byte name; may not be NUL-terminated. DO NOT strlen() it. */
                    __stosb((PBYTE)shortNameBuffer, 0, sizeof(shortNameBuffer));
                    memcpy(shortNameBuffer, tmpSymbolPtr->N.ShortName, 8);  // copy raw 8 bytes
                    symbolName = shortNameBuffer;
                    PRINT("\t\tSymbol ptr  : %p\n", symbolName);
                    PRINT("\t\tSymbol name : %s\n\n", symbolName);
                }

                /* Check if symbol is local */
                if (isSymbolLocallyDefined(tmpSymbolPtr)) {
                    /* Local symbol */
                    functionPtr = sectionMapping[tmpSymbolPtr->SectionNumber - 1];
                    functionPtr = (PVOID) ((ULONG_PTR) functionPtr + tmpSymbolPtr->Value);

                    PRINT("\t\t Function ptr : %p", functionPtr);
                }
                else if (isSymbolExternallyDefined(tmpSymbolPtr)) {
                    /* External symbol that we need to resolve */
                    functionPtr = resolveSymbol(symbolName);
                    if (functionPtr == NULL) {
                        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve symbol %s", symbolName);
                        goto Cleanup;
                    }
                    PRINT("Resolved %s at address %p", symbolName, functionPtr);
                    /* Store the address of our function pointer */
                    functionMapping[functionMappingCount] = functionPtr;

                    /* Get the address of the location where we just stored our function pointer */
                    functionPtr = &functionMapping[functionMappingCount];

                    /* Increment the count */
                    functionMappingCount += 1;
                }
                else {
                    /* Undefined symbol - exciting */
                    PRINT("\n\nRelocation %llu in section index %llu references undefined symbol %s\n", relocationCount, counter, symbolName);
                    goto Cleanup; // Bail so we don't crash
                }
#ifdef _M_X64   /* Yanked the relocations straight from CoffLoader */

                /* Type == 1 relocation is the 64-bit VA of the relocation target */
                if (relocationPtr->Type == IMAGE_REL_AMD64_ADDR64) {
                    memcpy(&offsetValue, (PVOID) (((ULONG_PTR) sectionMapping[counter]) + relocationPtr->VirtualAddress), sizeof(UINT64));
                    PRINT("\tReadin offsetValue : 0x%llX\n", offsetValue);
                    offsetValue += (UINT64) functionPtr;
                    PRINT("\tModified offsetValue : 0x%llX Base Address: %p\n", offsetValue, functionPtr);
                    memcpy((PVOID) (((ULONG_PTR) sectionMapping[counter]) + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT64));
                }
                /* This is Type == 3 relocation code */
                else if (relocationPtr->Type == IMAGE_REL_AMD64_ADDR32NB) {
                    memcpy(&offsetValue, (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\tReadin offsetValue : 0x%0llX\n", offsetValue);
                    PRINT("\t\tReferenced Section: 0x%llX\n", (ULONG_PTR) sectionMapping[coffSymbolPtr[relocationPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue);
                    PRINT("\t\tEnd of Relocation Bytes: 0x%llX\n", ((ULONG_PTR) sectionMapping[counter]) + relocationPtr->VirtualAddress + 4);
                    if (((CHAR*)((ULONG_PTR) sectionMapping[coffSymbolPtr[relocationPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue) - (CHAR*)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4)) > 0xffffffff) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }
                    offsetValue = ((CHAR*)((ULONG_PTR) sectionMapping[coffSymbolPtr[relocationPtr->SymbolTableIndex].SectionNumber - 1] + offsetValue) - (CHAR*)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4));
                    offsetValue += coffSymbolPtr[relocationPtr->SymbolTableIndex].Value;
                    PRINT("\tSetting 0x%p to offsetValue: 0x%llX\n", (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(INT32));
                } /* This is Type == 4 relocation code, this is either a relocation to a global or imported symbol */
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32) {
                    offsetValue = 0;

                    memcpy(&offsetValue, (PVOID) ((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%llX\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += ((ULONG_PTR)functionPtr - ((SIZE_T)sectionMapping[counter] + relocationPtr->VirtualAddress + 4));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%0llX\n", (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), (PVOID) & offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_1) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 1)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (size_t)functionPtr - ((size_t)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 1);
                    PRINT("\t\tSetting 0x%p to relative address: 0x%llX\n", (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_2) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 2)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 2));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_3) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 3)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 3));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_4) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 4)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 4));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_5) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 5)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 5));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID) ((ULONG_PTR) sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else {
                    BeaconPrintf(CALLBACK_ERROR, "No code for relocation type: %d\n", relocationPtr->Type);
                    goto Cleanup; // Bail for safety
                }
#endif // 64-bit end
#ifdef _M_IX86
                /* This is Type == IMAGE_REL_I386_DIR32 relocation code */
                if (relocationPtr->Type == IMAGE_REL_I386_DIR32) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\tReadin OffsetValue : 0x%0X\n", offsetValue);
                    offsetValue = (UINT32)functionPtr + offsetValue;
                    PRINT("\tSetting 0x%p to: 0x%X\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_I386_REL32) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\tReadin OffsetValue : 0x%0X\n", offsetValue);
                    offsetValue += (UINT32)functionPtr - (UINT32)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4);
                    PRINT("\tSetting 0x%p to relative address: 0x%X\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else {
                    BeaconPrintf(CALLBACK_ERROR, "No code for relocation type: %d\n", relocationPtr->Type);
                    goto Cleanup; // Bail for safety
                }
#endif // 32-bit end
            }

        }

        /* Set section permissions */
        for (counter = 0; counter < coffBase->NumberOfSections; counter++) {
            sectionPtr = firstSection + counter;
            /* Use the characteristics to determine the correct permissions */
            BeaconVirtualProtect(sectionMapping[counter], sectionPtr->SizeOfRawData, secCharsToProtect(sectionPtr->Characteristics), &oldProtect);
        }

        TracingBeaconPrintf(CALLBACK_OUTPUT, "Searching for function %s", functionName);

        for (counter = 0; counter < coffBase->NumberOfSymbols; counter++) {

            sectionPtr = firstSection + (coffSymbolPtr[counter].SectionNumber - 1);

            if (coffSymbolPtr[counter].N.Name.Short != 0 && strcmp((CHAR*)coffSymbolPtr[counter].N.ShortName, functionName) == 0 && (sectionPtr->Characteristics & IMAGE_SCN_CNT_CODE)) {
                PRINT("\t\tFound entry!\n");

                /* Set the address of our entry function */
                go = (void(__cdecl*)(CHAR*, INT))
                    ((PBYTE)sectionMapping[coffSymbolPtr[counter].SectionNumber - 1]
                        + coffSymbolPtr[counter].Value);

                PRINT("Trying to run: %p\n", go);

                TracingBeaconPrintf(CALLBACK_OUTPUT, "Running BOF!");

                /* Run the  BOF */
                go((CHAR*)argData, argLen);

                /* We ran the BOF */
                bResult = TRUE;

                goto Cleanup;

            }
        }

    Cleanup:
        if (sectionMapping != NULL) {
            for (counter = 0; counter < coffBase->NumberOfSections; counter++) {
                if (sectionMapping[counter]) {
                    BeaconVirtualFree(sectionMapping[counter], 0, MEM_RELEASE);
                }
            }
            free(sectionMapping);
            sectionMapping = NULL;
        }
        if (functionMapping != NULL) {
            BeaconVirtualFree(functionMapping, 0, MEM_RELEASE);
        }
        return bResult;
    }

    void go(char* args, int len) {

        datap parser;
        CHAR* functionName = NULL;

        UCHAR* coffData = NULL;
        SIZE_T coffSize = 0;

        UCHAR* argData = NULL;
        SIZE_T argLen  = 0;

        __stosb((PBYTE)&parser, 0, sizeof(parser));

        BeaconDataParse(&parser, args, len);
        coffData     = (UCHAR*)BeaconDataExtract(&parser, (int*)&coffSize);
        functionName = BeaconDataExtract(&parser, NULL);
        argData      = (UCHAR*)BeaconDataExtract(&parser, (int*) &argLen);

        TracingBeaconPrintf(CALLBACK_OUTPUT, "Received function name: %s\nBOF size: %llu", functionName, coffSize);

        if (!runCoff(functionName, coffData, coffSize, argData, argLen)) {
            BeaconPrintf(CALLBACK_ERROR, "Failed!");
        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Success!");
        }

    }

    // Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

    int main(int argc, char* argv[]) {
        // Run BOF's entrypoint
        // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
        bof::runMocked<char*, char*>(go, (char*) "go", (char*) rawCoff, (char*)"Hello World", 12);

        return 0;
    }

    // Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

    TEST(BofTest, Test1) {
        std::vector<bof::output::OutputEntry> got =
            bof::runMocked<>(go);
        std::vector<bof::output::OutputEntry> expected = {
            {CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
        };
        // It is possible to compare the OutputEntry vectors, like directly
        // ASSERT_EQ(expected, got);
        // However, in this case, we want to compare the output, ignoring the case.
        ASSERT_EQ(expected.size(), got.size());
        ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
    }
#endif
}