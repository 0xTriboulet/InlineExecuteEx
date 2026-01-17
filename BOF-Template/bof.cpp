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
#pragma comment(lib, "ntdll")
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "sleepmask.h"
#include "bof_helpers.h"

#include "common.h"
#include "coff.h"
#include "bofpe.h"

    /* Check if the MACHINE_CODE in the COFF Header matches the expected value */
    BOOL isValidCoff(UCHAR* coffData) {

        RETURN_FALSE_ON_NULL(coffData);

        PIMAGE_FILE_HEADER coffBase = NULL;

        /* Cast the header */
        coffBase = (PIMAGE_FILE_HEADER)coffData;

        /* Sanity check the BOF */
        if (coffBase->Machine == MACHINE_CODE) {
            return TRUE;
        }
        return FALSE;
    }

    /* Check if the buffer points to a valid PE file */
    BOOL isValidPE(UCHAR* peData) {

        RETURN_FALSE_ON_NULL(peData);

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peData;
        PIMAGE_NT_HEADERS ntHeaders = NULL;
        BOOL bResult = FALSE;

        /* Check for MZ signature */
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            goto Cleanup;
        }

        /* Verify e_lfanew is within a reasonable range */
        if (dosHeader->e_lfanew == 0 || dosHeader->e_lfanew > 0x1000) {
            goto Cleanup;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);

        /* Check for PE\0\0 signature */
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            goto Cleanup;
        }

        bResult = TRUE;

    Cleanup:
        return bResult;
    }

    /* Run a BOF-PE. Returns TRUE on success. */
    BOOL runPE(CHAR* functionName, UCHAR* peData, SIZE_T peSize, UCHAR* argData, SIZE_T argLen) {

        DFR_LOCAL(MSVCRT, memcpy)
        DFR_LOCAL(MSVCRT, memset)

        PIMAGE_DOS_HEADER dosHeader          = NULL;
        PIMAGE_NT_HEADERS ntHeaders          = NULL;
        PIMAGE_SECTION_HEADER section        = NULL;
        SIZE_T sectionSize                   = 0;
        PVOID preferredBase                  = NULL;
        PVOID mappedBase                     = NULL;
        SIZE_T imageSize                     = 0;
        SIZE_T headerSize                    = 0;
        WORD sectionCount                    = 0;
        WORD i                               = 0;
        BOOL bResult                         = FALSE;
        ULONGLONG delta                      = 0;
        VOID(__cdecl* entry)(CHAR*, INT)     = NULL;

        RETURN_FALSE_ON_NULL(functionName);
        RETURN_FALSE_ON_NULL(peData);
        RETURN_FALSE_ON_ZERO(peSize);

        if (!g_if && !InitInternalFunctionsDynamic()) {
            TracingBeaconPrintf(CALLBACK_ERROR, "InternalFunction init failed");
            goto Cleanup;
        }

        dosHeader = (PIMAGE_DOS_HEADER)peData;
        ntHeaders = (PIMAGE_NT_HEADERS)(peData + dosHeader->e_lfanew);

        preferredBase = (PVOID)(ULONG_PTR)ntHeaders->OptionalHeader.ImageBase;
        imageSize = ntHeaders->OptionalHeader.SizeOfImage;
        headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
        sectionCount = ntHeaders->FileHeader.NumberOfSections;
        section = IMAGE_FIRST_SECTION(ntHeaders);

        /* try the preferred base, otherwise just alloc anywhere */
        mappedBase = BeaconVirtualAlloc(preferredBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mappedBase == NULL) {
            mappedBase = BeaconVirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (mappedBase == NULL) {
                BeaconPrintf(CALLBACK_ERROR, "PE allocation failed");
                goto Cleanup;
            }
        }

        memset(mappedBase, 0, imageSize);
        memcpy(mappedBase, peData, headerSize);

        for (i = 0; i < sectionCount; i++) {

            sectionSize = section[i].SizeOfRawData;
            if (sectionSize == 0) {
                continue;
            }

            if (section[i].PointerToRawData != 0) {
                memcpy((PBYTE)mappedBase + section[i].VirtualAddress,
                    peData + section[i].PointerToRawData,
                    sectionSize);
            }
        }

        delta = (ULONGLONG)((ULONG_PTR)mappedBase - (ULONG_PTR)preferredBase);
        if (!processPeRelocations((UCHAR*)mappedBase, ntHeaders, delta)) {
            goto Cleanup;
        }

        if (!processPeImports((UCHAR*)mappedBase, ntHeaders)) {
            goto Cleanup;
        }

        if (!protectPeSections((UCHAR*)mappedBase, ntHeaders)) {
            goto Cleanup;
        }

        addExceptionSupport((UCHAR*)mappedBase, ntHeaders);

        processPeTls((UCHAR*)mappedBase, ntHeaders);

        entry = (VOID(__cdecl*)(CHAR*, INT))resolvePeExport((UCHAR*)mappedBase, ntHeaders, functionName);
        if (entry == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Export %s not found", functionName);
            goto Cleanup;
        }

        entry((CHAR*)argData, (INT)argLen);
        bResult = TRUE;

    Cleanup:
        if (mappedBase != NULL) {
            BeaconVirtualFree(mappedBase, 0, MEM_RELEASE);
        }
        return bResult;
    }

    /* Run the COFF. Returns TRUE on success, and FALSE on failure. */
    BOOL runCoff(CHAR* functionName, UCHAR* coffData, SIZE_T binSize, UCHAR* argData, SIZE_T argLen) {

        /* Input validation */
        RETURN_FALSE_ON_NULL(functionName);
        RETURN_FALSE_ON_NULL(coffData);
        RETURN_FALSE_ON_ZERO(binSize);

        DFR_LOCAL(KERNEL32, GetModuleHandleW)
        DFR_LOCAL(KERNEL32, GetProcAddress)

        DFR_LOCAL(MSVCRT, sprintf)
        DFR_LOCAL(MSVCRT, memcpy)
        DFR_LOCAL(MSVCRT, memset)
        DFR_LOCAL(MSVCRT, malloc)
        DFR_LOCAL(MSVCRT, strlen)
        DFR_LOCAL(MSVCRT, strcmp)
        DFR_LOCAL(MSVCRT, free)

        PIMAGE_SECTION_HEADER sectionPtr           = NULL;
        PIMAGE_SECTION_HEADER firstSection         = NULL;
        PIMAGE_FILE_HEADER    coffBase             = NULL;
        PIMAGE_RELOCATION     relocationPtr        = NULL;

        PIMAGE_SYMBOL         coffSymbolPtr        = NULL;
        PIMAGE_SYMBOL         tmpSymbolPtr         = NULL;

        PVOID                 symbolTable          = NULL;
        PVOID                 functionPtr          = NULL;
        PVOID                 tmpPtr               = NULL;

        DWORD                 oldProtect           = 0;

        SIZE_T                counter              = 0;
        SIZE_T                relocationCount      = 0;
        SIZE_T                relocationIterCount  = 0;
        SIZE_T                functionMappingCount = 0;
        SIZE_T                jumpTableAlloc       = JUMP_TABLE_SIZE;

        INT64                 offsetValue          = 0;
        UINT64                addend               = 0;
        UINT64                target               = 0;

        CHAR* symbolName       = NULL;

        VOID** sectionMapping  = NULL;
        VOID** functionMapping = NULL;
        VOID*  jumpTable       = NULL;

        BOOL   bResult         = FALSE;

        CHAR shortNameBuffer[9];
        CHAR functionNameBuffer[MAX_PATH];
        CHAR specificHandlerBuffer[MAX_PATH];

        SYMBOL_RESOLUTION symbolResolution;
        THUNK_RESULT thunkResult;

        __stosb((PBYTE)&thunkResult, 0, sizeof(thunkResult));
        __stosb((PBYTE)shortNameBuffer, 0, sizeof(shortNameBuffer));
        __stosb((PBYTE)&symbolResolution, 0, sizeof(symbolResolution));
        __stosb((PBYTE)functionNameBuffer, 0, sizeof(functionNameBuffer));
        __stosb((PBYTE)specificHandlerBuffer, 0, sizeof(specificHandlerBuffer));

        PRINT("Entry function name: %s\n", functionName);

        void(__cdecl * go) (CHAR * arg, INT argSize);

        if (!g_if && !InitInternalFunctionsDynamic()) {
            TracingBeaconPrintf(CALLBACK_ERROR, "InternalFunction init failed");
            goto Cleanup;
        }

        #ifdef _M_IX86 // Extra steps for 32-bit
        (void)sprintf(functionNameBuffer, "_%s", functionName);
        functionName = functionNameBuffer;
        #endif // End 32-bit

        #ifdef _DEBUG
        coffBase = (PIMAGE_FILE_HEADER)rawCoff;
        #else
        /* Cast the header */
        coffBase = (PIMAGE_FILE_HEADER)coffData;
        #endif
        /* Sanity check the BOF */
        if (!isValidCoff(coffData)) {
            BeaconPrintf(CALLBACK_ERROR, "Received invalid BOF: 0x%X", coffBase->Machine);
            return bResult;
        }

        /* Find the symbol table */
        coffSymbolPtr = (PIMAGE_SYMBOL)((ULONG_PTR)coffBase + (ULONG_PTR)coffBase->PointerToSymbolTable);
        symbolTable = (UCHAR*)((ULONG_PTR)coffSymbolPtr + (SIZE_T)(coffBase->NumberOfSymbols * IMAGE_SIZEOF_SYMBOL));

        /* Init jump table */
        jumpTable = BeaconVirtualAlloc(NULL, jumpTableAlloc, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
        if (jumpTable == NULL) {
            goto Cleanup;
        }

        /* Save the jump table start pointer, we need this to bounds check and free */
        g_JumpTableStartPointer = (ULONG_PTR)jumpTable;

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

        sectionMapping = (VOID**)malloc(sizeof(PVOID) * (coffBase->NumberOfSections + 1));
        if (sectionMapping == NULL) {
            PRINT("Failed to allocate sectionMapping\n");
            goto Cleanup;
        }

        __stosb((PBYTE)sectionMapping, 0, sizeof(PVOID) * (coffBase->NumberOfSections + 1));

        /* First section header is right after FILE_HEADER + OptionalHeader */
        firstSection = (PIMAGE_SECTION_HEADER)((ULONG_PTR)coffBase + IMAGE_SIZEOF_FILE_HEADER + coffBase->SizeOfOptionalHeader);

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

            /* Get whichever size is larger */
            SIZE_T allocSize = sectionPtr->Misc.VirtualSize > sectionPtr->SizeOfRawData ? sectionPtr->Misc.VirtualSize : sectionPtr->SizeOfRawData;

            /* Make an allocation for every section */
            sectionMapping[counter] = BeaconVirtualAlloc(NULL, allocSize, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
            if (sectionMapping[counter] == NULL && allocSize > 0) {
                PRINT("Failed to allocate memory\n");
                goto Cleanup;
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
        if (functionMapping == NULL && relocationCount > 0) {
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

            relocationPtr = (PIMAGE_RELOCATION)((ULONG_PTR)coffBase + sectionPtr->PointerToRelocations);

            /* Process relocations */
            for (relocationIterCount = 0;
                relocationIterCount < sectionPtr->NumberOfRelocations;
                relocationIterCount++, relocationPtr++)
            {
                PRINT("\tVirtualAddress   : 0x%X\n", relocationPtr->VirtualAddress);
                PRINT("\tSymbolTableIndex : 0x%X\n", relocationPtr->SymbolTableIndex);
                PRINT("\tType             : 0x%X\n", relocationPtr->Type);

                /* Ensure this is zero'd out at the top of every loop */
                __stosb((PBYTE)&symbolResolution, 0, sizeof(symbolResolution));
                __stosb((PBYTE)&thunkResult, 0, sizeof(thunkResult));

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
                if (isCoffSymbolLocallyDefined(tmpSymbolPtr)) {
                    /* Local symbol */
                    functionPtr = sectionMapping[tmpSymbolPtr->SectionNumber - 1];
                    functionPtr = (PVOID)((ULONG_PTR)functionPtr + tmpSymbolPtr->Value);

                    PRINT("\t\t Function ptr : %p", functionPtr);
                }
                else if (isCoffSymbolExternallyDefined(tmpSymbolPtr)
                    && coffSymbolPtr[relocationPtr->SymbolTableIndex].Value == 0) {
                    /* External symbol that we need to resolve */
                    if (!resolveCoffSymbol(symbolName, &symbolResolution)) {
                        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve symbol %s", symbolName);
                        goto Cleanup;
                    }

                    /* Set function pointer so I don't have a bunch of refactors*/
                    functionPtr = symbolResolution.functionPtr;

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
        #ifdef _M_X64   /* Yanked the relocations straight from CoffLoader + https://github.com/The-Z-Labs/bof-launcher*/

                /* Type == 1 relocation is the 64-bit VA of the relocation target */
                if (relocationPtr->Type == IMAGE_REL_AMD64_ADDR64) {
                    memcpy(&offsetValue, (PVOID)(((ULONG_PTR)sectionMapping[counter]) + relocationPtr->VirtualAddress), sizeof(UINT64));
                    PRINT("\tReadin offsetValue : 0x%llX\n", offsetValue);
                    offsetValue += (UINT64)functionPtr;
                    PRINT("\tModified offsetValue : 0x%llX Base Address: %p\n", offsetValue, functionPtr);
                    memcpy((PVOID)(((ULONG_PTR)sectionMapping[counter]) + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT64));
                }
                /* This is Type == 3 relocation code */
                else if (relocationPtr->Type == IMAGE_REL_AMD64_ADDR32NB) {

                    INT32 disp = (INT32)((ULONG_PTR)functionPtr - (ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress - 4);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &disp, sizeof(INT32));

                } /* This is Type == 4 relocation code, this is either a relocation to a global or imported symbol */
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32) {
                    offsetValue = 0;

                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%llX\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    if (functionMappingCount > 0 && functionPtr == &functionMapping[functionMappingCount - 1]
                        && symbolResolution.isImport  == FALSE)
                    { // Here we're checking if the __imp prefix was used, if not we need special handling

                        /* get the actual function pointer */
                        functionPtr = functionMapping[functionMappingCount - 1];

                        PRINT("\t\Adding jumpTable Thunk: 0x%p\n", functionPtr);

                        /* add a jump stub to our function in the jump table */
                        if (!addJumpThunk(
                            (PBYTE)jumpTable,
                            (PBYTE)jmpStub,
                            sizeof(jmpStub),
                            jmpIdx,
                            functionPtr,
                            (ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress,
                            &thunkResult
                        )) {
                            PRINT("\t\t Failed adding entry to the jumpTable");
                            goto Cleanup;
                        }
                        /* write back the computed disp32 to the instruction */
                        memcpy(
                            (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress),
                            &thunkResult.rel32,
                            sizeof(UINT32)
                        );

                        /* update jumpTable pointer for next thunk */
                        jumpTable = thunkResult.nextTable;
                    }
                    else {
                        /* normal handling, probably a C BOF */
                        offsetValue += ((ULONG_PTR)functionPtr - ((SIZE_T)sectionMapping[counter] + relocationPtr->VirtualAddress + 4));
                        PRINT("\t\tSetting 0x%p to relative address: 0x%0llX\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                        memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), (PVOID)&offsetValue, sizeof(UINT32));
                    }
                } /* And everything else is back to your regularly scheduled program (ie all COFF loaders do this) */
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_1) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 1)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (size_t)functionPtr - ((size_t)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 1);
                    PRINT("\t\tSetting 0x%p to relative address: 0x%llX\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_2) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 2)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 2));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_3) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 3)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 3));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_4) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 4)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 4));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
                }
                else if (relocationPtr->Type == IMAGE_REL_AMD64_REL32_5) {
                    offsetValue = 0;
                    memcpy(&offsetValue, (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), sizeof(INT32));
                    PRINT("\t\tReadin offset value: 0x%X\n", offsetValue);

                    if (llabs((LONGLONG)functionPtr - (LONGLONG)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 5)) > UINT_MAX) {
                        PRINT("Relocations > 4 gigs away, exiting\n");
                        goto Cleanup;
                    }

                    offsetValue += (SIZE_T)functionPtr - ((SIZE_T)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress + 4 + 5));
                    PRINT("\t\tSetting 0x%p to relative address: 0x%X\n", (PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), offsetValue);
                    memcpy((PVOID)((ULONG_PTR)sectionMapping[counter] + relocationPtr->VirtualAddress), &offsetValue, sizeof(UINT32));
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
            BeaconVirtualProtect(sectionMapping[counter], max(sectionPtr->SizeOfRawData, sectionPtr->Misc.VirtualSize), secCharsToProtect(sectionPtr->Characteristics), &oldProtect);
        }

        /* Jump table needs to be exec */
        if (jumpTable != NULL) {
            if (!BeaconVirtualProtect((PVOID)g_JumpTableStartPointer, jumpTableAlloc, PAGE_EXECUTE_READ, &oldProtect)) {
                goto Cleanup;
            }
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
                if (sectionMapping[counter] != NULL) {
                    BeaconVirtualFree(sectionMapping[counter], 0, MEM_RELEASE);
                }
            }
            free(sectionMapping);
            sectionMapping = NULL;
        }
        if (functionMapping != NULL) {
            BeaconVirtualFree(functionMapping, 0, MEM_RELEASE);
            functionMapping = NULL;
        }
        if (jumpTable != NULL) {
            BeaconVirtualFree((PVOID)g_JumpTableStartPointer, 0, MEM_RELEASE);
            g_JumpTableStartPointer = 0;
        }
        return bResult;
    }


    /* Run the PIC. Returns TRUE on success, and FALSE on failure. */
    BOOL runPIC( UCHAR* picData, SIZE_T binSize, UCHAR* argData, SIZE_T argLen){

        RETURN_FALSE_ON_NULL(picData);
        RETURN_FALSE_ON_ZERO(binSize);

        BOOL      bResult     = FALSE;
        DWORD     oldProtect  = 0;
        API_TABLE apiTable;

        void(__cdecl * go) (CHAR * arg, INT argSize, PAPI_TABLE apiTable);
        
        if (!g_if && !InitInternalFunctionsDynamic()) {
            TracingBeaconPrintf(CALLBACK_ERROR, "InternalFunction init failed");
            goto Cleanup;
        }

        if (!BuildApiTable(&apiTable)) { // BuildApiTable zero's out apiTable for us
            goto Cleanup;
        }

        /* Make sure we have RX */
        if(!BeaconVirtualProtect(picData, binSize, PAGE_EXECUTE_READ, &oldProtect)){
            goto Cleanup;
        }

        go = (void(__cdecl * ) (CHAR * arg, INT argSize, PAPI_TABLE apiTable)) picData;
        go((char*) argData, argLen, &apiTable);

        __stosb((PBYTE)&apiTable, 0, sizeof(apiTable));

        /* Restore */
        if(!BeaconVirtualProtect(picData, binSize, oldProtect, &oldProtect)){
            goto Cleanup;
        }

        /* We survived somehow lol */
        bResult = TRUE;

    Cleanup:
        return bResult;
    }

    void go(char* args, int len) {

        datap parser;
        CHAR* functionName           = NULL;
        CHAR  reservedFunctionName[] = "pic";

        UCHAR* binData   = NULL;
        SIZE_T binSize  = 0;

        UCHAR* argData   = NULL;
        SIZE_T argLen    = 0;

        BOOL   validCoff = FALSE;
        BOOL   validPE   = FALSE;
        BOOL   validPIC  = FALSE;
        BOOL   bResult   = FALSE;

        DFR_LOCAL(NTDLL, _strnicmp)

        if (!g_if && !InitInternalFunctionsDynamic()) {
            TracingBeaconPrintf(CALLBACK_ERROR, "InternalFunction init failed");
            goto Cleanup;
        }

        __stosb((PBYTE)&parser, 0, sizeof(parser));

        BeaconDataParse(&parser, args, len);
        binData = (UCHAR*)BeaconDataExtract(&parser, (int*)&binSize);
        functionName = BeaconDataExtract(&parser, NULL);
        argData = (UCHAR*)BeaconDataExtract(&parser, (int*)&argLen);

        TracingBeaconPrintf(CALLBACK_OUTPUT, "Received function name: %s\nBinary size: %llu", functionName, binSize);

        /* Check if the input binary is something this BOF can run */
        validCoff = isValidCoff(binData);
        validPE = isValidPE(binData);
        validPIC = (_strnicmp(functionName, reservedFunctionName, sizeof(reservedFunctionName) - 1) == 0);

        /* If we can't run it, then bail */
        if (validCoff == FALSE && validPE == FALSE && validPIC == FALSE) {
            BeaconPrintf(CALLBACK_ERROR, "Invalid binary!");
            goto Cleanup;
        }

        if (validCoff == TRUE && runCoff(functionName, binData, binSize, argData, argLen)) {
            /* If it's a COFF and we successfully ran it */
            bResult = TRUE;
        }
        else if (validPE == TRUE && runPE(functionName, binData, binSize, argData, argLen)) {
            /* If it's a BOF-PE and we successfully ran it */
            bResult = TRUE;
         }
        else if(validPIC == TRUE && runPIC(binData, binSize, argData, argLen)){
            /* If we intended to run this as PIC, and we successfully ran it */
            bResult = TRUE;
        }

         /* Everything worked! */
         if (bResult == TRUE) {
             BeaconPrintf(CALLBACK_OUTPUT, "[+] Success!");
         }
         else {
             /* Loading or running failed somehow */
             BeaconPrintf(CALLBACK_ERROR, "Failed!");
         }

    Cleanup:
        if (g_if != NULL) {
            BeaconVirtualFree(g_if, 0, MEM_RELEASE);
            g_if = NULL;
        }
        return;
    }
}
    // Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

    int main(int argc, char* argv[]) {
        // Run BOF's entrypoint
        // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
        bof::runMocked<char*, char*>(go, (char*)rawCoff, (char*)"go", (char*)"Hello World", 12);

        return 0;
    }


// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

    TEST(BofTest, Test1) {
        std::vector<bof::output::OutputEntry> got =
            bof::runMocked<char*, char*>(go, (char*)rawCoff, (char*)"go", (char*)"Hello World", 12);

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

