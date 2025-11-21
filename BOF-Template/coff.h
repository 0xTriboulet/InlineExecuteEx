#pragma once

#include <Windows.h>
#include <stdio.h>

#include "base/helpers.h"

#include "beacon.h"
#include "bof_helpers.h"

#include "common.h"

extern "C" {
    typedef struct _THUNK_RESULT {
        UINT32 rel32;     // value to write into the instruction
        PVOID  nextTable; // next available spot in jump table
    } THUNK_RESULT, * PTHUNK_RESULT;

    typedef struct SYMBOL_RESOLUTION {
        PVOID  functionPtr;
        BOOL   isImport;
    } SYMBOL_RESOLUTION, * PSYMBOL_RESOLUTION;

    /* Check if symbol is local ( if > 0 symbol is local ) */
    BOOL isCoffSymbolLocallyDefined(PIMAGE_SYMBOL symbol) {
        return symbol->SectionNumber > 0;
    }

    /* Check if symbol is external */
    BOOL isCoffSymbolExternallyDefined(PIMAGE_SYMBOL symbol) {
        return symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL
            || symbol->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
    }

    /* Resolve the symbol */
    BOOL resolveCoffSymbol(CHAR* symbolName, PSYMBOL_RESOLUTION symbolResolution) {

        RETURN_FALSE_ON_NULL(symbolName)

        DFR_LOCAL(MSVCRT, strncmp)
        DFR_LOCAL(MSVCRT, strcmp)
        DFR_LOCAL(MSVCRT, strlen)
        DFR_LOCAL(MSVCRT, memcpy)
        DFR_LOCAL(MSVCRT, memmove)
        DFR_LOCAL(MSVCRT, strtok)

        DFR_LOCAL(KERNEL32, LoadLibraryA)
        DFR_LOCAL(KERNEL32, GetProcAddress)

        PVOID   functionPtr = NULL;

        CHAR*   localLib    = NULL;
        CHAR*   localFunc   = NULL;

        HMODULE hModule = NULL;

        BOOL    bResult = FALSE;

        INT     counter = 0;

        CHAR    localBuffer[1024];

        __stosb((PBYTE)&localBuffer, 0, sizeof(localBuffer));

        memcpy(localBuffer, symbolName, strlen(symbolName)); // We're not copying the null-byte here, doesn't matter though
        if (startsWith(symbolName, PREPENDSYMBOL "Beacon")
            || startsWith(symbolName, PREPENDSYMBOL "toWideChar")
            || startsWith(symbolName, PREPENDSYMBOL "GetProcAddress")
            || startsWith(symbolName, PREPENDSYMBOL "LoadLibraryA")
            || startsWith(symbolName, PREPENDSYMBOL "GetModuleHandleA")
            || startsWith(symbolName, PREPENDSYMBOL "FreeLibrary")
            || startsWith(symbolName, PREPENDSYMBOL "memmove")
            || startsWith(symbolName, PREPENDSYMBOL "memcpy")
            || startsWith(symbolName, PREPENDSYMBOL "memset")
            || strcmp(symbolName, "__C_specific_handler") == 0
            )
        {
            const char* local = symbolName;
            if (strncmp(symbolName, PREPENDSYMBOL, strlen(PREPENDSYMBOL)) == 0) {
                local = symbolName + strlen(PREPENDSYMBOL);
            }

            functionPtr = IF_Get(local);
            if (functionPtr != NULL)
            {
                symbolResolution->functionPtr = functionPtr;
                symbolResolution->isImport = TRUE;
                bResult = TRUE;
                goto Cleanup;
            }
            // fall through if not found
        }
        else if (strncmp(symbolName, PREPENDSYMBOL, strlen(PREPENDSYMBOL)) == 0) {
            /* Move pointer past the prepend symbol*/
            localLib = localBuffer + strlen(PREPENDSYMBOL);

            /* Parse until the $ character */
            localLib = strtok(localLib, "$");

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
            PRINT("\t\nFunction address: 0x%p\n", functionPtr);
            symbolResolution->functionPtr = functionPtr;
            symbolResolution->isImport = TRUE;
            bResult = TRUE;
        }

        /* Check one more time without the prepended import symbol */
        if (startsWith(symbolName, "Beacon")
            || startsWith(symbolName, "toWideChar")
            || startsWith(symbolName, "GetProcAddress")
            || startsWith(symbolName, "LoadLibraryA")
            || startsWith(symbolName, "GetModuleHandleA")
            || startsWith(symbolName, "FreeLibrary")
            || startsWith(symbolName, "memmove")
            || startsWith(symbolName, "memcpy")
            || startsWith(symbolName, "memset")
            || strcmp(symbolName, "__C_specific_handler") == 0
            )
        {
            const char* local = symbolName;

            functionPtr = IF_Get(local);
            if (functionPtr != NULL)
            {
                symbolResolution->functionPtr = functionPtr;
                symbolResolution->isImport = FALSE;
                bResult = TRUE;
                goto Cleanup;
            }
            // fall through if not found
        }
        else {
            /* Move pointer past the prepend symbol*/
            localLib = localBuffer;

            /* Parse until the $ character */
            localLib = strtok(localLib, "$");

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
            PRINT("\t\nFunction address: 0x%p\n", functionPtr);

            symbolResolution->functionPtr = functionPtr;
            symbolResolution->isImport = FALSE;
            bResult = TRUE;
            goto Cleanup;
        }

    Cleanup:
        return bResult;
    }

}