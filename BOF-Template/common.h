#pragma once

#include <Windows.h>
#include <stdio.h>

#include "base/helpers.h"

#include "beacon.h"
#include "bof_helpers.h"

extern "C" {
    /* Check if the string starts with the substring */
    BOOL startsWith(const char* string, const char* substring) {
        DFR_LOCAL(MSVCRT, strncmp)
        DFR_LOCAL(MSVCRT, strlen)
        return strncmp(string, substring, strlen(substring)) == 0;
    }

    /* Map IMAGE_SECTION_HEADER.Characteristics->PAGE_* protection */
    DWORD secCharsToProtect(DWORD ch)
    {
        BOOL canRead  = (ch & IMAGE_SCN_MEM_READ) != 0;
        BOOL canWrite = (ch & IMAGE_SCN_MEM_WRITE) != 0;
        BOOL canExec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;

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

    BOOL SetSectionPermissions(VOID** sectionMapping, PIMAGE_SECTION_HEADER firstSection, SIZE_T numberOfSections) {

        RETURN_FALSE_ON_NULL(sectionMapping);
        RETURN_FALSE_ON_ZERO(numberOfSections)

        PIMAGE_SECTION_HEADER sectionPtr = NULL;
        DWORD  oldProtect = 0;
        SIZE_T counter    = 0;
        SIZE_T allocSize  = 0;

        /* Set section permissions */
        for (counter = 0; counter < numberOfSections; counter++) {
            sectionPtr = firstSection + counter;

            /* Get whichever size is larger */
            allocSize = sectionPtr->Misc.VirtualSize > sectionPtr->SizeOfRawData ? sectionPtr->Misc.VirtualSize : sectionPtr->SizeOfRawData;

            /* Use the characteristics to determine the correct permissions */
            if (allocSize > 0 && !BeaconVirtualProtect(sectionMapping[counter], allocSize, secCharsToProtect(sectionPtr->Characteristics), &oldProtect)) {
                return FALSE;
            }
        }
        return TRUE;
    }

    /* Get the absolute value of a LONGLONG */
    LONGLONG llabs(LONGLONG n) {
        return (n < 0) ? -n : n;
    }

}