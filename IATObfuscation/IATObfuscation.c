#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

/*
* Helper function that takes two strings.
* Converts them to lowercase and compares them.
* Returns true if both are equal, false otherwise.
*/
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

    WCHAR lStr1[MAX_PATH],
          lStr2[MAX_PATH];

    int len1 = lstrlenW(Str1),
        len2 = lstrlenW(Str2);

    int i = 0,
        j = 0;

    // overflow protection
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    // convert Str1 to lower case
    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0';  // null terminated strings

    // convert Str2 to lower case
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0';

    // compare the lowercase strings
    return (lstrcmpiW(lStr1, lStr2) == 0);

}

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	/*
	* How `GetProcAddress` works:
	*	1) The `hModule` parameter is the base address of the loaded DLL.
	*	2) Retrieving a function's address is done by looping thru the exported functions inside the provided DLL and checking if the target's name exists.
	*	3) To access the exported functions, it's necessary to access the DLL's export table (IMAGE_EXPORT_DIRECTORY).
	*/
	/*
	* typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Name;
        DWORD   Base;
        DWORD   NumberOfFunctions;
        DWORD   NumberOfNames;
        DWORD   AddressOfFunctions;     // RVA from base of image
        DWORD   AddressOfNames;         // RVA from base of image
        DWORD   AddressOfNameOrdinals;  // RVA from base of image
    * } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
	*/

    /*
    * Remember:
    *   1) `AddressOfFunctions` => the address of an array of addresses of exported functions.
    *   2) `AddressOfNames` => the address of an array of addresses of the names of exported functions.
    *   3) `AddressOfNameOrdinals` => the address of an array of ordinal numbers for the exported functions.
    */

    // We do this to avoid casting each time we use `hModule`
    PBYTE pBase = (PBYTE)hModule;

    // Get the DOS header and perform a signature check
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // Get the NT headers and perform a signature check
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // Get the optional header
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    // we can get the optional header like this as well																								
    // PIMAGE_OPTIONAL_HEADER	pImgOptHdr	= (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

    // Get the image export table (this is the export directory)
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // Get the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // Get the function's ordinal array pointer
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    // Loop through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

        // get the name of the function
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

        // get the address of the function via its ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // search for the function name specified
        if (strcmp(lpApiName, pFunctionName) == 0) {
            printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return pFunctionAddress;
        }

        //printf("[ %0.4d ] NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);

    }

    return NULL;

}

HMODULE GetModuleHandleReplacementx64(IN LPCWSTR szModuleName) {

    /*
    * How `GetModuleHandle` works:
    *   1) The `HMODULE` data type is the base address of the loaded DLL; where the DLL is located in the address space of the process.
    *   2) The goal of the replacement function is to retrieve the base address of a specified DLL.
    *   3) The Process Environment Block (PEB) contains info re: the loaded DLLs, notably the PEB_LDR_DATA Ldr member of the structure.
    */
    // Remember, the pointer to the PEB is found within the TEB, which is stored in the `GS` register.

    // get the PEB
    PPEB                    pPeb = (PEB*)(__readgsqword(0x60));  // works on x64 only

    // Get the Ldr
    PPEB_LDR_DATA           pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    // Get the first element in the linked list (contains info about the first module)
    PLDR_DATA_TABLE_ENTRY   pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    // Search for the target module by name
    while (pDte) {

        // if not null
        if (pDte->FullDllName.Length != NULL) {

            // check if both equal
            if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
                wprintf(L"[+] Found DLL \"%s\"\n", pDte->FullDllName.Buffer);
                // return handle to the DLL
                return (HMODULE)pDte->Reserved2[0];
            }
            //wprintf(L"[i]\"%s\"\n", pDte->FullDllName.Buffer);

        } else {
            break;
        }

        // next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

    }

    // return null if no match
    return NULL;

}

int main() {

    printf("[i] Original 0x%p\n", GetModuleHandleW(L"NTDLL.DLL"));

    printf("[i] Replacement 0x%p\n", GetModuleHandleReplacementx64(L"NTDLL.DLL"));

    printf("[#] Press <Enter> to quit...");
    getchar();

    return 0;

}