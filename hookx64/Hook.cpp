#include "hook.h"

BOOL Hook::Run(_In_ CONST std::string& szDLLName, _In_ CONST std::string& szProcName, _In_ LPVOID HookProcPtr, _Out_ LPVOID* pRealProcPtr)
{
	DWORD64 dwImageBase = reinterpret_cast<DWORD64>(::GetModuleHandleW(NULL));
	PIMAGE_DOS_HEADER pDocHeader = 0x0;
	PIMAGE_NT_HEADERS pNtHeader = 0x0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = 0x0;

	pDocHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dwImageBase);
	if (pDocHeader == nullptr)
	{
		return FALSE;
	}

	pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64 *>(pDocHeader->e_lfanew + dwImageBase);
	if (pNtHeader == nullptr) {
		return FALSE;
	} else
		;

	if (pNtHeader->Signature == NULL) {
		return FALSE;
	} else
		;

	pImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(dwImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; pImportDescriptor->Name != NULL; pImportDescriptor++) {
		CHAR* pszImportDLLName = reinterpret_cast<CHAR*>(dwImageBase) + pImportDescriptor->Name;
		if (strcmp(pszImportDLLName, szDLLName.c_str()) != 0) {
			continue;
		} else
			;

		auto pOriginThunk = reinterpret_cast<IMAGE_THUNK_DATA64 *>(dwImageBase + pImportDescriptor->OriginalFirstThunk);
		auto pRealThunk = reinterpret_cast<IMAGE_THUNK_DATA64 *>(dwImageBase + pImportDescriptor->FirstThunk);
		for (; pOriginThunk->u1.Function != NULL; pOriginThunk++, pRealThunk++) {
			if ((pOriginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) == 0) {
				IMAGE_IMPORT_BY_NAME* pImageImportName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(dwImageBase + pOriginThunk->u1.AddressOfData);
				if (strcmp(pImageImportName->Name, szProcName.c_str()) == 0) {
					*pRealProcPtr = reinterpret_cast<LPVOID>(pRealThunk->u1.Function);

					DWORD dwOldProtect = NULL;
					::VirtualProtect(&pRealThunk->u1.Function, 8, PAGE_EXECUTE_READWRITE, &dwOldProtect);
					pRealThunk->u1.Function = reinterpret_cast<DWORD64>(HookProcPtr);
					::VirtualProtect(&pRealThunk->u1.Function, 8, dwOldProtect, &dwOldProtect);
					return TRUE;
				} else
					;
			} else
				;
		}

		break;
	}
	
	return FALSE;
}
