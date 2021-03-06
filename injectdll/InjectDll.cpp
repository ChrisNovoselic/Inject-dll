// InjectDll.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>	// process snapshot
#include <io.h>
#include <fcntl.h>		// _setmode
#include <functional>

#pragma comment(lib,"Advapi32.lib") // RaisePrivilige()

VOID RaisePrivilige(_In_ LPCWSTR pwszPrivilegeName)
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tkp = { 0 };
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken);

	LookupPrivilegeValue(NULL, pwszPrivilegeName, &tkp.Privileges[0].Luid);
	tkp.PrivilegeCount = 1;  // one privilege to set   
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	CloseHandle(hToken);
}

DWORD LoadRemoteDLL(_In_ DWORD dwPid, _In_ LPCWSTR pwszDLLPath, _In_ LPCWSTR pwszDLLName, _In_ LPCWSTR pwszImageNameToHide)
{
	DWORD cerr = 0;
	WCHAR wszDLLFullPath[MAX_PATH] = { 0 };
	
	::lstrcatW(wszDLLFullPath, pwszDLLPath);
	::lstrcatW(wszDLLFullPath, L"\\");
	::lstrcatW(wszDLLFullPath, pwszDLLName);

	// elevated Authority...   because OpenProcess(System Process) failed , and ErrCode = 5 in Windows xp
	RaisePrivilige(SE_DEBUG_NAME);
	RaisePrivilige(SE_SECURITY_NAME);

	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)
	{
		cerr = ::GetLastError();
		std::wcout << L"::OpenProcess () - failed..." << std::endl;
	}
	else
		;

	// Alloc in Target Process
	std::size_t dwToWrite = (wcslen(wszDLLFullPath) + 1) * 2;
	LPVOID pAllocMem = VirtualAllocEx(hProcess, NULL, dwToWrite, MEM_COMMIT, PAGE_READWRITE);
	if ((cerr == 0) && pAllocMem == nullptr)
	{
		cerr = ::GetLastError();
		std::wcout << "::VirtualAllocEx () - failed..." << std::endl;
	}
	else
		;

	//
	BOOL bRetCode = WriteProcessMemory(hProcess, (PVOID)pAllocMem, (PVOID)wszDLLFullPath, dwToWrite, NULL);
	if ((cerr == 0) && !bRetCode)
	{
		cerr = ::GetLastError();
		std::wcout << "::WriteProcessMemory () - failed..." << std::endl;
	}
	else
		;

	//
	HMODULE hmKernel32 = ::GetModuleHandle(TEXT("Kernel32"));
	if ((cerr == 0) && hmKernel32 == NULL)
	{
		cerr = ::GetLastError();
		std::wcout << "::GetModuleHandle (""Kernel32"") - failed..." << std::endl;
	}
	else
		;

	PTHREAD_START_ROUTINE pfnThreadRrn = reinterpret_cast<PTHREAD_START_ROUTINE>(GetProcAddress(hmKernel32, "LoadLibraryW"));
	if ((cerr == 0) && pfnThreadRrn == NULL)
	{
		cerr = ::GetLastError();
		std::wcout << "::GetProcAddress (""Kernel32::LoadLibraryW"") - failed..." << std::endl;
	}
	else
		;

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRrn, (PVOID)pAllocMem, 0, NULL);
	if ((cerr == 0) && hThread == NULL)
	{
		cerr = ::GetLastError();
		std::wcout << "::CreateRemoteThread () - failed..." << std::endl;
	}
	else
		;

	// TODO: ожидать, пока целевой процесс не завершится...
	/*WaitForSingleObject(hThread, INFINITE);
	if (pAllocMem != NULL)
	VirtualFreeEx(hProcess, (PVOID)pAllocMem, 0, MEM_RELEASE);
	if (hThread != NULL)
	CloseHandle(hThread);
	if (hProcess != NULL)
	CloseHandle(hProcess);*/

	return cerr;
}

/* Преобразовать текст в соответсвии с указанным делегатом (TODO: ??? копия в 'hookx86.cpp')
- текст для преобразования
- делегат для преобразования
*/
template<typename T, typename _fnPtr>
static std::basic_string<T> MakeTextTo(_In_ CONST std::basic_string<T>& wsText, _In_ _fnPtr fnPtr)
{
	std::basic_string<T> tmpText;
	for (auto& itm : wsText)
		tmpText.push_back(static_cast<T>(fnPtr(itm)));

	return tmpText;
}

/* Преобразовать текст в нижний регистр (TODO: ??? копия в 'hookx86.cpp')
- текст для преобразования
*/
template<typename T>
static std::basic_string<T> MakeTextToLower(_In_ CONST std::basic_string<T>& wsText)
{
	return MakeTextTo(wsText, tolower);
}

/* Найти целевой процесс для внедрения библиотеки */
VOID FindProcName_In_ProcessSnapshot(_In_ CONST std::wstring& wsProcName, _In_ std::function<BOOL(DWORD)> ActionPtr)
{
	HANDLE hThSnap32 = NULL;
	PROCESSENTRY32W pe32;

	hThSnap32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hThSnap32 == INVALID_HANDLE_VALUE)
		return;
	else
		;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32FirstW(hThSnap32, &pe32))
	{
		::CloseHandle(hThSnap32);
		return;
	}

	do
	{
		if (MakeTextToLower(std::wstring(pe32.szExeFile)) == MakeTextToLower(wsProcName))  {
			std::wcout << L"Find '" << wsProcName.c_str() << L"' Pid=" << pe32.th32ProcessID << std::endl;
			if (!ActionPtr(pe32.th32ProcessID)) {
				::CloseHandle(hThSnap32);
				return;
			} else
				;
		} else
			;

	} while (Process32NextW(hThSnap32, &pe32));
	::CloseHandle(hThSnap32);
}

int main(int argc, const char *argv[])
{
	DWORD dwResultLoadRemoteDll = 255;
	WCHAR wszTaskMgr[] = L"taskmgr.exe";

	if (argc == 3) {
		WCHAR wszDLLName[MAX_PATH] = { 0 }
			, wszImageNameToHide[MAX_PATH] = { 0 }
			, wszDLLPath[MAX_PATH] = { 0 };

		::GetCurrentDirectoryW(MAX_PATH, wszDLLPath);

		mbstate_t state;
		size_t szRet;
		::mbsrtowcs_s (&szRet, wszDLLName, &argv[1], ::strlen(argv[1]), &state);
		::mbsrtowcs_s(&szRet, wszImageNameToHide, &argv[2], ::strlen(argv[2]), &state);

		setlocale(LC_ALL, "");
		_setmode(_fileno(stdout), _O_U8TEXT);
		std::wcout << L"Searching taskmgr.exe ......" << std::endl;
		FindProcName_In_ProcessSnapshot(wszTaskMgr, [&wszDLLPath, &wszDLLName, &wszImageNameToHide, &dwResultLoadRemoteDll, &wszTaskMgr](DWORD dwPid)
		{
			dwResultLoadRemoteDll = LoadRemoteDLL(dwPid, wszDLLPath, wszDLLName, wszImageNameToHide);
			std::wcout << L"Injector DLL path=[" << wszDLLPath << L"] to '" << wszTaskMgr << " ['" << dwPid << L"] done... error=" << dwResultLoadRemoteDll << std::endl;

			return dwResultLoadRemoteDll == 0;
		});

		if (dwResultLoadRemoteDll < 255)
			std::wcout << L"Injector all of '" << wszTaskMgr << "' done...";
		else
			std::wcout << L"Process '" << wszTaskMgr << "' not found...";
	}
	else
		std::wcout << std::endl << "Sintax error: library-injector-name.dll image-name-to-hide.exe";

	std::wcout << std::endl;
	system("pause");

    return 0;
}

