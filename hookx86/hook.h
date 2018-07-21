#ifndef __INJECTDLL_HOOKX86_HOOK_H__
#define __INJECTDLL_HOOKX86_HOOK_H__

#include <Windows.h>

class Hook
{
public:
	Hook() = default;
	~Hook() = default;

	static BOOL InlineHook(_In_ LPVOID , _In_ LPVOID , _Out_ LPVOID* );

	static VOID UnInlineHook(_In_ LPVOID , LPVOID );
private:
	static BOOL GetPatchSize(_In_ LPVOID , _In_ DWORD dwSize, _Out_ DWORD* );

	static ULONG __fastcall SizeOfCode(_In_ LPVOID , UCHAR ** );
};


#endif // !__INJECTDLL_HOOKX86_HOOK_H__
