#ifndef __INJECTDLL_HOOKX64_HOOK_H__
#define __INJECTDLL_HOOKX64_HOOK_H__

#include <Windows.h>
#include <string>

class Hook
{
public:
	Hook() = default;
	~Hook() = default;

	static BOOL Run(_In_ CONST std::string & , _In_ CONST std::string & , _In_ LPVOID , _Out_ LPVOID* );
private:

};

#endif // !__INJECTDLL_HOOKX64_HOOK_H__
