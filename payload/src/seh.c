#include <windows.h>

typedef void (*Callback)(void *context);

DWORD ExecuteWithSEH(Callback callback, void *context)
{
	__try
	{
		callback(context);
		return 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}
}
