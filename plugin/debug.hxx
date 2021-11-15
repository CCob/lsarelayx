
#ifndef NDEBUG
void _DBGPRINT(const char* kwszFunction, int iLineNumber, const wchar_t* kwszDebugFormatString, ... );
#else
#define _DBGPRINT(kwszDebugFormatString, ...)
#endif

#define DBGPRINT(kwszDebugFormatString, ...) _DBGPRINT(__FUNCTION__, __LINE__, kwszDebugFormatString, __VA_ARGS__)
