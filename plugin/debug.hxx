#define _DEBUG

#define DBGPRINT(kwszDebugFormatString, ...) _DBGPRINT(__FUNCTION__, __LINE__, kwszDebugFormatString, __VA_ARGS__)

void _DBGPRINT(const char* kwszFunction, int iLineNumber, const wchar_t* kwszDebugFormatString, ... );
