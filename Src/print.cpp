#include "stdafx.h"
#include "util.h"

#define _malloca_s(size) ((size) < _ALLOCA_S_THRESHOLD ? alloca(size) : new BYTE[size])

inline void _freea_s(PVOID pv)
{
	PNT_TIB tib = (PNT_TIB)NtCurrentTeb();
	if (pv < tib->StackLimit || tib->StackBase <= pv) delete [] pv;
}

static HANDLE _G_hFile = 0;
static BOOLEAN _G_bConsole = FALSE;

void PrintUTF8(PCWSTR pwz, ULONG cch)
{
	PSTR buf = 0;
	ULONG len = 0;
	while (len = WideCharToMultiByte(CP_UTF8, 0, pwz, cch, buf, len, 0, 0))
	{
		if (buf)
		{
			if (IsDebuggerPresent())
			{
				ULONG_PTR params[] = { cch, (ULONG_PTR)pwz, len, (ULONG_PTR)buf };
				RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, _countof(params), params);
			}
			if (_G_hFile)
			{
				if (_G_bConsole)
				{
					WriteConsoleW(_G_hFile, pwz, cch, &cch, 0);
				}
				else
				{
					WriteFile(_G_hFile, buf, len, &len, 0);
				}
			}
			break;
		}

		if (!(buf = (PSTR)_malloca_s(len)))
		{
			break;
		}
	}

	if (buf)
	{
		_freea_s(buf);
	}
}

void PrintWA_v(PCWSTR format, ...)
{
	va_list ap;
	va_start(ap, format);

	PWSTR buf = 0;
	int len = 0;
	while (0 < (len = _vsnwprintf(buf, len, format, ap)))
	{
		if (buf)
		{
			PrintUTF8(buf, len);
			break;
		}

		++len;
		if (!(buf = (PWSTR)_malloca_s(len * sizeof(WCHAR))))
		{
			break;
		}
	}

	if (buf)
	{
		_freea_s(buf);
	}
}

HRESULT PrintError(HRESULT dwError)
{
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) /*|| (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL)*/)
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (ULONG cch = FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		PrintUTF8(lpText, cch);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return dwError;
}

void InitPrintf()
{
	if (_G_hFile = GetStdHandle(STD_OUTPUT_HANDLE))
	{
		FILE_FS_DEVICE_INFORMATION ffdi;
		IO_STATUS_BLOCK iosb;
		if (0 <= NtQueryVolumeInformationFile(_G_hFile, &iosb, &ffdi, sizeof(ffdi), FileFsDeviceInformation))
		{
			switch (ffdi.DeviceType)
			{
			case FILE_DEVICE_CONSOLE:
				_G_bConsole = TRUE;
				break;
			}
		}
	}
}