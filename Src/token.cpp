#include "stdafx.h"
#include "util.h"

#define echo(x) x
#define label(x) echo(x)##__LINE__

#define BEGIN_PRIVILEGES(name, n) static const union { TOKEN_PRIVILEGES name;\
struct { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[n];} label(_) = { n, {

#define LAA(se) {{se}, SE_PRIVILEGE_ENABLED }

#define END_PRIVILEGES }};};

extern const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityDelegation, SECURITY_DYNAMIC_TRACKING, FALSE
};

extern const OBJECT_ATTRIBUTES oa_sqos = { sizeof(oa_sqos), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };

BEGIN_PRIVILEGES(tp_Debug, 2)
	LAA(SE_DEBUG_PRIVILEGE),
	LAA(SE_IMPERSONATE_PRIVILEGE),
END_PRIVILEGES

BEGIN_PRIVILEGES(tp_CreateTcb, 2)
	LAA(SE_CREATE_TOKEN_PRIVILEGE),
	LAA(SE_TCB_PRIVILEGE),
END_PRIVILEGES

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

NTSTATUS ImpersonateToken(_In_ PVOID buf, _In_ const TOKEN_PRIVILEGES* RequiredSet)
{
	NTSTATUS status;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	pv = buf;
	ULONG NextEntryOffset = 0;

	do 
	{
		pb += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		CLIENT_ID ClientId = { pspi->UniqueProcessId };

		if (ClientId.UniqueProcess)
		{
			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
				const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), &ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE|TOKEN_QUERY, 
						const_cast<POBJECT_ATTRIBUTES>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						status = NtAdjustPrivilegesToken(hNewToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(RequiredSet), 0, 0, 0);

						if (STATUS_SUCCESS == status)	
						{
							status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
						}

						NtClose(hNewToken);

						if (STATUS_SUCCESS == status)
						{
							return STATUS_SUCCESS;
						}
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS AdjustPrivileges(_In_ const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken, hNewToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &hToken)))
	{
		status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
			const_cast<OBJECT_ATTRIBUTES*>(&oa_sqos), FALSE, TokenImpersonation, &hNewToken);

		NtClose(hToken);

		if (0 <= status)
		{
			if (STATUS_SUCCESS == (status = NtAdjustPrivilegesToken(hNewToken, FALSE, 
				const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0)))
			{
				status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
			}

			NtClose(hNewToken);
		}
	}

	return status;
}

NTSTATUS ImpersonateToken(_In_ const TOKEN_PRIVILEGES* RequiredSet)
{
	NTSTATUS status;

	ULONG cb = 0x40000;

	do 
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (PBYTE buf = new BYTE[cb += 0x1000])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				status = ImpersonateToken(buf, RequiredSet);

				if (status == STATUS_INFO_LENGTH_MISMATCH)
				{
					status = STATUS_UNSUCCESSFUL;
				}
			}

			delete [] buf;
		}

	} while(status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}

HRESULT IsSrvRunning(_In_ PCWSTR lpServiceName)
{
	HRESULT hr;

	if (SC_HANDLE hSCManager = HR(hr, OpenSCManagerW(0, 0, SC_MANAGER_CONNECT )))
	{
		SC_HANDLE hService = HR(hr, OpenServiceW(hSCManager, lpServiceName, SERVICE_QUERY_STATUS ));

		CloseServiceHandle(hSCManager);

		if (hService)
		{
			SERVICE_STATUS ServiceStatus;

			if (HR(hr, QueryServiceStatus(hService, &ServiceStatus)))
			{
				if (ServiceStatus.dwCurrentState != SERVICE_RUNNING)
				{				
					if (NOERROR == (hr = ServiceStatus.dwWin32ExitCode))
					{
						hr = ERROR_SERVICE_NOT_ACTIVE;
					}
				}
			}

			CloseServiceHandle(hService);
		}
	}

	return HRESULT_FROM_WIN32(hr);
}


