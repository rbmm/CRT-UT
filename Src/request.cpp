#include "StdAfx.h"

#include "util.h"

extern volatile const UCHAR guz = 0;

PCSTR GetDispositionString(LONG Disposition, PSTR buf, ULONG len)
{
	switch (Disposition)
	{
	case CR_DISP_INCOMPLETE: return "INCOMPLETE";
	case CR_DISP_ERROR: return "ERROR";
	case CR_DISP_DENIED: return "DENIED";
	case CR_DISP_ISSUED: return "ISSUED";
	case CR_DISP_ISSUED_OUT_OF_BAND: return "ISSUED_OUT_OF_BAND";
	case CR_DISP_UNDER_SUBMISSION: return "UNDER_SUBMISSION";
	case CR_DISP_REVOKED: return "REVOKED";
	}

	sprintf_s(buf, len, "%x", Disposition);
	return buf;
}

HRESULT PrintCertOp(PCCERT_CONTEXT pCertContext, HRESULT hr)
{
	WCHAR name[0x400];

	if (CertNameToStrW(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_X500_NAME_STR, name, _countof(name)))
	{
		DbgPrint("%s[%08x] \"%s\"\r\n", hr ? L"!! " : L"", hr, name);
	}

	UCHAR hash[20];
	ULONG cb = sizeof(hash);
	if (CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, hash, &cb))
	{
		DumpBytesInLine(hash, cb, "thumbprint: ");
	}

	return PrintError(hr), hr;
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, 
					 _In_ PCERT_CHAIN_PARA pChainPara,
					 _Out_opt_ PCCERT_CHAIN_CONTEXT* ppChainContext /*= 0*/)
{
	PCCERT_CHAIN_CONTEXT pChainContext = 0;

	HRESULT hr;

	if (HR(hr, CertGetCertificateChain(HCCE_LOCAL_MACHINE, pCertContext, 0, 0, pChainPara, 
		CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, 0, &pChainContext)))
	{
		CERT_CHAIN_POLICY_PARA PolicyPara = { sizeof(PolicyPara) };
		CERT_CHAIN_POLICY_STATUS PolicyStatus = { sizeof(PolicyStatus) };

		if (HR(hr, CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_NT_AUTH, pChainContext, &PolicyPara, &PolicyStatus)))
		{
			if (CRYPT_E_REVOCATION_OFFLINE == (hr = PolicyStatus.dwError))
			{
				hr = S_OK;
			}
		}

		if (0 <= hr && ppChainContext)
		{
			*ppChainContext = pChainContext;
		}
		else
		{
			CertFreeCertificateChain(pChainContext);
		}
	}

	DbgPrint("VerifyCertificate=%x\r\n", hr);

	PrintError(hr);

	return HRESULT_FROM_WIN32(hr);
}

HRESULT SaveChainToStore(_In_ PCCERT_CHAIN_CONTEXT pChainContext, _Out_ HCERTSTORE* phStore)
{
	HRESULT hr = NTE_NOT_FOUND;

	if (DWORD cChain = pChainContext->cChain)
	{
		PCERT_SIMPLE_CHAIN* rgpChain = pChainContext->rgpChain;

		do 
		{
			PCERT_SIMPLE_CHAIN pChain = *rgpChain++;

			if (pChain->TrustStatus.dwErrorStatus)
			{
				continue;
			}

			DWORD cElement = pChain->cElement;
			
			if (1 < cElement--)
			{
				if (HCERTSTORE hStore = HR(hr, CertOpenStore(sz_CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)))
				{
					PCERT_CHAIN_ELEMENT* rgpElement = pChain->rgpElement + 1;

					do 
					{
						PCERT_CHAIN_ELEMENT pElement = *rgpElement++;

						hr = BOOL_TO_ERROR(CertAddCertificateContextToStore(hStore, pElement->pCertContext, CERT_STORE_ADD_NEW, 0));
						
						if (PrintCertOp(pElement->pCertContext, hr))
						{
							CertCloseStore(hStore, 0);
							PrintCertOp(pElement->pCertContext, hr);
							return hr;
						}

					} while (--cElement);

					*phStore = hStore;

					return S_OK;
				}

				break;
			}

		} while (--cChain);
	}

	return hr;
}

HRESULT myAddToStore(HCERTSTORE hToCertStore, PCCERT_CONTEXT pCertContext)
{
	switch (HRESULT hr = PrintCertOp(pCertContext, BOOL_TO_ERROR(CertAddCertificateContextToStore(
		hToCertStore, pCertContext, CERT_STORE_ADD_NEWER, 0))))
	{
	case CRYPT_E_EXISTS:
	case NOERROR:
		return NOERROR;
	default:
		return hr;
	}
}

void ExecNotepad()
{
	WCHAR notepad[MAX_PATH];

	if (SearchPathW(0, L"notepad.exe", 0, _countof(notepad), notepad, 0))
	{
		PROCESS_INFORMATION pi;
		STARTUPINFOW si = { sizeof(si) };

		PWSTR cmd = 0;
		ULONG cch = 0;

		while (cch = ExpandEnvironmentStringsW(L"* %SystemRoot%\\system32\\drivers\\etc\\hosts", cmd, cch))
		{
			if (cmd)
			{
				if (CreateProcessW(notepad, cmd, 0, 0, 0, 0, 0, 0, &si, &pi))
				{
					NtClose(pi.hThread);
					NtClose(pi.hProcess);

					return;
				}

				break;
			}

			cmd = (PWSTR)alloca(cch * sizeof(WCHAR));
		}
	}
}
HRESULT SetRealmToHost(PCWSTR RealmName, PWSTR KDCnameZ)
{
	static const WCHAR Domains[] = L"\\registry\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Domains\\";
	
	size_t s = (wcslen(RealmName) + 1) * sizeof(WCHAR);
	PWSTR KeyName = (PWSTR)alloca(sizeof(Domains) - sizeof(WCHAR) + s);
	memcpy(KeyName, Domains, sizeof(Domains) - sizeof(WCHAR));
	memcpy(KeyName + _countof(Domains) - 1, RealmName, s);
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, KeyName);

	NTSTATUS status = ZwCreateKey(&oa.RootDirectory, KEY_WRITE, &oa, 0, 0, 0, 0);

	if (0 <= status)
	{
		UNICODE_STRING KdcNames = RTL_CONSTANT_STRING(L"KdcNames");

		status = ZwSetValueKey(oa.RootDirectory, &KdcNames, 0, REG_MULTI_SZ, KDCnameZ, ((ULONG)wcslen(KDCnameZ) + 2) * sizeof(WCHAR));

		NtClose(oa.RootDirectory);
	}

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT AddKdc(PCERT_NAME_BLOB Issuer)
{
	HRESULT hr;

	PCERT_NAME_INFO pcni;

	if (0 <= (hr = Decode(X509_NAME, Issuer, &pcni)))
	{
		hr = NTE_NOT_FOUND;

		if (DWORD cRDN = pcni->cRDN)
		{
			PCERT_RDN rgRDN = pcni->rgRDN;

			do 
			{
				if (DWORD cRDNAttr = rgRDN->cRDNAttr)
				{
					PCERT_RDN_ATTR rgRDNAttr = rgRDN->rgRDNAttr;
					do 
					{
						if (rgRDNAttr->dwValueType == CERT_RDN_UNICODE_STRING && 
							!strcmp(rgRDNAttr->pszObjId, szOID_COMMON_NAME))
						{
							ULONG cbData = rgRDNAttr->Value.cbData;

							if (!(cbData & (sizeof(WCHAR) - 1)))
							{
								PWSTR szName = (PWSTR)rgRDNAttr->Value.pbData;
								PWSTR pc = (PWSTR)RtlOffsetToPointer(szName, cbData);
								if (!*pc && *--pc=='$')
								{
									if (wcslen(szName)*sizeof(WCHAR) == cbData)
									{
										*pc = 0;
										DbgPrint("KDC= \"%s\"\r\n", szName);

										if (PWSTR szRealm = wcschr(szName, '.'))
										{
											DbgPrint("Realm= \"%s\"\r\n", 1 + szRealm);

											if (0 <= (hr = SetRealmToHost(1 + szRealm, szName)))
											{
												DbgPrint("system must be able resolve %s address.\r\n"
													"may be add it to HOSTS\r\n", szName);

												ExecNotepad();
											}
										}
									}
								}
							}
						}

					} while (rgRDNAttr++, --cRDNAttr);
				}
			} while (rgRDN++, --cRDN);
		}

		LocalFree(pcni);
	}

	return hr;
}

HRESULT ImportCA(_In_ HCERTSTORE hCertStore)
{
	union {
		PCCRL_CONTEXT pCrlContext = 0;
		PCCERT_CONTEXT pCertContext;
	};

	HRESULT hr = NTE_NOT_FOUND;

	while (pCrlContext = CertEnumCRLsInStore(hCertStore, pCrlContext))
	{
		if (HRESULT hr2 = AddKdc(&pCrlContext->pCrlInfo->Issuer))
		{
			hr = hr2;
		}
		else
		{
			hr = NOERROR;
		}
	}

	if (hr)
	{
		return hr;
	}

	HCERTSTORE hToCertStore = 0;

	while (pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))
	{
		if (!hToCertStore)
		{
			if (hToCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, 
				0, CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE, L"NTAuth")))
			{
				DbgPrint(">> NTAuth:\r\n");
				hr = myAddToStore(hToCertStore, pCertContext);
				CertCloseStore(hToCertStore, 0);
				hToCertStore = 0;
			}

			if (hr)
			{
				break;
			}
		}

		ULONG cb = pCertContext->pCertInfo->Subject.cbData;
		if (cb == pCertContext->pCertInfo->Issuer.cbData &&
			!memcmp(pCertContext->pCertInfo->Subject.pbData, pCertContext->pCertInfo->Issuer.pbData, cb))
		{
			if (hToCertStore)
			{
				CertCloseStore(hToCertStore, 0);
			}

			if (hToCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, 
				0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"Root")))
			{
				DbgPrint(">> ROOT:\r\n");
				hr = myAddToStore(hToCertStore, pCertContext);
				CertCloseStore(hToCertStore, 0);
				hToCertStore = 0;
			}

			if (hr)
			{
				break;
			}
		}
		else
		{
			if (hToCertStore || 
				(hToCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, 
				0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"CA"))))
			{
				DbgPrint(">> CA:\r\n");
				hr = myAddToStore(hToCertStore, pCertContext);
			}

			if (hr)
			{
				break;
			}
		}
	}

	if (hToCertStore)
	{
		CertCloseStore(hToCertStore, 0);
	}

	return hr;
}

HRESULT ImportCA(_In_ PCWSTR lpFileName)
{
	HRESULT hr;

	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(sz_CERT_STORE_PROV_FILENAME_W, 0, 0, 
		CERT_STORE_READONLY_FLAG|CERT_STORE_OPEN_EXISTING_FLAG, lpFileName)))
	{
		hr = ImportCA(hCertStore);
		CertCloseStore(hCertStore, 0);
	}

	return HRESULT_FROM_WIN32(hr);
}

// In AD DS, the value of the dNSHostName attribute being written is in the following format: 
// computerName.fullDomainDnsName, where computerName is the current sAMAccountName of the object 
// (without the final "$" character), and the fullDomainDnsName is the DNS name of the domain NC 
// or one of the values of msDS-AllowedDNSSuffixes on the domain NC 
// (if any) where the object that is being modified is located.

HRESULT GetCAInfo(_In_ PCWSTR wszCertType, _Out_ BSTR* ppwszComputerName, _Out_ BSTR* ppwszAuthority)
{
	HRESULT hr;
	HCAINFO hCAInfo;

	if (0 <= (hr = CAFindByCertType(wszCertType, 0, 0, &hCAInfo)))
	{
		static const PCWSTR wszPropertyNames[] = {
			CA_PROP_DNSNAME, CA_PROP_NAME
		};

		BSTR bstrs[_countof(wszPropertyNames)] = {};

		PZPWSTR pawszPropertyValue;

		ULONG n = _countof(wszPropertyNames);
		do 
		{
			if (0 <= (hr = CAGetCAProperty(hCAInfo, wszPropertyNames[--n], &pawszPropertyValue)))
			{
				hr = NTE_NOT_FOUND;

				if (pawszPropertyValue)
				{
					if (PWSTR pwsz = *pawszPropertyValue)
					{
						if (pwsz = SysAllocString(pwsz))
						{
							bstrs[n] = pwsz;
							hr = S_OK;
						}
						else
						{
							hr = E_OUTOFMEMORY;
						}
					}
				}

				CAFreeCAProperty(hCAInfo, pawszPropertyValue);

				if (0 > hr)
				{
					break;
				}
			}
		} while (n);

		if (0 > hr)
		{
			SysFreeString(bstrs[1]);
		}
		else
		{
			*ppwszAuthority = bstrs[1];
			*ppwszComputerName = bstrs[0];

			DbgPrint("CA: \"%s\"\r\nDNS: \"%s\"\r\n", *ppwszAuthority, *ppwszComputerName);
		}

		CACloseCA(hCAInfo);
	}

	return hr;
}

class DECLSPEC_UUID("d99e6e74-fc88-11d0-b498-00a0c90312f3") CCertRequestD;

HRESULT SendRequest(_Out_ CERTTRANSBLOB* pctbEncodedCert,
					_In_ ICertRequestD* pCrtReq,
					_In_ ULONG dwFlags,
					_In_ const CERTTRANSBLOB *pctbRequest, 
					_In_ PCWSTR pwszAuthority,
					_In_opt_ BSTR Attributes = 0)
{
	ULONG requestId = 0;

	union {
		HRESULT InternalError;
		ULONG dwDisposition;
	};

	CERTTRANSBLOB ctbCertChain {}, ctbDispositionMessage {};

	HRESULT hr = pCrtReq->Request(
		dwFlags,
		pwszAuthority, 
		&requestId, 
		&dwDisposition, 
		Attributes,
		pctbRequest,
		&ctbCertChain, 
		pctbEncodedCert, 
		&ctbDispositionMessage);
	
	if (0 <= hr)
	{
		char buf[16];
		DbgPrint("[ID=%x] CR_DISP_%S\r\n", requestId, GetDispositionString(dwDisposition, buf, _countof(buf)));

		if (ctbCertChain.pb)
		{
			CoTaskMemFree(ctbCertChain.pb);
		}

		if (ctbDispositionMessage.pb)
		{
			DbgPrint("msg: %s\r\n", ctbDispositionMessage.pb);
			CoTaskMemFree(ctbDispositionMessage.pb);
		}

		if (CR_DISP_ISSUED != dwDisposition)
		{
			hr = InternalError < 0 ? InternalError : E_FAIL;
		}
	}

	return hr;
}

HRESULT SendRequest(_Out_ CERTTRANSBLOB* pctbEncodedCert, 
					_In_ ULONG dwFlags,
					_In_ const CERTTRANSBLOB *pctbRequest,
					_In_ PCWSTR pwszAuthority,
					_In_ PWSTR pwszServerPrincName,
					_In_opt_ BSTR Attributes = 0)
{
	HRESULT hr;

	COSERVERINFO ServerInfo = { 
		0, pwszServerPrincName
	}; 

	MULTI_QI Result = { 
		&__uuidof(ICertRequestD) 
	};

	hr = CoCreateInstanceEx(__uuidof(CCertRequestD), 0, 
		CLSCTX_LOCAL_SERVER|CLSCTX_REMOTE_SERVER|CLSCTX_ENABLE_CLOAKING,
		&ServerInfo, 1, &Result);

	if (0 <= hr && 0 <= (hr = Result.hr))
	{
		if (0 <= (hr = CoSetProxyBlanket(
			Result.pItf, 
			RPC_C_AUTHN_DEFAULT, 
			RPC_C_AUTHZ_DEFAULT,
			COLE_DEFAULT_PRINCIPAL, 
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY, 
			RPC_C_IMP_LEVEL_IMPERSONATE,
			0, 
			EOAC_STATIC_CLOAKING)))
		{
			hr = SendRequest(pctbEncodedCert, 
				reinterpret_cast<ICertRequestD*>(Result.pItf), 
				dwFlags,
				pctbRequest, 
				pwszAuthority,
				Attributes);
		}

		Result.pItf->Release();
	}

	return hr;
}

HRESULT FormatAttributes(_Out_ BSTR* pAttributes)
{
	ULONG cch = 0;
	PWSTR ComputerName = 0;

	BSTR buf = 0;
	static const WCHAR rmd[] = L"rmd:";

	HRESULT hr;

	do 
	{
		SysFreeString(buf);

		if (cch)
		{
			if (!(buf = SysAllocStringLen(0, cch + _countof(rmd) - 2)))
			{
				return E_OUTOFMEMORY;
			}

			wcscpy(buf, rmd);

			ComputerName = buf + _countof(rmd) - 1;
		}

		hr = BOOL_TO_ERROR(GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, ComputerName, &cch));

	} while (ERROR_MORE_DATA == hr);

	if (NOERROR == hr)
	{
		*((PULONG)buf - 1) = (cch + _countof(rmd) - 1) * sizeof(WCHAR);
		*pAttributes = buf;
		return S_OK;
	}

	SysFreeString(buf);

	return hr;
}

// values for wszREGVERIFYFLAGS ("VerifyFlags")
#define CA_VERIFY_FLAGS_ALLOW_UNTRUSTED_ROOT (0x1)
#define CA_VERIFY_FLAGS_IGNORE_OFFLINE (0x2)
#define CA_VERIFY_FLAGS_NO_REVOCATION (0x4)
#define CA_VERIFY_FLAGS_FULL_CHAIN_REVOCATION (0x8)
#define CA_VERIFY_FLAGS_NT_AUTH (0x10)
#define CA_VERIFY_FLAGS_IGNORE_INVALID_POLICIES (0x20)
#define CA_VERIFY_FLAGS_IGNORE_NOREVCHECK (0x40)
#define CA_VERIFY_FLAGS_STRONG_SIGNATURE (0x80)
#define CA_VERIFY_FLAGS_MICROSOFT_ROOT (0x100)
#define CA_VERIFY_FLAGS_MICROSOFT_TEST_ROOT (0x200)
#define CA_VERIFY_FLAGS_FORCE_UPDATE (0x400)
#define CA_VERIFY_FLAGS_MICROSOFT_APPLICATION_ROOT (0x800)
#define CA_VERIFY_FLAGS_CONSOLE_TRACE (0x20000000)
#define CA_VERIFY_FLAGS_DUMP_CHAIN (0x40000000)
#define CA_VERIFY_FLAGS_SAVE_CHAIN (0x80000000)

namespace NT{
	void Help();

}
HRESULT FormatRequesterName(_In_ PCWSTR pszUserName, _Out_ PCRYPT_ATTR_BLOB RequesterName);

void FreeCryptProvOrNCryptKey(_In_ HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
							  _In_ ULONG dwKeySpec,
							  _In_ BOOL fCallerFreeProvOrNCryptKey)
{
	if (fCallerFreeProvOrNCryptKey)
	{
		if (CERT_NCRYPT_KEY_SPEC == dwKeySpec)
		{
			NCryptFreeObject(hCryptProvOrNCryptKey);
		}
		else
		{
			CryptReleaseContext(hCryptProvOrNCryptKey, 0);
		}
	}
}

struct CERT_AND_KEY 
{
	PCCERT_CONTEXT _M_pCertContext = 0;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE _M_hCryptProvOrNCryptKey = 0;
	ULONG _M_dwKeySpec = 0;
	BOOL _M_fCallerFreeProvOrNCryptKey = FALSE;

	~CERT_AND_KEY()
	{
		FreeCryptProvOrNCryptKey(_M_hCryptProvOrNCryptKey, _M_dwKeySpec, _M_fCallerFreeProvOrNCryptKey);
		CertFreeCertificateContext(_M_pCertContext);
	}
};

class __declspec(novtable) GetCertCommon 
{
	virtual HRESULT OnFind(
		_In_ PCCERT_CONTEXT pCertContext, 
		_In_ HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
		_In_ ULONG dwKeySpec,
		_In_ BOOL fCallerFreeProvOrNCryptKey,
		_In_ PCCERT_CHAIN_CONTEXT pChainContext
		) = 0;
public:

	HRESULT Search(_In_ ULONG dwFlags, _In_ PCSTR pszUsageIdentifier);
};

HRESULT GetCertCommon::Search(_In_ ULONG dwFlags, _In_ PCSTR pszUsageIdentifier)
{
	HRESULT hr;

	DbgPrint("Search for Cert with EKU %S\r\n", pszUsageIdentifier);

	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwFlags, L"My")))
	{
		CERT_CHAIN_PARA ChainPara = { 
			sizeof(ChainPara), { USAGE_MATCH_TYPE_AND, { 1, const_cast<PSTR*>(&pszUsageIdentifier) } } 
		};

		PCCERT_CONTEXT pCertContext = 0;

		while (pCertContext = HR(hr, CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 
			CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG, CERT_FIND_ENHKEY_USAGE, 
			&ChainPara.RequestedUsage.Usage, pCertContext)))
		{
			ULONG dwKeySpec;
			BOOL fCallerFreeProvOrNCryptKey;
			HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey;

			if (CryptAcquireCertificatePrivateKey(pCertContext, 
				CRYPT_ACQUIRE_COMPARE_KEY_FLAG|CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG, 
				0, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
			{
				PCCERT_CHAIN_CONTEXT pChainContext = 0;

				if (0 <= ValidateCert(pCertContext, &ChainPara, &pChainContext))
				{
					PrintCertOp(pCertContext, S_OK);

					hr = OnFind(pCertContext, hCryptProvOrNCryptKey, dwKeySpec, fCallerFreeProvOrNCryptKey, pChainContext);

					CertFreeCertificateChain(pChainContext);

					break;
				}

				FreeCryptProvOrNCryptKey(hCryptProvOrNCryptKey, dwKeySpec, fCallerFreeProvOrNCryptKey);
			}
		}

		CertCloseStore(hCertStore, 0);
	}

	return PrintError(hr), hr;
}

class GetEACert : public GetCertCommon, public CERT_AND_KEY
{
	virtual HRESULT OnFind(
		_In_ PCCERT_CONTEXT pCertContext, 
		_In_ HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
		_In_ ULONG dwKeySpec,
		_In_ BOOL fCallerFreeProvOrNCryptKey,
		_In_ PCCERT_CHAIN_CONTEXT /*pChainContext*/
		)
	{
		_M_pCertContext = pCertContext;
		_M_hCryptProvOrNCryptKey = hCryptProvOrNCryptKey;
		_M_dwKeySpec = dwKeySpec;
		_M_fCallerFreeProvOrNCryptKey = fCallerFreeProvOrNCryptKey;

		return S_OK;
	}
};

class GetKDCCert : public GetCertCommon
{
	PCWSTR _M_lpFileName, _M_ComputerName;

	virtual HRESULT OnFind(
		_In_ PCCERT_CONTEXT pCertContext, 
		_In_ HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
		_In_ ULONG dwKeySpec,
		_In_ BOOL fCallerFreeProvOrNCryptKey,
		_In_ PCCERT_CHAIN_CONTEXT pChainContext
		)
	{
		HRESULT hr;
		HCERTSTORE hCertStore;

		if (0 <= (hr = SaveChainToStore(pChainContext, &hCertStore)))
		{
			S_OK == (hr = CreateFakeCRL(hCertStore, _M_ComputerName)) &&
				NOERROR == (hr = BOOL_TO_ERROR(CertSaveStore(hCertStore, 0, 
				CERT_STORE_SAVE_AS_STORE, CERT_STORE_SAVE_TO_FILENAME_W, 
				const_cast<PWSTR>(_M_lpFileName), 0)));

			CertCloseStore(hCertStore, 0);
		}

		FreeCryptProvOrNCryptKey(hCryptProvOrNCryptKey, dwKeySpec, fCallerFreeProvOrNCryptKey);
		CertFreeCertificateContext(pCertContext);

		return hr;
	}

public:

	GetKDCCert(_In_ PCWSTR lpFileName, _In_ PCWSTR ComputerName) : _M_lpFileName(lpFileName), _M_ComputerName(ComputerName)
	{
	}
};

HRESULT ExportCA(_In_ PCWSTR lpFileName)
{
	HRESULT hr;

	union {
		PVOID buf;
		PWSTR ComputerName = 0;
	};

	ULONG cchMax = 0, cch = 0x40;

	PVOID stack = alloca(guz);
	do 
	{
		if (cchMax < cch)
		{
			cchMax = RtlPointerToOffset(buf = alloca((1 + cch - cchMax) * sizeof(WCHAR)), stack) / sizeof(WCHAR) - 1;
		}

		hr = BOOL_TO_ERROR(GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, ComputerName, &(cch = cchMax)));

	} while (ERROR_MORE_DATA == hr);

	if (NOERROR == hr)
	{
		if (wcschr(ComputerName, L'.'))
		{
			ComputerName[cch] = '$';
			ComputerName[cch + 1] = 0;

			GetKDCCert kdc(lpFileName, ComputerName);

			hr = kdc.Search(CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG|
				CERT_SYSTEM_STORE_LOCAL_MACHINE, szOID_PKINIT_KP_KDC);
		}
		else
		{
			hr = HRESULT_FROM_NT(STATUS_MUST_BE_KDC);
		}
	}

	return HRESULT_FROM_WIN32(hr);
}

HRESULT SignRequest(_In_ PCWSTR pszUserName, _Inout_ CERTTRANSBLOB* request, _Out_ PULONG pdwFlags)
{
	if (!*pszUserName)
	{
		return S_OK;
	}

	*pdwFlags = CR_IN_BINARY|CR_IN_PKCS7;

	HRESULT hr;
	CRYPT_ATTR_BLOB RequesterName {};

	if (0 <= (hr = FormatRequesterName(pszUserName, &RequesterName)))
	{
		GetEACert ea;

		if (0 <= (hr = ea.Search(CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG|
			CERT_SYSTEM_STORE_CURRENT_USER, szOID_ENROLLMENT_AGENT)))
		{
			CERTTRANSBLOB sig{};

			if (0 <= (hr = SignMsg(ea._M_pCertContext,
				ea._M_hCryptProvOrNCryptKey, ea._M_dwKeySpec,
				request, &RequesterName, &sig)))
			{
				LocalFree(request->pb);
				*request = sig;
			}
		}

		LocalFree(RequesterName.pbData);
	}

	return hr;
}

void WINAPI ep(PWSTR lpCommandLine)
{	
	InitPrintf();
	HRESULT hr;
	PWSTR argv[4];
	ULONG argc = 0;

	lpCommandLine = GetCommandLineW();

	while (lpCommandLine = wcschr(lpCommandLine, '*'))
	{
		*lpCommandLine++ = 0;

		argv[argc++] = lpCommandLine;

		if (_countof(argv) == argc)
		{
			break;
		}
	}

	if (!argc)
	{
		DbgPrint(
			"The syntax of this command is:\r\n"
			"\r\n"
			"CRT-UT [ v0 | v1 | v2 | v3 | v4 ]\r\n"
			"\r\n"
			"\tv0: *user*[UserName]*pfx-file-name*pass-for-pfx\r\n"
			"\tv1: *ea\r\n"
			"\tv2: *kdc\r\n"
			"\tv3: *export*sst-file-name\r\n"
			"\tv4: *import*sst-file-name\r\n"
			);

		ExitProcess((ULONG)STATUS_INVALID_PARAMETER_MIX);
	}

	if (0 <= (hr = CoInitializeEx(0, COINIT_MULTITHREADED|COINIT_DISABLE_OLE1DDE)))
	{
		//if (IsDebuggerPresent())__debugbreak();

		hr = HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);

		BSTR pwszComputerName = 0, pwszAuthority = 0;
		CERTTRANSBLOB ctbEncodedCert{}, request {};
		WCHAR szKeyName[32 + 40];

		if (!wcscmp(argv[0], L"user"))
		{
			// *user*[UPN[:password]]*pfx*password

			if (4 == argc)
			{
				ULONG dwFlags = CR_IN_BINARY|CR_IN_PKCS10;
				NCRYPT_KEY_HANDLE hKey;

				PWSTR pszUserName = argv[1];

				if (0 <= (hr = GetCAInfo(wszCERTTYPE_USER_SMARTCARD_LOGON, &pwszComputerName, &pwszAuthority)))
				{
					if (0 <= (hr = BuildPkcs10ForSL(&request, &hKey)))
					{
						if (0 <= (hr = SignRequest(pszUserName, &request, &dwFlags)))
						{
							if (0 <= (hr = SendRequest(&ctbEncodedCert, dwFlags, &request, pwszAuthority, pwszComputerName, 0)))
							{
								hr = ExportToPfx(argv[2], hKey, argv[3], ctbEncodedCert.pb, ctbEncodedCert.cb);
								CoTaskMemFree(ctbEncodedCert.pb);
							}
						}

						LocalFree(request.pb);
						NCryptFreeObject(hKey);
					}

					SysFreeString(pwszComputerName);
					SysFreeString(pwszAuthority);
				}
			}
		}
		else if (!wcscmp(argv[0], L"kdc"))
		{
			// *kdc
			if (1 == argc)
			{
				if (0 <= (hr = GetCAInfo(wszCERTTYPE_KERB_AUTHENTICATION, &pwszComputerName, &pwszAuthority)))
				{

					if (0 <= (hr = BuildPkcs10ForKDC(&request, szKeyName, _countof(szKeyName))))
					{
						BSTR Attributes = 0;
						FormatAttributes(&Attributes);

						static const TOKEN_PRIVILEGES tp_TCB = { 1, { { { SE_TCB_PRIVILEGE }, SE_PRIVILEGE_ENABLED } } };
						if (0 <= (hr = ImpersonateToken(&tp_TCB)))
						{
							hr = SendRequest(&ctbEncodedCert, CR_IN_BINARY|CR_IN_PKCS10, &request, pwszAuthority, pwszComputerName, Attributes);
							RtlRevertToSelf();
						}

						SysFreeString(Attributes);
						LocalFree(request.pb);

						if (0 <= hr)
						{
							hr = AddToMyStore(ctbEncodedCert.pb, ctbEncodedCert.cb, szKeyName, 
								CERT_SYSTEM_STORE_LOCAL_MACHINE, 
								NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
							CoTaskMemFree(ctbEncodedCert.pb);
						}
					}

					SysFreeString(pwszComputerName);
					SysFreeString(pwszAuthority);
				}
			}
		}
		else if (!wcscmp(argv[0], L"ea"))
		{
			// *ea
			if (1 == argc)
			{
				if (0 <= (hr = GetCAInfo(wszCERTTYPE_ENROLLMENT_AGENT, &pwszComputerName, &pwszAuthority)))
				{
					if (0 <= (hr = BuildPkcs10ForEA(&request, szKeyName, _countof(szKeyName))))
					{
						if (0 <= (hr = SendRequest(&ctbEncodedCert, CR_IN_BINARY|CR_IN_PKCS10, &request, pwszAuthority, pwszComputerName)))
						{
							hr = AddToMyStore(ctbEncodedCert.pb, ctbEncodedCert.cb, szKeyName,
								CERT_SYSTEM_STORE_CURRENT_USER, NCRYPT_SILENT_FLAG);
							CoTaskMemFree(ctbEncodedCert.pb);
						}

						LocalFree(request.pb);
					}

					SysFreeString(pwszComputerName);
					SysFreeString(pwszAuthority);
				}
			}
		}
		else if (!wcscmp(argv[0], L"export"))
		{
			// *export*file.sst
			if (2 == argc)
			{
				hr = ExportCA(argv[1]);
			}
		}
		else if (!wcscmp(argv[0], L"import"))
		{
			// *export*file.sst
			if (2 == argc)
			{
				hr = ImportCA(argv[1]);
			}
		}

		CoUninitialize();
	}

	ExitProcess(PrintError(hr));
}