#include "StdAfx.h"

#include "util.h"

#define SHA1_HASH_LENGTH 20

void DumpBytes(const UCHAR* pb, ULONG cb, PCSTR prefix /*= ""*/, PCSTR suffix /*= ""*/);

HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ BYTE** ppbEncoded, _Inout_ ULONG *pcbEncoded)
{
	return GetLastHr(CryptEncodeObjectEx(X509_ASN_ENCODING, lpszStructType, 
		pvStructInfo, CRYPT_ENCODE_ALLOC_FLAG|CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, 0, ppbEncoded, pcbEncoded));
}

inline HRESULT EncodeObject(_In_ PCSTR lpszStructType, _In_ const void *pvStructInfo, _Out_ PDATA_BLOB blob)
{
	return EncodeObject(lpszStructType, pvStructInfo, &blob->pbData, &blob->cbData);
}

inline HRESULT EncodeExtension(_Out_ PCERT_EXTENSION Extension,
							   _In_ PCSTR pszObjId,
							   _In_ const void *pvStructInfo,
							   _In_ BOOL fCritical = FALSE,
							   _In_ PCSTR lpszStructType = 0 
							   )
{
	Extension->fCritical = fCritical;
	Extension->pszObjId = const_cast<PSTR>(pszObjId);
	return EncodeObject(lpszStructType ? lpszStructType : pszObjId, 
		pvStructInfo, &Extension->Value.pbData, &Extension->Value.cbData);
}

HRESULT EncodeCommonName(PCWSTR szName, PCERT_NAME_BLOB Subject)
{
	CERT_RDN_ATTR RDNAttr = { 
		const_cast<PSTR>(szOID_COMMON_NAME), CERT_RDN_UNICODE_STRING, { (ULONG)wcslen(szName) * sizeof(WCHAR), (PBYTE)szName }
	};

	CERT_RDN RDN = { 1, &RDNAttr };
	CERT_NAME_INFO cni = { 1, &RDN };

	return EncodeObject(X509_NAME, &cni, Subject);
}

HRESULT DoHash(PUCHAR pbData, ULONG cbData, PUCHAR pbOutput, ULONG cbOutput, PCWSTR pszAlgId)
{
	return GetLastHr(CryptHashCertificate2(pszAlgId, 0, 0, pbData, cbData, pbOutput, &cbOutput));
}

HRESULT 
OpenOrCreateKey(_Out_ NCRYPT_KEY_HANDLE *phKey, 
				_In_ PCWSTR pszKeyName,
				_In_ PCWSTR pszAlgId,
				_In_ ULONG Length,
				_In_ ULONG dwFlags)
{
	NCRYPT_PROV_HANDLE hProvider;

	NTSTATUS status = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0);

	if (NOERROR == status)
	{
		if (!pszKeyName || NTE_BAD_KEYSET == (status = NCryptOpenKey(hProvider, phKey, pszKeyName, 0, dwFlags)))
		{
			NCRYPT_KEY_HANDLE hKey;

			if (NOERROR == (status = NCryptCreatePersistedKey(hProvider, &hKey, pszAlgId, pszKeyName, 0, dwFlags)))
			{
				if ((status = (Length ? NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&Length, sizeof(Length), 0) : 0) ||
					(status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, 
					(PBYTE)&(dwFlags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG), sizeof(dwFlags), 0)) ||
					(status = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG))))
				{
					NCryptFreeObject(hKey);
				}
				else
				{
					*phKey = hKey;
				}
			}
		}

		NCryptFreeObject(hProvider);
	}

	return 0 < status ? (status & 0xFFFF) | (FACILITY_SSPI << 16) | 0x80000000 : status;
}

HRESULT SetRsaPublicKey(_Inout_ PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo, 
						_In_ PBYTE pbKey, _Out_ PBYTE pbKeyId, _In_ ULONG cbKeyId)
{
	SubjectPublicKeyInfo->Algorithm.pszObjId = const_cast<PSTR>(szOID_RSA_RSA);

	HRESULT hr = EncodeObject(CNG_RSA_PUBLIC_KEY_BLOB, pbKey, 
		&SubjectPublicKeyInfo->PublicKey.pbData, &SubjectPublicKeyInfo->PublicKey.cbData);

	if (0 <= hr)
	{
		hr = GetLastHr(CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0, 
			SubjectPublicKeyInfo->PublicKey.pbData, SubjectPublicKeyInfo->PublicKey.cbData,
			pbKeyId, &cbKeyId));
	}

	return hr;
}

HRESULT SetRsaPublicKey(_Inout_ PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo, 
						_In_ NCRYPT_KEY_HANDLE hKey,
						_Out_ PBYTE pbKeyId, 
						_In_ ULONG cbKeyId)
{
	PBYTE pbKey = 0;
	ULONG cbKey = 0;
	HRESULT hr;

	while (0 <= (hr = NCryptExportKey(hKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, pbKey, cbKey, &cbKey, 0)))
	{
		if (pbKey)
		{
			return SetRsaPublicKey(SubjectPublicKeyInfo, pbKey, pbKeyId, cbKeyId);
		}

		pbKey = (PBYTE)alloca(cbKey);
	}

	return hr;
}

void reverse(PBYTE pb, ULONG cb )
{
	if (cb)
	{
		PBYTE qb = pb + cb;

		do 
		{
			BYTE b = *--qb;
			*qb = *pb;
			*pb++ = b;
		} while (pb < qb);
	}
}

enum {
	H_RSA = 0x28B40C00, 
	H_ECDSA_P256 = 0x45AEE24E, 
	H_ECDSA_P384 = 0x462FF28A, 
	H_ECDSA_P521 = 0x4726100F
};

NTSTATUS GetAlgHash(_Out_ PULONG pAlgHash, _In_ NCRYPT_KEY_HANDLE hKey)
{
	WCHAR AlgorithmName[32];
	ULONG cb;

	NTSTATUS status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)AlgorithmName, sizeof(AlgorithmName), &cb, 0);

	if (0 > status)
	{
		return status;
	}

	UNICODE_STRING String;
	RtlInitUnicodeString(&String, AlgorithmName);
	return RtlHashUnicodeString(&String, FALSE, HASH_STRING_ALGORITHM_X65599, pAlgHash);
}

HRESULT 
EncodeSignAndEncode(_Out_ CERTTRANSBLOB* request,
					_Inout_ PULONG pAlgHash,
					_In_ NCRYPT_KEY_HANDLE hKey,
					_In_ PCSTR lpszInStructType, 
					_In_ const void *pvInStructInfo,
					_Out_opt_ PCRYPT_ALGORITHM_IDENTIFIER InSignatureAlgorithm, // inside pvInStructInfo
					_In_ PCSTR lpszOutStructType, 
					_In_ const void *pvOutStructInfo, 
					_In_ PCRYPT_DER_BLOB ToBeSigned, // inside pvOutStructInfo
					_Out_ PCRYPT_BIT_BLOB Signature, // inside pvOutStructInfo
					_Out_ PCRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm // inside pvOutStructInfo
			  )
{
	NTSTATUS status;

	ULONG AlgHash = *pAlgHash;

	if (!AlgHash)
	{
		if (0 > (status = GetAlgHash(&AlgHash, hKey)))
		{
			return status;
		}

		*pAlgHash = AlgHash;
	}

	BCRYPT_PKCS1_PADDING_INFO pi, *pPaddingInfo = 0;

	PSTR pszObjId = const_cast<PSTR>(szOID_ECDSA_SHA256);
	PCSTR AlgorithmParameter = 0;
	ULONG dwFlags = 0;

	switch (AlgHash)
	{
	case H_RSA: // "RSA" - BCRYPT_RSA_ALGORITHM
		pszObjId = const_cast<PSTR>(szOID_RSA_SHA256RSA);
		dwFlags = BCRYPT_PAD_PKCS1;
		pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
		pPaddingInfo = &pi;
		break;

	case H_ECDSA_P256: // "ECDSA_P256" - BCRYPT_ECDSA_P256_ALGORITHM
		AlgorithmParameter = szOID_ECC_CURVE_P256;
		break;

	case H_ECDSA_P384: // "ECDSA_P384" - BCRYPT_ECDSA_P384_ALGORITHM
		AlgorithmParameter = szOID_ECC_CURVE_P384;
		break;

	case H_ECDSA_P521: // "ECDSA_P521" - BCRYPT_ECDSA_P521_ALGORITHM
		AlgorithmParameter = szOID_ECC_CURVE_P521;
		break;

	default:
		return NTE_BAD_ALGID;
	}

	SignatureAlgorithm->pszObjId = pszObjId;

	if (AlgorithmParameter)
	{
		if (0 > (status = EncodeObject(X509_OBJECT_IDENTIFIER, &AlgorithmParameter, &SignatureAlgorithm->Parameters)))
		{
			return status;
		}
	}

	if (InSignatureAlgorithm)
	{
		*InSignatureAlgorithm = *SignatureAlgorithm;
	}

	if (0 <= (status = EncodeObject(lpszInStructType, pvInStructInfo, ToBeSigned)))
	{
		UCHAR hash[32];

		if (0 <= (status = DoHash(ToBeSigned->pbData, ToBeSigned->cbData, hash, sizeof(hash), BCRYPT_SHA256_ALGORITHM)))
		{
			while (0 <= (status = NCryptSignHash(hKey, pPaddingInfo, hash, sizeof(hash), 
				Signature->pbData, Signature->cbData, &Signature->cbData, dwFlags)))
			{
				if (Signature->pbData)
				{
					if (!dwFlags)
					{
						// ECC_CURVE
						ULONG cbData = Signature->cbData >> 1;

						CERT_ECC_SIGNATURE ecc_sign = { 
							{ cbData, Signature->pbData }, 
							{ cbData, Signature->pbData + cbData} 
						};

						reverse(ecc_sign.r.pbData, cbData);
						reverse(ecc_sign.s.pbData, cbData);

						status = EncodeObject(X509_ECC_SIGNATURE, &ecc_sign, &Signature->pbData, &Signature->cbData);
					}

					if (0 <= status)
					{
						status = GetLastHr(CryptEncodeObjectEx(X509_ASN_ENCODING, lpszOutStructType, 
							pvOutStructInfo, CRYPT_ENCODE_ALLOC_FLAG|CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, 
							0, &request->pb, &request->cb));

						if (!dwFlags)
						{
							LocalFree(Signature->pbData);
						}
					}

					break;
				}

				Signature->pbData = (PUCHAR)alloca(Signature->cbData);
			}
		}

		LocalFree(ToBeSigned->pbData);
	}

	if (AlgorithmParameter)
	{
		LocalFree(SignatureAlgorithm->Parameters.pbData);
	}

	return status;
}

HRESULT 
EncodeSignAndEncode(_Out_ CERTTRANSBLOB* request,
					_In_ NCRYPT_KEY_HANDLE hKey,
					_In_ PCSTR lpszStructType, 
					_In_ const void *pvStructInfo,
					_Out_opt_ PCRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm // inside pvStructInfo
					)
{
	CERT_SIGNED_CONTENT_INFO csci { };
	ULONG hAlgId = SignatureAlgorithm ? H_ECDSA_P256 : H_RSA;//0

	return EncodeSignAndEncode(request, &hAlgId, hKey, 
		lpszStructType, pvStructInfo, SignatureAlgorithm,
		X509_CERT, &csci, &csci.ToBeSigned, &csci.Signature, &csci.SignatureAlgorithm);
}

HRESULT myEncodeOsVersion(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue)
{
	ULONG M, m, b;
	RtlGetNtVersionNumbers(&M, &m, &b);
	char buf[32];
	CERT_NAME_VALUE cnvOSVer = { 
		CERT_RDN_IA5_STRING, { 
			(ULONG)sprintf_s(buf, _countof(buf), "%u.%u.%u." _CRT_STRINGIZE(VER_PLATFORM_WIN32_NT), M, m, b & 0x0FFFFFFF), (PBYTE)buf
		} 
	};

	Attribute->pszObjId = const_cast<PSTR>(szOID_OS_VERSION);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;
	return EncodeObject(X509_NAME_VALUE, &cnvOSVer, rgValue);
}

HRESULT myEncodeCspInfo(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue)
{
	CRYPT_CSP_PROVIDER CSPProvider { 0, const_cast<PWSTR>(MS_KEY_STORAGE_PROVIDER), {} };

	CERT_NAME_VALUE cnvCSP = { CERT_RDN_ENCODED_BLOB };

	if (HRESULT hr = EncodeObject(szOID_ENROLLMENT_CSP_PROVIDER, &CSPProvider, &cnvCSP.Value))
	{
		return hr;
	}

	Attribute->pszObjId = const_cast<PSTR>(szOID_ENROLLMENT_CSP_PROVIDER);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	return EncodeObject(X509_NAME_VALUE, &cnvCSP, rgValue);
}

void FreeBlocks(ULONG n, CRYPT_DER_BLOB rgValues[4])
{
	do 
	{
		if (PBYTE pb = rgValues[--n].pbData)
		{
			LocalFree(pb);
		}
	} while (n);
}

HRESULT EncodeUtf8String(PCWSTR pcsz, PDATA_BLOB rgValue)
{
	CERT_NAME_VALUE cnv = {
		CERT_RDN_UTF8_STRING, {
			(ULONG)wcslen(pcsz)*sizeof(WCHAR), (PBYTE)pcsz
		}
	};

	return EncodeObject(X509_UNICODE_NAME_VALUE, &cnv, rgValue);
}

HRESULT myEncodeClientInfo(PCRYPT_ATTRIBUTE Attribute, PDATA_BLOB rgValue, PCWSTR MachineName)
{
	CRYPT_DER_BLOB rgValues[4] = {};
	CRYPT_SEQUENCE_OF_ANY soa = { _countof(rgValues), rgValues };

	Attribute->pszObjId = const_cast<PSTR>(szOID_REQUEST_CLIENT_INFO);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	static const RequestClientInfoClientId ClientId = ClientIdTest;

	HRESULT hr;

	0 <= (hr = EncodeObject(X509_INTEGER, &ClientId, &rgValues[0])) &&
		0 <= (hr = EncodeUtf8String(MachineName, &rgValues[1])) &&
		0 <= (hr = EncodeUtf8String(L"NT AUTHORITY\\SYSTEM", &rgValues[2])) &&
		0 <= (hr = EncodeUtf8String(L"rbmm", &rgValues[3])) &&
		0 <= (hr = EncodeObject(X509_SEQUENCE_OF_ANY, &soa, rgValue));

	FreeBlocks(_countof(rgValues), rgValues);

	return hr;
}

HRESULT SetPolicy(PCERT_EXTENSION rgExtension, const CERT_ENHKEY_USAGE* EnKeyUsage)
{
	DWORD cUsageIdentifier = EnKeyUsage->cUsageIdentifier;
	PCERT_POLICY_INFO rgPolicyInfo = (PCERT_POLICY_INFO)alloca(cUsageIdentifier*sizeof(CERT_POLICY_INFO));
	CERT_POLICIES_INFO cpi { cUsageIdentifier, rgPolicyInfo };

	if (cUsageIdentifier)
	{
		PSTR *rgpszUsageIdentifier = EnKeyUsage->rgpszUsageIdentifier;
		do 
		{
			rgPolicyInfo->cPolicyQualifier = 0;
			rgPolicyInfo->rgPolicyQualifier = 0;
			rgPolicyInfo++->pszPolicyIdentifier = *rgpszUsageIdentifier++;
		} while (--cUsageIdentifier);
	}

	return EncodeExtension(rgExtension, szOID_APPLICATION_CERT_POLICIES, &cpi, FALSE, szOID_CERT_POLICIES);
}

HRESULT SetKeyUsage(PCERT_EXTENSION rgExtension, BYTE KeyUsage)
{
	CRYPT_BIT_BLOB IntendedKeyUsage = { sizeof(KeyUsage), &KeyUsage };

	return EncodeExtension(rgExtension, szOID_KEY_USAGE, &IntendedKeyUsage, TRUE);
}

HRESULT SetEnhancedKeyUsage(PCERT_EXTENSION rgExtension, const CERT_ENHKEY_USAGE* EnKeyUsage)
{
	return EncodeExtension(rgExtension, szOID_ENHANCED_KEY_USAGE, EnKeyUsage);
}

HRESULT SetEnhancedKeyUsage(PCERT_EXTENSION rgExtension, PCSTR szUsageIdentifier)
{
	CERT_ENHKEY_USAGE EnKeyUsage = { 1, const_cast<PSTR*>(&szUsageIdentifier) };
	return SetEnhancedKeyUsage(rgExtension, &EnKeyUsage);
}

HRESULT SetDnsName(PCERT_EXTENSION rgExtension, _In_ PCWSTR DnsName)
{
	CERT_ALT_NAME_ENTRY ane = { CERT_ALT_NAME_DNS_NAME, { (PCERT_OTHER_NAME)DnsName} };
	CERT_ALT_NAME_INFO ani = { 1, &ane };
	
	return EncodeExtension(rgExtension, szOID_SUBJECT_ALT_NAME2, &ani);
}

HRESULT SetUPN(PCERT_EXTENSION rgExtension, PCWSTR pcszUPN)
{
	CERT_NAME_VALUE cnv = { CERT_RDN_UNICODE_STRING, { 0, (PBYTE)pcszUPN } };
	CERT_OTHER_NAME con = { const_cast<PSTR>(szOID_NT_PRINCIPAL_NAME) };
	CERT_ALT_NAME_ENTRY ane = { CERT_ALT_NAME_OTHER_NAME, { &con } };
	CERT_ALT_NAME_INFO ani = { 1, &ane };

	HRESULT hr;

	if (0 <= (hr = EncodeObject(X509_UNICODE_ANY_STRING, &cnv, &con.Value)))
	{
		hr = EncodeExtension(rgExtension, szOID_SUBJECT_ALT_NAME2, &ani);
		LocalFree(con.Value.pbData);
	}

	return hr;
}

HRESULT SetKeyId(PCERT_EXTENSION rgExtension, _In_ PBYTE pbKeyId)
{
	CRYPT_HASH_BLOB KeyId = { SHA1_HASH_LENGTH, pbKeyId };

	return EncodeExtension(rgExtension, szOID_SUBJECT_KEY_IDENTIFIER, &KeyId);
}

HRESULT SetTemplateName(PCERT_EXTENSION rgExtension, _In_ PCWSTR pcszTemplateName)
{
	CERT_NAME_VALUE cnv = {
		CERT_RDN_UNICODE_STRING, {
			(ULONG)wcslen(pcszTemplateName)*sizeof(WCHAR), (PBYTE)pcszTemplateName
		}
	};

	return EncodeExtension(rgExtension, szOID_ENROLL_CERTTYPE_EXTENSION, &cnv, FALSE, X509_UNICODE_NAME_VALUE);
}

HRESULT myEncodeExtensions(_Out_ PCRYPT_ATTRIBUTE Attribute, 
						   _Out_ PDATA_BLOB rgValue, 
						   _In_ PBYTE pbKeyId,
						   _In_ PCWSTR pcszTemplateName,
						   _In_opt_ PCWSTR pcszUPN = 0
						   )
{
	CERT_EXTENSION rgExtension[4] = {};
	CERT_EXTENSIONS ext = { 0, rgExtension };

	Attribute->pszObjId = const_cast<PSTR>(szOID_RSA_certExtensions);
	Attribute->cValue = 1;
	Attribute->rgValue = rgValue;

	HRESULT hr;
	0 <= (hr = SetKeyId(&rgExtension[ext.cExtension++], pbKeyId)) &&
		0 <= (hr = SetTemplateName(&rgExtension[ext.cExtension++], pcszTemplateName)) &&
		0 <= (hr = pcszUPN ? SetUPN(&rgExtension[ext.cExtension++], pcszUPN) : S_OK) &&
		0 <= (hr = EncodeObject(X509_EXTENSIONS, &ext, rgValue));

	ULONG n = _countof(rgExtension);
	do 
	{
		if (PBYTE pb = rgExtension[--n].Value.pbData)
		{
			LocalFree(pb);
		}
	} while (n);

	return hr;
}

extern volatile const UCHAR guz;

HRESULT BuildPkcs10(_Out_ CERTTRANSBLOB* request,
					_Out_writes_(cchKeyName) PWSTR pszKeyName,
					_In_ ULONG cchKeyName,
					_In_ ULONG dwFlags,
					_In_ PCWSTR pcszTemplateName,
					_Out_opt_ NCRYPT_KEY_HANDLE* phKey = 0)
{
	if (cchKeyName - 1 < 32 + 8)
	{
		return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_4);
	}

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
			cchMax = RtlPointerToOffset(buf = alloca((cch - cchMax) * sizeof(WCHAR)), stack) / sizeof(WCHAR);
		}

		hr = BOOL_TO_ERROR(GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, ComputerName, &(cch = cchMax)));

	} while (ERROR_MORE_DATA == hr);

	if (NOERROR != hr)
	{
		goto __exit;
	}

	if (pszKeyName)
	{

		int len;

		if (0 > (len = swprintf_s(pszKeyName, cchKeyName - 32, L"te-%.32s-", pcszTemplateName)))
		{
			hr = HRESULT_FROM_NT(STATUS_INTERNAL_ERROR);
			goto __exit;
		}

		UCHAR md5[16];
		ULONG cb;
		if (!CryptHashCertificate2(BCRYPT_MD5_ALGORITHM, 0, 0, (PBYTE)ComputerName, cch*sizeof(WCHAR), md5, &(cb = sizeof(md5))) ||
			!CryptBinaryToStringW(md5, cb, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF, pszKeyName + len, &(cch = cchKeyName - len)))
		{
			hr = GetLastHr();
			goto __exit;
		}
	}

	NCRYPT_KEY_HANDLE hKey;

	if (S_OK == (hr = OpenOrCreateKey(&hKey, pszKeyName, BCRYPT_RSA_ALGORITHM, 2048, dwFlags)))
	{
		DATA_BLOB rgValues[4] = {};
		CRYPT_ATTRIBUTE rgAttribute[4];
		CERT_REQUEST_INFO cri = { CERT_REQUEST_V1, {}, {}, _countof(rgAttribute), rgAttribute };

		if (0 <= (hr = EncodeCommonName(L"", &cri.Subject)))
		{
			UCHAR KeyId[SHA1_HASH_LENGTH];

			if (0 <= (hr = SetRsaPublicKey(&cri.SubjectPublicKeyInfo, hKey, KeyId, sizeof(KeyId))))
			{
				0 <= (hr = myEncodeOsVersion(&rgAttribute[0], &rgValues[0])) &&
					0 <= (hr = myEncodeCspInfo(&rgAttribute[1], &rgValues[1])) &&
					0 <= (hr = myEncodeClientInfo(&rgAttribute[2], &rgValues[2], ComputerName)) &&
					0 <= (hr = myEncodeExtensions(&rgAttribute[3], &rgValues[3], KeyId, pcszTemplateName)) &&
					0 <= (hr = EncodeSignAndEncode(request, hKey, X509_CERT_REQUEST_TO_BE_SIGNED, &cri, 0));

				LocalFree(cri.SubjectPublicKeyInfo.PublicKey.pbData);
			}

			LocalFree(cri.Subject.pbData);
		}

		FreeBlocks(_countof(rgValues), rgValues);

		if (phKey && 0 <= hr)
		{
			*phKey = hKey;
		}
		else
		{
			NCryptFreeObject(hKey);
		}
	}

__exit:
	return HRESULT_FROM_WIN32(hr);
}

HRESULT BuildPkcs10ForKDC(_Out_ CERTTRANSBLOB* request, 
						  _Out_writes_(cchKeyName) PWSTR pszKeyName,
						  _In_ ULONG cchKeyName)
{
	HRESULT hr = IsSrvRunning(L"kdc");

	return 0 > hr ? HRESULT_FROM_NT(STATUS_MUST_BE_KDC) : 
		BuildPkcs10(request, pszKeyName, cchKeyName, NCRYPT_MACHINE_KEY_FLAG, wszCERTTYPE_KERB_AUTHENTICATION);
}

HRESULT BuildPkcs10ForSL(_Out_ CERTTRANSBLOB* request, _Out_ NCRYPT_KEY_HANDLE* phKey)
{
	return BuildPkcs10(request, 0, 0, 0, wszCERTTYPE_USER_SMARTCARD_LOGON, phKey);
}

HRESULT BuildPkcs10ForEA(_Out_ CERTTRANSBLOB* request, 
						 _Out_writes_(cchKeyName) PWSTR pszKeyName,
						 _In_ ULONG cchKeyName)
{
	return BuildPkcs10(request, pszKeyName, cchKeyName, 0, wszCERTTYPE_ENROLLMENT_AGENT);
}

HRESULT CreateFakeCRL(_In_ HCERTSTORE hStore, _In_ PCWSTR pszName)
{
	CRL_INFO ci = { CRL_V2 };

	HRESULT hr;

	if (0 <= (hr = EncodeCommonName(pszName, &ci.Issuer)))
	{
		NCRYPT_KEY_HANDLE hKey;
		if (0 <= OpenOrCreateKey(&hKey, 0, BCRYPT_ECDSA_P256_ALGORITHM, 256, 0))
		{
			GetSystemTimeAsFileTime(&ci.ThisUpdate);
			GetSystemTimeAsFileTime(&ci.NextUpdate);
			CERTTRANSBLOB db;
			hr = EncodeSignAndEncode(&db, hKey, X509_CERT_CRL_TO_BE_SIGNED, &ci, &ci.SignatureAlgorithm);
			NCryptFreeObject(hKey);
			if (0 <= hr)
			{
				hr = BOOL_TO_ERROR(CertAddEncodedCRLToStore(hStore, X509_ASN_ENCODING, db.pb, db.cb, CERT_STORE_ADD_NEW, 0));

				LocalFree(db.pb);
			}
		}

		LocalFree(ci.Issuer.pbData);
	}

	return hr;
}

HRESULT SignMsg(_In_ PCCERT_CONTEXT pCertContext,
				_In_ HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
				_In_ ULONG dwKeySpec,
				_In_ CERTTRANSBLOB* Msg, 
				_In_ PCRYPT_ATTR_BLOB RequesterName,
				_Out_ CERTTRANSBLOB* request)
{
	HRESULT hr;

	CRYPT_ATTRIBUTE AuthAttr = {
		const_cast<PSTR>(szOID_ENROLLMENT_NAME_VALUE_PAIR), 1, RequesterName
	};

	CMSG_SIGNER_ENCODE_INFO SignerEncodeInfo = { //szOID_NIST_sha256 //szOID_RSA_SHA256RSA
		sizeof(SignerEncodeInfo), pCertContext->pCertInfo, { hCryptProvOrNCryptKey }, 
		dwKeySpec, pCertContext->pCertInfo->SignatureAlgorithm, 0, 1, &AuthAttr 
	};

	CERT_BLOB CertEncoded = { pCertContext->cbCertEncoded, pCertContext->pbCertEncoded };

	CMSG_SIGNED_ENCODE_INFO SignedMsgEncodeInfo = {
		sizeof(SignedMsgEncodeInfo), 1, &SignerEncodeInfo, 1, &CertEncoded
	};

	if (HCRYPTMSG hCryptMsg = HR(hr, CryptMsgOpenToEncode(
		PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &SignedMsgEncodeInfo, 0, 0)))
	{
		if (HR(hr, CryptMsgUpdate(hCryptMsg, Msg->pb, Msg->cb, TRUE)))
		{
			PBYTE pbEncodedBlob = 0;
			ULONG cbEncodedBlob = 0;

			while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CONTENT_PARAM, 0, pbEncodedBlob, &cbEncodedBlob)))
			{
				if (pbEncodedBlob)
				{
					request->pb = pbEncodedBlob;
					request->cb = cbEncodedBlob;
					pbEncodedBlob = 0;
					break;
				}

				if (!(pbEncodedBlob = (PBYTE)LocalAlloc(LMEM_FIXED, cbEncodedBlob)))
				{
					hr = HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
					break;
				}
			}

			if (pbEncodedBlob)
			{
				LocalFree(pbEncodedBlob);
			}
		}

		CryptMsgClose(hCryptMsg);
	}
	
	return HRESULT_FROM_WIN32(hr);
}

HRESULT FormatRequesterName(_In_ PCWSTR pszUserName, _Out_ PCRYPT_ATTR_BLOB RequesterName)
{
	NTSTATUS status;
	LSA_HANDLE PolicyHandle;
	LONG FACILITY = FACILITY_NT_BIT;

	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { sizeof(ObjectAttributes) };

	DbgPrint("user: \"%s\"\r\n", pszUserName);

	if (0 <= (status = LsaOpenPolicy(0, &ObjectAttributes, POLICY_LOOKUP_NAMES, &PolicyHandle)))
	{
		UNICODE_STRING Name, *DomainName;
		RtlInitUnicodeString(&Name, pszUserName);

		ULONG DomainIndex;
		PLSA_REFERENCED_DOMAIN_LIST ReferencedDomains;
		PLSA_TRANSLATED_SID2 Sids;
		PLSA_TRANSLATED_NAME Names;

		status = LsaLookupNames2(PolicyHandle, 0, 1, &Name, &(ReferencedDomains = 0), &(Sids = 0));
		
		LsaFreeMemory(ReferencedDomains);

		if (0 > status)
		{
			DbgPrint("!! %s -> %x\r\n", pszUserName, status);
		}
		else if (Sids->Use == SidTypeUser)
		{
			if (0 <= (status = LsaLookupSids2(PolicyHandle, 0, 1, &Sids->Sid, &(ReferencedDomains = 0), &(Names = 0))))
			{
				if ((DomainIndex = Names->DomainIndex) < ReferencedDomains->Entries)
				{
					DomainName = &ReferencedDomains->Domains[DomainIndex].Name;

					status = STATUS_INTERNAL_ERROR;

					int len = 0;
					CRYPT_ENROLLMENT_NAME_VALUE_PAIR cenvp { const_cast<PWSTR>(L"RequesterName") };

					while (0 < (len = _snwprintf(cenvp.pwszValue, len, L"%wZ\\%wZ", DomainName, &Names->Name)))
					{
						if (cenvp.pwszValue)
						{
							DbgPrint("%s= \"%s\"\r\n", cenvp.pwszName, cenvp.pwszValue);

							FACILITY = 0;

							status = EncodeObject(szOID_ENROLLMENT_NAME_VALUE_PAIR, &cenvp, RequesterName);
							break;
						}

						cenvp.pwszValue = (PWSTR)alloca(++len * sizeof(WCHAR));
					}
				}
				else
				{
					status = STATUS_INTERNAL_ERROR;
				}
			}

			LsaFreeMemory(ReferencedDomains);
			LsaFreeMemory(Names);

		}
		else
		{
			status = STATUS_NO_SUCH_USER;
			DbgPrint("!! SID_NAME_USE: %x\r\n", Sids->Use);
		}

		LsaFreeMemory(Sids);

		LsaClose(PolicyHandle);
	}

	return status ? status|FACILITY : S_OK;
}