#include "stdafx.h"

PCSTR GetEncodeName(ULONG u)
{
	switch (u)
	{
	case 1: return "X509_CERT";
	case 2: return "X509_CERT_TO_BE_SIGNED";
	case 3: return "X509_CERT_CRL_TO_BE_SIGNED";
	case 4: return "X509_CERT_REQUEST_TO_BE_SIGNED";
	case 5: return "X509_EXTENSIONS";
	case 6: return "X509_NAME_VALUE";
	case 7: return "X509_NAME";
	case 8: return "X509_PUBLIC_KEY_INFO";
	case 9: return "X509_AUTHORITY_KEY_ID";
	case 10: return "X509_KEY_ATTRIBUTES";
	case 11: return "X509_KEY_USAGE_RESTRICTION";
	case 12: return "X509_ALTERNATE_NAME";
	case 13: return "X509_BASIC_CONSTRAINTS";
	case 14: return "X509_KEY_USAGE";
	case 15: return "X509_BASIC_CONSTRAINTS2";
	case 16: return "X509_CERT_POLICIES";
	case 17: return "PKCS_UTC_TIME";
	case 18: return "PKCS_TIME_REQUEST";
	case 19: return "RSA_CSP_PUBLICKEYBLOB";
	case 20: return "X509_UNICODE_NAME";
	case 21: return "X509_KEYGEN_REQUEST_TO_BE_SIGNED";
	case 22: return "PKCS_ATTRIBUTE";
	case 23: return "PKCS_CONTENT_INFO_SEQUENCE_OF_ANY";
	case 24: return "X509_UNICODE_NAME_VALUE";
	case 25: return "X509_OCTET_STRING";
	case 26: return "X509_BITS";
	case 27: return "X509_INTEGER";
	case 28: return "X509_MULTI_BYTE_INTEGER";
	case 29: return "X509_ENUMERATED";
	case 30: return "X509_CHOICE_OF_TIME";
	case 31: return "X509_AUTHORITY_KEY_ID2";
	case 32: return "X509_AUTHORITY_INFO_ACCESS";
	case 33: return "PKCS_CONTENT_INFO";
	case 34: return "X509_SEQUENCE_OF_ANY";
	case 35: return "X509_CRL_DIST_POINTS";
	case 36: return "X509_ENHANCED_KEY_USAGE";
	case 37: return "PKCS_CTL";
	case 38: return "X509_MULTI_BYTE_UINT";
	case 39: return "X509_DSS_PARAMETERS";
	case 40: return "X509_DSS_SIGNATURE";
	case 41: return "PKCS_RC2_CBC_PARAMETERS";
	case 42: return "PKCS_SMIME_CAPABILITIES";
		//case 42: return "X509_QC_STATEMENTS_EXT";
	case 43: return "PKCS_RSA_PRIVATE_KEY";
	case 44: return "PKCS_PRIVATE_KEY_INFO";
	case 45: return "PKCS_ENCRYPTED_PRIVATE_KEY_INFO";
	case 46: return "X509_PKIX_POLICY_QUALIFIER_USERNOTICE";
	case 47: return "X509_DH_PARAMETERS";
	case 48: return "PKCS_ATTRIBUTES";
	case 49: return "PKCS_SORTED_CTL";
		//case 47: return "X509_ECC_SIGNATURE";
	case 50: return "X942_DH_PARAMETERS";
	case 51: return "X509_BITS_WITHOUT_TRAILING_ZEROES";
	case 52: return "X942_OTHER_INFO";
	case 53: return "X509_CERT_PAIR";
	case 54: return "X509_ISSUING_DIST_POINT";
	case 55: return "X509_NAME_CONSTRAINTS";
	case 56: return "X509_POLICY_MAPPINGS";
	case 57: return "X509_POLICY_CONSTRAINTS";
	case 58: return "X509_CROSS_CERT_DIST_POINTS";
	case 59: return "CMC_DATA";
	case 60: return "CMC_RESPONSE";
	case 61: return "CMC_STATUS";
	case 62: return "CMC_ADD_EXTENSIONS";
	case 63: return "CMC_ADD_ATTRIBUTES";
	case 64: return "X509_CERTIFICATE_TEMPLATE";
	case 65: return "OCSP_SIGNED_REQUEST";
	case 66: return "OCSP_REQUEST";
	case 67: return "OCSP_RESPONSE";
	case 68: return "OCSP_BASIC_SIGNED_RESPONSE";
	case 69: return "OCSP_BASIC_RESPONSE";
	case 70: return "X509_LOGOTYPE_EXT";
	case 71: return "X509_BIOMETRIC_EXT";
	case 72: return "CNG_RSA_PUBLIC_KEY_BLOB";
	case 73: return "X509_OBJECT_IDENTIFIER";
	case 74: return "X509_ALGORITHM_IDENTIFIER";
	case 75: return "PKCS_RSA_SSA_PSS_PARAMETERS";
	case 76: return "PKCS_RSAES_OAEP_PARAMETERS";
	case 77: return "ECC_CMS_SHARED_INFO";
	case 78: return "TIMESTAMP_REQUEST";
	case 79: return "TIMESTAMP_RESPONSE";
	case 80: return "TIMESTAMP_INFO";
	case 81: return "X509_CERT_BUNDLE";
	case 82: return "X509_ECC_PRIVATE_KEY";
	case 83: return "CNG_RSA_PRIVATE_KEY_BLOB";
	case 84: return "X509_SUBJECT_DIR_ATTRS";
	case 85: return "X509_ECC_PARAMETERS";
	case 500: return "PKCS7_SIGNER_INFO";
	case 501: return "CMS_SIGNER_INFO";	
	}

	return 0;
}

#pragma warning(disable : 4838)

static const LONG known_enc_mask[] = {
	0xfffffffe, 0xffffffff, 0x003fffff, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00300000,
};

typedef CONST UCHAR *PCUCHAR;

struct OID_NAME { PCSTR pszObjId, pszMacro; };

static const OID_NAME _s_onames[] = {
	{ "1.2.840.113549.1.1.7", "szOID_RSAES_OAEP" },
	{ "1.2.840.113549.1.1.10", "szOID_RSA_SSA_PSS" },
	{ "1.2.840.113549.1.9.5", "szOID_RSA_signingTime" },
	{ "1.2.840.113549.1.9.14", "szOID_RSA_certExtensions" },
	{ "1.2.840.113549.1.9.15", "szOID_RSA_SMIMECapabilities" },
	{ "1.2.840.113549.3.2", "szOID_RSA_RC2CBC" },
	{ "1.2.840.10045.2.1", "szOID_ECC_PUBLIC_KEY" },
	{ "1.2.840.10045.4.3", "szOID_ECDSA_SPECIFIED" },
	{ "2.5.29.1", "szOID_AUTHORITY_KEY_IDENTIFIER" },
	{ "2.5.29.2", "szOID_KEY_ATTRIBUTES" },
	{ "2.5.29.3", "szOID_CERT_POLICIES_95" },
	{ "2.5.29.4", "szOID_KEY_USAGE_RESTRICTION" },
	{ "2.5.29.7", "szOID_SUBJECT_ALT_NAME" },
	{ "2.5.29.8", "szOID_ISSUER_ALT_NAME" },
	{ "2.5.29.10", "szOID_BASIC_CONSTRAINTS" },
	{ "2.5.29.15", "szOID_KEY_USAGE" },
	{ "2.5.29.19", "szOID_BASIC_CONSTRAINTS2" },
	{ "2.5.29.32", "szOID_CERT_POLICIES" },
	{ "2.5.29.54", "szOID_INHIBIT_ANY_POLICY" },
	{ "2.5.29.35", "szOID_AUTHORITY_KEY_IDENTIFIER2" },
	{ "2.5.29.14", "szOID_SUBJECT_KEY_IDENTIFIER" },
	{ "2.5.29.17", "szOID_SUBJECT_ALT_NAME2" },
	{ "2.5.29.18", "szOID_ISSUER_ALT_NAME2" },
	{ "2.5.29.21", "szOID_CRL_REASON_CODE" },
	{ "2.5.29.31", "szOID_CRL_DIST_POINTS" },
	{ "2.5.29.37", "szOID_ENHANCED_KEY_USAGE" },
	{ "2.5.29.20", "szOID_CRL_NUMBER" },
	{ "2.5.29.27", "szOID_DELTA_CRL_INDICATOR" },
	{ "2.5.29.28", "szOID_ISSUING_DIST_POINT" },
	{ "2.5.29.46", "szOID_FRESHEST_CRL" },
	{ "2.5.29.30", "szOID_NAME_CONSTRAINTS" },
	{ "2.5.29.33", "szOID_POLICY_MAPPINGS" },
	{ "2.5.29.5", "szOID_LEGACY_POLICY_MAPPINGS" },
	{ "2.5.29.36", "szOID_POLICY_CONSTRAINTS" },
	{ "1.3.6.1.4.1.311.13.2.1", "szOID_ENROLLMENT_NAME_VALUE_PAIR" },
	{ "1.3.6.1.4.1.311.13.2.2", "szOID_ENROLLMENT_CSP_PROVIDER" },
	{ "1.3.6.1.5.5.7.1.1", "szOID_AUTHORITY_INFO_ACCESS" },
	{ "1.3.6.1.5.5.7.1.11", "szOID_SUBJECT_INFO_ACCESS" },
	{ "1.3.6.1.5.5.7.1.2", "szOID_BIOMETRIC_EXT" },
	{ "1.3.6.1.5.5.7.1.3", "szOID_QC_STATEMENTS_EXT" },
	{ "1.3.6.1.5.5.7.1.12", "szOID_LOGOTYPE_EXT" },
	{ "1.3.6.1.4.1.311.2.1.14", "szOID_CERT_EXTENSIONS" },
	{ "1.3.6.1.4.1.311.10.2", "szOID_NEXT_UPDATE_LOCATION" },
	{ "1.3.6.1.4.1.311.10.9.1", "szOID_CROSS_CERT_DIST_POINTS" },
	{ "1.3.6.1.4.1.311.10.1", "szOID_CTL" },
	{ "1.3.6.1.4.1.311.21.7", "szOID_CERTIFICATE_TEMPLATE" },
	{ "2.5.29.9", "szOID_SUBJECT_DIR_ATTRS" },
	{ "1.3.6.1.5.5.7.2.2", "szOID_PKIX_POLICY_QUALIFIER_USERNOTICE" },
	{ "2.16.840.1.113733.1.7.1.1", "szOID_CERT_POLICIES_95_QUALIFIER1" },
	{ "2.5.4.52", "szOID_ATTR_SUPPORTED_ALGORITHMS" },
	{ "2.23.133.2.16", "szOID_ATTR_TPM_SPECIFICATION" },
	{ "1.3.6.1.5.5.7.48.1.1", "szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE" },
	{ "1.2.840.113549.1.9.16.2.12", "" },
	{ "1.2.840.113549.1.9.16.2.11", "" },
	{ "1.2.840.113549.1.9.16.2.4", "" },
	{ "1.2.840.113549.1.9.16.2.3", "" },
	{ "1.2.840.113549.1.9.16.2.2", "" },
	{ "1.2.840.113549.1.9.16.2.1", "" },
	{ "1.2.840.113549.1.9.16.1.1", "" },
	{ "1.3.6.1.4.1.311.16.4", "" },
	{ "1.3.6.1.4.1.311.16.1.1", "" },
	{ "1.3.6.1.4.1.311.12.2.3", "" },
	{ "1.3.6.1.4.1.311.12.2.2", "" },
	{ "1.3.6.1.4.1.311.12.2.1", "" },
	{ "1.3.6.1.4.1.311.10.11.85", "" },
	{ "1.3.6.1.4.1.311.2.4.4", "" },
	{ "1.3.6.1.4.1.311.2.4.3", "" },
	{ "1.3.6.1.4.1.311.2.4.2", "" },
	{ "1.3.6.1.4.1.311.2.1.30", "" },
	{ "1.3.6.1.4.1.311.2.1.28", "" },
	{ "1.3.6.1.4.1.311.2.1.27", "" },
	{ "1.3.6.1.4.1.311.2.1.26", "" },
	{ "1.3.6.1.4.1.311.2.1.25", "" },
	{ "1.3.6.1.4.1.311.2.1.20", "" },
	{ "1.3.6.1.4.1.311.2.1.15", "" },
	{ "1.3.6.1.4.1.311.2.1.12", "" },
	{ "1.3.6.1.4.1.311.2.1.11", "" },
	{ "1.3.6.1.4.1.311.2.1.10", "" },
	{ "1.3.6.1.4.1.311.2.1.4", "" },
};

void TestDecode(PCUCHAR pb, ULONG cb)
{
	ULONG i = (ULONG)(ULONG_PTR)CMS_SIGNER_INFO;
	ULONG cbStructInfo;
	PVOID pvStructInfo;

	do 
	{
		if (_bittest(known_enc_mask, i))
		{
			if (CryptDecodeObjectEx(X509_ASN_ENCODING, (PCSTR)(ULONG_PTR)i, 
				pb, cb, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &pvStructInfo, &cbStructInfo))
			{
				DbgPrint("\t!!\t%s\n", GetEncodeName(i));
				LocalFree(pvStructInfo);
			}
		}
	} while (--i);

	i = _countof(_s_onames);

	do 
	{
		if (CryptDecodeObjectEx(X509_ASN_ENCODING, _s_onames[--i].pszObjId, 
			pb, cb, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG|CRYPT_DECODE_SHARE_OID_STRING_FLAG, 0, &pvStructInfo, &cbStructInfo))
		{
			DbgPrint("\t!!\t%s ( %s )\n", _s_onames[i].pszObjId, _s_onames[i].pszMacro);
			LocalFree(pvStructInfo);
		}
	} while (i);
}

void TestDecode(PDATA_BLOB pdb)
{
	TestDecode(pdb->pbData, pdb->cbData);
}

#if 0
HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PDATA_BLOB pdb, _In_ ULONG MaxSize = 0x1000000, _In_ ULONG MinSize = 0x10);

namespace NT {;

#include "../winZ/str.h"

static const PCSTR st[] = {
	"2.5.29.1",
	"2.5.29.2",
	"2.5.29.3",
	"2.5.29.4",
	"2.5.29.5",
	"2.5.29.7",
	"2.5.29.8",
	"2.5.29.9",
	"2.5.29.10",
	"2.5.29.14",
	"2.5.29.15",
	"2.5.29.17",
	"2.5.29.18",
	"2.5.29.19",
	"2.5.29.20",
	"2.5.29.21",
	"2.5.29.27",
	"2.5.29.28",
	"2.5.29.30",
	"2.5.29.31",
	"2.5.29.32",
	"2.5.29.33",
	"2.5.29.35",
	"2.5.29.36",
	"2.5.29.37",
	"2.5.29.46",
	"2.5.29.54",
	"2.5.4.52",
	"2.16.840.1.113733.1.7.1.1",
	"2.23.133.2.16",
	"1.3.6.1.4.1.311.2.1.4",
	"1.3.6.1.4.1.311.2.1.10",
	"1.3.6.1.4.1.311.2.1.11",
	"1.3.6.1.4.1.311.2.1.12",
	"1.3.6.1.4.1.311.2.1.14",
	"1.3.6.1.4.1.311.2.1.15",
	"1.3.6.1.4.1.311.2.1.20",
	"1.3.6.1.4.1.311.2.1.25",
	"1.3.6.1.4.1.311.2.1.26",
	"1.3.6.1.4.1.311.2.1.27",
	"1.3.6.1.4.1.311.2.1.28",
	"1.3.6.1.4.1.311.2.1.30",
	"1.3.6.1.4.1.311.2.4.2",
	"1.3.6.1.4.1.311.2.4.3",
	"1.3.6.1.4.1.311.2.4.4",
	"1.3.6.1.4.1.311.10.1",
	"1.3.6.1.4.1.311.10.2",
	"1.3.6.1.4.1.311.10.9.1",
	"1.3.6.1.4.1.311.10.11.85",
	"1.3.6.1.4.1.311.12.2.1",
	"1.3.6.1.4.1.311.12.2.2",
	"1.3.6.1.4.1.311.12.2.3",
	"1.3.6.1.4.1.311.13.2.1",
	"1.3.6.1.4.1.311.13.2.2",
	"1.3.6.1.4.1.311.16.1.1",
	"1.3.6.1.4.1.311.16.4",
	"1.3.6.1.4.1.311.21.7",
	"1.3.6.1.5.5.7.1.1",
	"1.3.6.1.5.5.7.1.2",
	"1.3.6.1.5.5.7.1.3",
	"1.3.6.1.5.5.7.1.11",
	"1.3.6.1.5.5.7.1.12",
	"1.3.6.1.5.5.7.2.2",
	"1.3.6.1.5.5.7.48.1.1",
	"1.2.840.10045.2.1",
	"1.2.840.10045.4.3",
	"1.2.840.113549.1.1.7",
	"1.2.840.113549.1.1.10",
	"1.2.840.113549.1.9.5",
	"1.2.840.113549.1.9.14",
	"1.2.840.113549.1.9.15",
	"1.2.840.113549.1.9.16.1.1",
	"1.2.840.113549.1.9.16.2.1",
	"1.2.840.113549.1.9.16.2.2",
	"1.2.840.113549.1.9.16.2.3",
	"1.2.840.113549.1.9.16.2.4",
	"1.2.840.113549.1.9.16.2.11",
	"1.2.840.113549.1.9.16.2.12",
	"1.2.840.113549.3.2",
};

void do_j(PCSTR pa, PCSTR pb)
{
	LONG bits[32]{};
	//PCSTR dd = _strnstr(pa, pb, "1.3.6.1.4.1.311.13.1");

	while (pa = _strnstr(pa, pb, "\n#define"))
	{
		if (PSTR pc = _strnchr(pa, pb, '\r'))
		{
			//if (dd<pc)__debugbreak();

			for (;;)
			{
				switch (*pa++)
				{
				case '\t':
				case ' ':
					continue;
				}

				break;
			}

			PCSTR pszMacro = pa - 1;

			for (;;)
			{
				switch (*pa++)
				{
				case '\t':
				case ' ':
				case '\r':
					break;
				default:
					continue;
				}

				break;
			}

			PCSTR pszMacro_ = pa - 1;

			PCSTR _pc = pc - 1;

			if (pa < _pc)
			{
				if (pa = _strnchr(pa, _pc, '\"'))
				{
					if (PCSTR py = _strnchr(pa, _pc, '\"'))
					{
						if (size_t len = --py - pa)
						{
							ULONG i = _countof(st);
							do 
							{
								PCSTR pszOid = st[--i];
								if (!memcmp(pa, pszOid, len) && !pszOid[len])
								{
									DbgPrint("%s{ \"%s\", \"%.*s\" },\n", _bittestandset(bits, i) ? "// " : "", 
										pszOid, pszMacro_ - pszMacro, pszMacro);
								}
							} while (i);
						}
					}
				}
			}

			pa = pc;

			continue;
		}
		break;
	}

	ULONG i = _countof(st);
	do 
	{
		if (!_bittest(bits, --i))
		{
			DbgPrint("{ \"%s\", \"\" }\n",  st[i]);
		}
	} while (i);
}

void Help()
{
	DATA_BLOB db;
	if (0 <= ReadFromFile(L"c:\\inc\\um\\wincrypt.h", &db))
	{
		do_j((PCSTR)db.pbData, (PCSTR)db.pbData + db.cbData);
		LocalFree(db.pbData);
	}
}

}
#endif