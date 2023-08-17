#pragma once

struct CAPROP;
struct CATRANSPROP;
enum TestKeyAttResult;
enum LogPriority;

WINBASEAPI
HRESULT WINAPI myVerifyEKOrAIKCertContext(int,PCCERT_CONTEXT,ULONG,void *); // #875

WINBASEAPI
PCWSTR myHResultToStringRawEx(unsigned short *,unsigned __int64,long); // #874

WINBASEAPI
PCWSTR myHResultToStringEx(unsigned short *,unsigned __int64,long); // #873

WINBASEAPI
HRESULT WINAPI myVerifyCertContext(PCCERT_CONTEXT,ULONG,ULONG,PCSTR const *,void *,void *,unsigned short * *); // #872

WINBASEAPI
HRESULT WINAPI myVerifyEKPub(PCWSTR,PCWSTR,int *); // #871

WINBASEAPI
HRESULT WINAPI myVerifyEKCertContext(PCCERT_CONTEXT,ULONG,void *); // #870

WINBASEAPI
HRESULT WINAPI LoadTpmTestEnumErrorMessages(TestKeyAttResult,unsigned short * *); // #869

WINBASEAPI
HRESULT WINAPI myFileTimeToDate(_FILETIME const *,double *); // #868

WINBASEAPI
HRESULT WINAPI myGetAlgorithmNameFromPubKey(_CERT_PUBLIC_KEY_INFO const *,int,int *,unsigned short * *); // #867

WINBASEAPI
HRESULT WINAPI myGetIsSigningCertificate(PCCERT_CONTEXT,ULONG,unsigned __int64,bool *); // #866

WINBASEAPI
HRESULT WINAPI myCryptGetDefaultProvider(ULONG,PCWSTR,PCWSTR,ULONG,unsigned short * *,unsigned short * *); // #865

WINBASEAPI
void WINAPI CSPrintErrorInit(void (*)(SYSTEMTIME const *,PCWSTR,PCWSTR,PCWSTR,ULONG,long)); // #859

WINBASEAPI
HRESULT WINAPI CertcliGetDetailedCertcliVersionString(PCWSTR *); // #858

WINBASEAPI
void WINAPI myFreeColumnDisplayNames2(); // #857

WINBASEAPI
HRESULT WINAPI GetDetailedVersionString(PCWSTR,unsigned short * *); // #856

WINBASEAPI
HRESULT WINAPI myEnablePrivilege(long,int); // #855

WINBASEAPI
HRESULT WINAPI myGetHashAlgorithmOIDInfoFromSignatureAlgorithm(_CRYPT_ALGORITHM_IDENTIFIER const *,_CRYPT_OID_INFO const * *); // #854

WINBASEAPI
HRESULT WINAPI myGetTargetMachineDomainDnsName(PCWSTR,unsigned short * *,unsigned short * *,unsigned short * *); // #852

WINBASEAPI
HRESULT WINAPI AddOrRemoveOCSPISAPIExtension(int,int *); // #851

WINBASEAPI
HRESULT WINAPI SplitConfigString(PCWSTR,unsigned short * *,unsigned short * *); // #850

WINBASEAPI
HRESULT WINAPI RemoveISAPIExtension(PCWSTR); // #848

WINBASEAPI
LogPriority DbgLogStringInit2(void (*)(PCSTR),LogPriority); // #847

WINBASEAPI
void WINAPI CSPrintErrorLineFileData2(PCWSTR,ULONG,long,long); // #842

WINBASEAPI
void WINAPI CSPrintErrorLineFileData(PCWSTR,ULONG,long); // #841

WINBASEAPI
void WINAPI CSPrintErrorLineFile2(ULONG,long,long); // #840

WINBASEAPI
void WINAPI CSPrintErrorLineFile(ULONG,long); // #839

WINBASEAPI
HRESULT WINAPI myHGetLastError(); // #838

WINBASEAPI
int WINAPI mylstrcmpiL(PCWSTR,PCWSTR); // #837

WINBASEAPI
void WINAPI myGenerateGuidSerialNumber(_GUID *); // #836

WINBASEAPI
HRESULT WINAPI myGenerateGuidString(unsigned short * *); // #835

WINBASEAPI
HRESULT WINAPI myRevertSanitizeName(PCWSTR,unsigned short * *); // #834

WINBASEAPI
HRESULT WINAPI mySanitizedNameToShortName(PCWSTR,int,unsigned short * *); // #833

WINBASEAPI
HRESULT WINAPI mySanitizedNameToDSName(PCWSTR,unsigned short * *); // #832

WINBASEAPI
HRESULT WINAPI mySanitizeName(PCWSTR,unsigned short * *); // #831

WINBASEAPI
ULONG myGetSidFromDomain(unsigned short *,void * *); // #829

WINBASEAPI
HRESULT WINAPI IsISAPIExtensionEnabled(PCWSTR,bool &); // #827

WINBASEAPI
HRESULT WINAPI EnableASPInIIS(int *); // #826

WINBASEAPI
HRESULT WINAPI IsASPEnabledInIIS(bool &); // #825

WINBASEAPI
int DbgPrintfW(ULONG,PCWSTR,...); // #824

WINBASEAPI
HRESULT WINAPI myHExceptionCodePrint(EXCEPTION_POINTERS const *,PCSTR,ULONG,ULONG); // #823

WINBASEAPI
void WINAPI myLogExceptionInit(void (*)(long,EXCEPTION_POINTERS const *,PCSTR,ULONG,ULONG)); // #822

WINBASEAPI
HRESULT WINAPI myOIDHashOIDToString(PCWSTR,unsigned short * *); // #821

WINBASEAPI
HRESULT WINAPI myCAPropInfoLookup(CAPROP const *,long,long,CAPROP const * *); // #818

WINBASEAPI
HRESULT WINAPI myCAPropInfoUnmarshal(CATRANSPROP const *,long,ULONG,CAPROP * *); // #817

WINBASEAPI
HRESULT WINAPI myCAPropGetDisplayName(long,PCWSTR *); // #816

WINBASEAPI
unsigned short * myGetErrorMessageTextEx(long,ULONG,PCWSTR *,ULONG); // #815

WINBASEAPI
unsigned short * myGetErrorMessageText1(long,ULONG,PCWSTR); // #814

WINBASEAPI
HRESULT WINAPI WszToMultiByteInteger(ULONG,PCWSTR,ULONG *,unsigned char * *); // #813

WINBASEAPI
HRESULT WINAPI WszToMultiByteIntegerBuf(ULONG,PCWSTR,ULONG *,unsigned char *); // #812

WINBASEAPI
void WINAPI DbgLogStringInit(void (*)(PCSTR)); // #811

WINBASEAPI
HRESULT WINAPI myAddShare(PCWSTR,PCWSTR,PCWSTR,int,int *); // #810

WINBASEAPI
HRESULT WINAPI EncodeToFileW(PCWSTR,unsigned PCSTR,ULONG,ULONG); // #809

WINBASEAPI
HRESULT WINAPI DecodeFileW(PCWSTR,unsigned char * *,ULONG *,ULONG); // #808

WINBASEAPI
HRESULT WINAPI myModifyVirtualRootsAndFileShares(ULONG,ENUM_CATYPES,ULONG,ULONG *,ULONG *); // #807

WINBASEAPI
HRESULT WINAPI myJetHResult(HRESULT); // #806

WINBASEAPI
HRESULT WINAPI myHExceptionCode(EXCEPTION_POINTERS const *); // #805

WINBASEAPI
int WINAPI myIsDelayLoadHResult(HRESULT); // #804

WINBASEAPI
void WINAPI myFreeColumnDisplayNames(); // #802

WINBASEAPI
HRESULT WINAPI myDoesDSExist(int); // #801

WINBASEAPI
PCWSTR myHResultToStringRaw_old(unsigned short *,long); // #708

WINBASEAPI
unsigned short * myGetErrorMessageText(long,ULONG); // #707

WINBASEAPI
PCWSTR myHResultToString_old(unsigned short *,long); // #706

WINBASEAPI
int WINAPI DbgIsSSActive(ULONG); // #705

WINBASEAPI
void WINAPI DbgPrintfInit(PCSTR); // #704

WINBASEAPI
int WINAPI DbgPrintf(ULONG,PCSTR,...); // #703

WINBASEAPI
void WINAPI CSPrintError(PCSTR,PCWSTR,PCSTR,ULONG,long,long); // #702

WINBASEAPI
void WINAPI CSPrintAssert(PCSTR,PCSTR,ULONG,PCSTR); // #701

WINBASEAPI
HRESULT WINAPI myCryptBinaryToStringA(unsigned PCSTR,ULONG,ULONG,char * *); // #604

WINBASEAPI
HRESULT WINAPI myCryptStringToBinaryA(PCSTR,ULONG,ULONG,unsigned char * *,ULONG *,ULONG *,ULONG *); // #603

WINBASEAPI
HRESULT WINAPI myCryptBinaryToString(unsigned PCSTR,ULONG,ULONG,unsigned short * *); // #602

WINBASEAPI
HRESULT WINAPI myCryptStringToBinary(PCWSTR,ULONG,ULONG,unsigned char * *,ULONG *,ULONG *,ULONG *); // #601
