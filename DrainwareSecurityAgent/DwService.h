// DwService.h: declaración de CDwService

#pragma once
#include "resource.h"       // Símbolos principales



#include "DrainwareSecurityAgent_i.h"
#include "_IDwServiceEvents_CP.H"



#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Los objetos COM de un único subproceso no se admiten completamente en la plataforma Windows CE, como por ejemplo la plataforma Windows Mobile, que no incluye la compatibilidad DCOM completa. Defina _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA para que ATL tenga que admitir la creación de objetos COM de un único subproceso y permitir el uso de sus implementaciones de este tipo de objetos. El modelo de subprocesos del archivo rgs estaba establecido en 'Free' ya que es el único modelo de subprocesos admitido en plataformas que no son Windows CE DCOM."
#endif

using namespace ATL;


// CDwService

class ATL_NO_VTABLE CDwService :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CDwService, &CLSID_DwService>,
	public IDispatchImpl<IDwService, &IID_IDwService, &LIBID_DrainwareSecurityAgentLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
	public IConnectionPointContainerImpl<CDwService>,
	public CProxy_IDwServiceEvents<CDwService>
{
public:
	CDwService() : m_thMonitor( NULL ), m_pUserData( NULL )
	{
	}

DECLARE_REGISTRY_RESOURCEID(IDR_DWSERVICE)


BEGIN_COM_MAP(CDwService)
	COM_INTERFACE_ENTRY(IDwService)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY(IConnectionPointContainer)
END_COM_MAP()

BEGIN_CONNECTION_POINT_MAP(CDwService)
	CONNECTION_POINT_ENTRY(__uuidof(_IDwServiceEvents))
END_CONNECTION_POINT_MAP()

	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct();
	void FinalRelease();
	void LoadDDIConfig();
	void LoadDDIConfig( CStringA &strConfig );
	void LoadDDIConfigFromRegistry();
	void GetScreenShot( PBYTE &pBuffer, size_t &nSize );
	void SaveDDIConfig( const CStringA &strConfig );
	void PrinterSetPort( PTSTR szPrinterName, PTSTR szPortname = _T("DwPort:") );
	void PrintJobPS( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName );
	void PrintJobImg( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName );
	void PrintJob( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName );
	bool IsMappedDrive( PCTSTR szOrg, CString &strUNCPath );
	void Close( VARIANT_BOOL bUpdate );
	static DWORD WINAPI ThreadMonitor( PVOID pVoid );

	CString m_strUserName;
	CAccessToken m_token;
	DWORD m_dwClientProcID;
	CEvent m_evtMonitor;
	HANDLE m_thMonitor;
	CUserData *m_pUserData;

	//CStringA m_strScreenShot;
public:
	STDMETHOD(CheckText)( BSTR bstrText, TEXT_TYPE nTextType, BSTR bstrApp, VARIANT_BOOL* bEraseText );
	STDMETHOD(CheckFile)( FILE_TYPE nFileType, BSTR bstrFileOrg, BSTR bstrFileDest, VARIANT_BOOL bDestIsExternFolder, VARIANT_BOOL* bDeleteFile );
	STDMETHOD(CheckRemoteUnit)( BSTR bstrFileOrg, BSTR bstrFileDest, VARIANT_BOOL bDestIsExternFolder, VARIANT_BOOL* bDeleteFile );
	STDMETHOD(SkipFile)( BSTR bstrFileDest );
	STDMETHOD(MonitorProcess)( ULONG dwProcId );
	STDMETHOD(SetScreenShot)( BYTE* pImage, DWORD cb );
	STDMETHOD(SendATPEvent)( BSTR bstrUserName, BSTR bstrJSON );
	STDMETHOD(LoadATP)( BSTR bstrProcName, VARIANT_BOOL* bLoad );
	STDMETHOD(CheckTextExt)( BSTR bstrText, TEXT_TYPE nTextType, BSTR bstrApp, VARIANT_BOOL* bEraseText, BYTE* pImage, DWORD cb );
	STDMETHOD(GetProtectionType)( ULONG *pt );
	STDMETHOD(AddIfRemoteFile)( BSTR bstrDestDir, BSTR bstrFileOrg );
	STDMETHOD(RemoveADS)( BSTR bstrFileOrg );
	STDMETHOD(AddProxy)( BSTR bstrProxyServer, LONG bEnable );
	//License
	STDMETHOD(IsLicensed)( VARIANT_BOOL *bLicensed );
	HRESULT CheckLicense( PCTSTR szValue, LONG &nCode, CStringA &strURL, CStringA &strServer, int &nPort );
	STDMETHODIMP SetLicense( BSTR bstrLic1, BSTR bstrLic2, BSTR bstrLic3, BSTR bstrLic4, BSTR *bstrUrl, LONG* pnCode );
	bool Post( const char *szUrl, CStringA &strPost, CStringA &strResult );
};

OBJECT_ENTRY_AUTO(__uuidof(DwService), CDwService)
