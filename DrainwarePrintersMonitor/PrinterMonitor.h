#pragma once
#include "..\DrainwareSecurityAgent\DrainwareSecurityAgent_i.h"

struct XcvPort
{
	DWORD m_dwSize;
	HANDLE m_hMonitor;
	TCHAR m_szPortName[ 512 ];
	ACCESS_MASK m_accm;

	XcvPort( HANDLE hMonitor, PCTSTR szPortName, ACCESS_MASK accm ) : m_dwSize( sizeof(XcvPort) ), m_hMonitor( hMonitor ), m_accm( accm )
	{
		lstrcpyn( m_szPortName, szPortName, 512 );
	}

	bool IsXcvPort() const throw()
	{
		return m_dwSize == sizeof(XcvPort );
	}
};

#define PORTS_NAME _T("Ports")
#define BACK_SLASH _T("\\")
#define DESCKEY _T("Description")


class CDwEventHandler : public _IDwServiceEvents
{
public:
	CDwEventHandler();
//IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface( REFIID riid,void ** ppvObject );
    ULONG STDMETHODCALLTYPE AddRef();
    ULONG STDMETHODCALLTYPE Release();

//_IDwServiceEvents
	HRESULT STDMETHODCALLTYPE OnClose( VARIANT_BOOL bUpdate );
	HRESULT STDMETHODCALLTYPE OnShowTrayWindow( ULONG nMsgType, VARIANT_BOOL *bShowed );
	HRESULT STDMETHODCALLTYPE OnGetScreenShot( VARIANT_BOOL *bShowed );
	HRESULT STDMETHODCALLTYPE OnShowCheckDialog( ULONG nMsgType, VARIANT_BOOL *bShowed );
	HRESULT STDMETHODCALLTYPE OnShowUserMessage( BSTR bstrMsg );
	HRESULT STDMETHODCALLTYPE OnActiveModules( ULONG nActiveModules );
private:
	volatile LONG m_dwRef;
};

class CPrinterMonitor
{
public:
	CPrinterMonitor();

	//MONITOR2
	static BOOL WINAPI EnumPorts( HANDLE hMonitor,  LPWSTR pName,  DWORD Level,  LPBYTE pPorts,  DWORD cbBuf,  LPDWORD pcbNeeded,  LPDWORD pcReturned );
	static BOOL WINAPI EnumPortsOld( HANDLE hMonitor,  LPWSTR pName,  DWORD Level,  LPBYTE pPorts,  DWORD cbBuf,  LPDWORD pcbNeeded,  LPDWORD pcReturned );
	static BOOL WINAPI OpenPort( HANDLE hMonitor, LPWSTR pName, PHANDLE pHandle );
	static BOOL WINAPI StartDocPort( HANDLE hPort, LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo );
	static BOOL WINAPI WritePort( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten );
	static BOOL WINAPI ReadPort( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuffer, LPDWORD pcbRead );
	static BOOL WINAPI EndDocPort( HANDLE hPort );
	static BOOL WINAPI ClosePort( HANDLE hPort );
	static BOOL WINAPI AddPort( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pMonitorName );
	static BOOL WINAPI AddPortEx( HANDLE hMonitor, LPWSTR pName, DWORD Level, LPBYTE lpBuffer, LPWSTR pMonitorName );
	static BOOL WINAPI ConfigurePort( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pPortName );
	static BOOL WINAPI DeletePort( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pPortName );
	static BOOL WINAPI GetPrinterDataFromPort( HANDLE hPort, DWORD ControlID, LPWSTR pValueName, LPWSTR lpInBuffer, DWORD cbInBuffer, LPWSTR lpOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbReturned );
	static BOOL WINAPI SetPortTimeOuts( HANDLE hPort, LPCOMMTIMEOUTS lpCTO, DWORD reserved );
	static BOOL WINAPI XcvOpenPort( HANDLE hMonitor, LPCWSTR pszObject, ACCESS_MASK GrantedAccess, PHANDLE phXcv );
	static DWORD WINAPI XcvDataPort( HANDLE hXcv, LPCWSTR pszDataName, PBYTE pInputData, DWORD cbInputData, PBYTE pOutputData, DWORD cbOutputData, PDWORD pcbOutputNeeded );
	static BOOL  WINAPI XcvClosePort( HANDLE hXcv );
	static VOID  WINAPI Shutdown( HANDLE hMonitor );
	static DWORD WINAPI SendRecvBidiDataFromPort( HANDLE hPort, DWORD dwAccessBit, LPCWSTR pAction, PBIDI_REQUEST_CONTAINER pReqData, PBIDI_RESPONSE_CONTAINER* ppResData );

	//MONITORUI
	static BOOL WINAPI AddPortUI(PCWSTR pszServer, HWND hWnd, PCWSTR pszPortNameIn, PWSTR *ppszPortNameOut );
	static BOOL WINAPI ConfigurePortUI( PCWSTR pszServer, HWND hWnd, PCWSTR pszPortName );
	static BOOL WINAPI DeletePortUI( PCWSTR pszServer, HWND hWnd, PCWSTR pszPortName );

	//Initialization
	static void LoadDefaultPorts();
	static void RestoreDefaultPorts();
	static void SetDwPorts();

	static void InitThreadWatch();
	static void CloseThreadWatch();
	static void PrintFiles();

	static HINSTANCE m_hDll;
	static bool m_bCloseService;
	
	//static CAtlMap< CString, CString > m_mapPrinterPorts;

private:

	static void PrintFile();
	static DWORD WINAPI CPrinterMonitor::ThreadWatch( PVOID pVoid );
	//Helpers
	static LONG DwOpenKey( HANDLE hMonitor, LPCTSTR pszSubKey, REGSAM samDesired, HANDLE *phkResult );
	static LONG DwCloseKey( HANDLE hMonitor, HANDLE hcKey );
	static LONG DwEnumKey( HANDLE hMonitor, HANDLE hcKey, DWORD dwIndex, LPTSTR pszName, PDWORD pcchName );
	static LONG DwQueryValue(HANDLE hMonitor, HANDLE hcKey, LPCTSTR pszValue, PDWORD pType, PBYTE pData, PDWORD pcbData );

	static CEvent m_evtWatch;
	static CEvent m_evtWatchOn;
	static CEvent m_evtWatchOff;
	static HANDLE m_hThreadWatch;

	static CComPtr<IDwService> m_pDwService;
	static DWORD m_dwCookie;
	static CDwEventHandler m_DwServiceEvents;

	MONITORREG m_mr;
	MONITORINIT m_mi;
	HANDLE m_hMonitor;
};
