#include "stdafx.h"
#include "PrinterMonitor.h"
#include "PrinterPort.h"

#include "..\DrainwareSecurityAgent\DrainwareSecurityAgent_i.h"
#include "..\DrainwareSecurityAgent\DrainwareSecurityAgent_i.c"


CDwEventHandler::CDwEventHandler() : m_dwRef( 1 )
{}

//IUnknown
HRESULT STDMETHODCALLTYPE CDwEventHandler::QueryInterface( REFIID riid,void **ppvObject )
{
	if( !ppvObject )
		return E_INVALIDARG;

	if( IsEqualGUID( riid, IID_IUnknown ) )
	{
		AddRef();
		*ppvObject = (IUnknown*)this;
		return S_OK;
	}
	else
		if( IsEqualGUID( riid, IID__IDwServiceEvents) )
		{
			AddRef();
			*ppvObject = (_IDwServiceEvents*)this;
			return S_OK;
		}
	*ppvObject = NULL;
	return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE CDwEventHandler::AddRef()
{
	return InterlockedIncrement( &m_dwRef );
}

ULONG STDMETHODCALLTYPE CDwEventHandler::Release()
{
	return InterlockedDecrement( &m_dwRef );
}


//_IDwServiceEvents
HRESULT STDMETHODCALLTYPE CDwEventHandler::OnClose( VARIANT_BOOL bUpdate )
{
	CPrinterMonitor::CloseThreadWatch();
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CDwEventHandler::OnShowTrayWindow( ULONG nMsgType, VARIANT_BOOL *bShowed )
{
	if( !bShowed )
		return E_POINTER;
	*bShowed = VARIANT_FALSE;
	return S_OK;
}

HRESULT WINAPI CDwEventHandler::OnGetScreenShot( VARIANT_BOOL *bShowed )
{
	if( !bShowed )
		return E_POINTER;
	*bShowed = VARIANT_FALSE;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CDwEventHandler::OnShowCheckDialog( ULONG nMsgType, VARIANT_BOOL *bShowed )
{
	if( !bShowed )
		return E_POINTER;
	*bShowed = VARIANT_FALSE;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CDwEventHandler::OnShowUserMessage( BSTR bstrMsg )
{
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CDwEventHandler::OnActiveModules( ULONG nActiveModules )
{
	return S_OK;
}



HINSTANCE CPrinterMonitor::m_hDll = NULL;
bool CPrinterMonitor::m_bCloseService = false;

//CAtlMap< CString, CString > CPrinterMonitor::m_mapPrinterPorts;

CEvent CPrinterMonitor::m_evtWatch;
CEvent CPrinterMonitor::m_evtWatchOn;
CEvent CPrinterMonitor::m_evtWatchOff;

HANDLE CPrinterMonitor::m_hThreadWatch = NULL;

CComPtr<IDwService> CPrinterMonitor::m_pDwService;

DWORD CPrinterMonitor::m_dwCookie = 0;

CDwEventHandler CPrinterMonitor::m_DwServiceEvents;

CPrinterMonitor::CPrinterMonitor() : m_hMonitor( NULL )
{
}

BOOL WINAPI CPrinterMonitor::EnumPorts( HANDLE hMonitor,  LPWSTR pName,  DWORD nLevel,  LPBYTE pPorts,  DWORD cbBuf,  LPDWORD pcbNeeded,  LPDWORD pcReturned )
{
	*pcbNeeded = *pcReturned = NULL;
	if( nLevel < 1 || nLevel > 2 )
	{
		SetLastError( ERROR_INVALID_LEVEL );
		return FALSE;
	}
	TCHAR szMonitorName[] = _T("Drainware Monitor");
	TCHAR szPortName[] = _T("DwPort:");
	TCHAR szPortDesc[] = _T("Drainware Port Monitor");

	DWORD dwSize = 0;
	if( nLevel == 1 )
		dwSize = sizeof(PORT_INFO_1) + sizeof(szPortName);
	else
		dwSize = sizeof(PORT_INFO_2) + sizeof(szMonitorName) + sizeof(szPortName) + sizeof(szPortDesc);

	*pcbNeeded = dwSize;

	if( !pPorts || dwSize > cbBuf )
	{
		SetLastError( ERROR_INSUFFICIENT_BUFFER );
		return FALSE;
	}

	LPTSTR pStr = reinterpret_cast<LPTSTR>(pPorts + cbBuf);

	if( nLevel == 1 )
	{
	    PORT_INFO_1 *pPortInfo1 = reinterpret_cast<PORT_INFO_1 *>(pPorts);
		pStr -= sizeof(szPortName) / sizeof(TCHAR);
		lstrcpy( pStr, szPortName );
		pPortInfo1->pName = pStr;

	}
	else
	{
	    PORT_INFO_2 *pPortInfo2 = reinterpret_cast<PORT_INFO_2 *>(pPorts);
		pStr -= sizeof(szMonitorName) / sizeof(TCHAR);
		lstrcpy( pStr, szMonitorName );
		pPortInfo2->pMonitorName = pStr;
		pStr -= sizeof(szPortName) / sizeof(TCHAR);
		lstrcpy( pStr, szPortName );
		pPortInfo2->pPortName = pStr;
		pStr -= sizeof(szPortDesc) / sizeof(TCHAR);
		lstrcpy( pStr, szPortDesc );
		pPortInfo2->pDescription = pStr;
		pPortInfo2->fPortType = PORT_TYPE_WRITE;// | PORT_TYPE_WRITE;
		pPortInfo2->Reserved = 0;
	}

	*pcReturned = 1;

	return TRUE;
}

BOOL WINAPI CPrinterMonitor::EnumPortsOld( HANDLE hMonitor,  LPWSTR pName,  DWORD nLevel,  LPBYTE pPorts,  DWORD cbBuf,  LPDWORD pcbNeeded,  LPDWORD pcReturned )
{
	*pcbNeeded = *pcReturned = NULL;
	if( nLevel < 1 || nLevel > 2 )
	{
		SetLastError( ERROR_INVALID_LEVEL );
		return FALSE;
	}
	MONITORINIT *pMI = reinterpret_cast<MONITORINIT *>(hMonitor);

	HANDLE hKey;
	LONG nRet = DwOpenKey( hMonitor, PORTS_NAME, KEY_READ, &hKey );
	if( nRet != ERROR_SUCCESS )
		return TRUE;

	TCHAR szMonitorName[ 256 ] = _T("Drainware Monitor");
	TCHAR szPortName[ 256 ];
	TCHAR szPortDesc[ 256 ];
	TCHAR szBuffer[ 256 ];
	DWORD dwData = sizeof(szPortName);

	nRet = DwEnumKey( hMonitor, hKey, 0, szPortName, &dwData );
	DWORD dwNeedMem = 0;
	DWORD dwIndex = 0;
	while( nRet == ERROR_SUCCESS )
	{
		dwNeedMem += ( lstrlen( szPortName ) + 1 ) * sizeof(TCHAR);
		if( nLevel == 1 )
			dwNeedMem += sizeof(PORT_INFO_1);
		else
		{
			dwNeedMem += sizeof(PORT_INFO_2);
			dwNeedMem += ( lstrlen( szMonitorName ) + 1 ) * sizeof(TCHAR);
			lstrcpy( szBuffer, PORTS_NAME );
			lstrcat( szBuffer, BACK_SLASH );
			lstrcat( szBuffer, szPortName );
			HANDLE hSubKey;
			if( DwOpenKey( hMonitor, szBuffer, KEY_READ, &hSubKey ) == ERROR_SUCCESS )
			{
				DWORD dwKeyType = REG_SZ;
				dwData = sizeof(szPortDesc);
				if( DwQueryValue( hMonitor, hSubKey, DESCKEY, &dwKeyType, reinterpret_cast<PBYTE>(szPortDesc), &dwData ) == ERROR_SUCCESS )
					dwNeedMem += ( lstrlen( szPortDesc ) + 1 ) * sizeof(TCHAR);
				else
					dwNeedMem += sizeof(TCHAR);
				DwCloseKey( hMonitor, hSubKey );
			}
			else
				dwNeedMem += sizeof(TCHAR);
		}
		dwData = sizeof(szPortName);
		nRet = DwEnumKey( hMonitor, hKey, ++dwIndex, szPortName, &dwData );
	}

	*pcbNeeded = dwNeedMem;

	if( !pPorts || dwNeedMem > cbBuf )
	{
		DwCloseKey( hMonitor, hKey );
		SetLastError( ERROR_INSUFFICIENT_BUFFER );
		return FALSE;
	}

	dwIndex = 0;
    PORT_INFO_1 *pPortInfo1 = reinterpret_cast<PORT_INFO_1 *>(pPorts);
    PORT_INFO_2 *pPortInfo2 = reinterpret_cast<PORT_INFO_2 *>(pPorts);
	LPTSTR pStr = reinterpret_cast<LPTSTR>(pPorts + cbBuf);
	
	dwData = sizeof(szPortName);
	nRet = DwEnumKey( hMonitor, hKey, 0, szPortName, &dwData );
	while( nRet == ERROR_SUCCESS )
	{
		pStr -= lstrlen(szPortName) + 1;
		lstrcpy( pStr, szPortName );
		if( nLevel == 1 )
			pPortInfo1[ dwIndex ].pName = pStr;
		else
		{
			pPortInfo2[ dwIndex ].pPortName = pStr;

			pStr -= lstrlen(szMonitorName) + 1;
			lstrcpy( pStr, szMonitorName );
			pPortInfo2[ dwIndex ].pMonitorName = pStr;

			lstrcpy( szBuffer, PORTS_NAME );
			lstrcat( szBuffer, BACK_SLASH );
			lstrcat( szBuffer, szPortName );

			HANDLE hSubKey;
			if( DwOpenKey( hMonitor, szBuffer, KEY_READ, &hSubKey ) == ERROR_SUCCESS )
			{
				dwData = sizeof(szPortDesc);
				DWORD dwKeyType = REG_SZ;
				if( DwQueryValue( hMonitor, hSubKey, DESCKEY, &dwKeyType, reinterpret_cast<PBYTE>(szPortDesc), &dwData ) != ERROR_SUCCESS )
					szPortDesc[ 0 ] = 0;
				DwCloseKey( hMonitor, hSubKey );
			}
			else
				szPortDesc[ 0 ] = 0;

			pStr -= lstrlen(szPortDesc) + 1;
			lstrcpy( pStr, szPortDesc );
			pPortInfo2[ dwIndex ].pDescription = pStr;

			pPortInfo2[ dwIndex ].fPortType = PORT_TYPE_WRITE;
			pPortInfo2[ dwIndex ].Reserved = 0;
		}
		++dwIndex;
		dwData = sizeof(szPortName);
		nRet = DwEnumKey( hMonitor, hKey, dwIndex, szPortName, &dwData );
	}

	*pcReturned = dwIndex;
	DwCloseKey( hMonitor, hKey );
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::OpenPort( HANDLE hMonitor, LPWSTR pName, PHANDLE pHandle )
{
	return CPrinterPort::CreatePort( hMonitor, pName, pHandle );
}

BOOL WINAPI CPrinterMonitor::StartDocPort( HANDLE hPort, LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo )
{
	CPrinterPort *pPort = reinterpret_cast<CPrinterPort *>(hPort);
	if( !pPort )
	{
		SetLastError( ERROR_INVALID_HANDLE );
		return FALSE;
	}
	return pPort->StartDoc( pPrinterName, JobId, Level, pDocInfo );
}

BOOL WINAPI CPrinterMonitor::WritePort( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten )
{
	if( !hPort )
	{
		SetLastError( ERROR_INVALID_HANDLE );
		return FALSE;
	}
	return reinterpret_cast<CPrinterPort *>(hPort)->Write( pBuffer, cbBuf, pcbWritten );
}

BOOL WINAPI CPrinterMonitor::ReadPort( HANDLE hPort, LPBYTE pBuffer, DWORD cbBuffer, LPDWORD pcbRead )
{
	//Not supported
	return FALSE;
}

BOOL WINAPI CPrinterMonitor::EndDocPort( HANDLE hPort )
{
	CPrinterPort *pPort = reinterpret_cast<CPrinterPort *>(hPort);
	return pPort->EndDoc();
}

BOOL WINAPI CPrinterMonitor::ClosePort( HANDLE hPort )
{
	return CPrinterPort::ClosePort( hPort );
}

BOOL WINAPI CPrinterMonitor::AddPort( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pMonitorName )
{
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::AddPortEx( HANDLE hMonitor, LPWSTR pName, DWORD Level, LPBYTE lpBuffer, LPWSTR pMonitorName )
{
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::ConfigurePort( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pPortName )
{
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::DeletePort( HANDLE hMonitor, LPWSTR pName, HWND hWnd, LPWSTR pPortName )
{
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::GetPrinterDataFromPort( HANDLE hPort, DWORD ControlID, LPWSTR pValueName, LPWSTR lpInBuffer, DWORD cbInBuffer, LPWSTR lpOutBuffer, DWORD cbOutBuffer, LPDWORD lpcbReturned )
{
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::SetPortTimeOuts( HANDLE hPort, LPCOMMTIMEOUTS lpCTO, DWORD reserved )
{
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::XcvOpenPort( HANDLE hMonitor, LPCWSTR pszObject, ACCESS_MASK GrantedAccess, PHANDLE phXcv )
{
	XcvPort *pXcvPort = new XcvPort( hMonitor, pszObject, GrantedAccess );
	*phXcv = reinterpret_cast<HANDLE>(pXcvPort);
	return TRUE;
}

DWORD WINAPI CPrinterMonitor::XcvDataPort( HANDLE hXcv, LPCWSTR pszDataName, PBYTE pInputData, DWORD cbInputData, PBYTE pOutputData, DWORD cbOutputData, PDWORD pcbOutputNeeded )
{
	XcvPort *pXcvPort = reinterpret_cast<XcvPort *>(hXcv);
	if( !lstrcmp( pszDataName, _T("MonitorUI") ) )
	{
		//TCHAR szName[ 512 ];
		//DWORD dwLen = GetModuleFileName( m_hDll, szName, 512 );
		//*pcbOutputNeeded = (dwLen + 1) * sizeof(TCHAR);
		//if( *pcbOutputNeeded > cbOutputData )
		//	return ERROR_INSUFFICIENT_BUFFER;
		//CopyMemory( pOutputData, szName, *pcbOutputNeeded );
		TCHAR szDllName[] = _T("DrainwarePrintersMonitor.dll");
		*pcbOutputNeeded = sizeof(szDllName);
		if( *pcbOutputNeeded > cbOutputData )
			return ERROR_INSUFFICIENT_BUFFER;
		CopyMemory( pOutputData, szDllName, *pcbOutputNeeded );
	}
	return ERROR_SUCCESS;
}

BOOL  WINAPI CPrinterMonitor::XcvClosePort( HANDLE hXcv )
{
	XcvPort *pXcvPort = reinterpret_cast<XcvPort*>(hXcv);
	if( !pXcvPort || !pXcvPort->IsXcvPort() )
		return FALSE;
	delete pXcvPort;
	return ERROR_SUCCESS;
}

VOID  WINAPI CPrinterMonitor::Shutdown( HANDLE hMonitor )
{
	int n = 0;
}

DWORD WINAPI CPrinterMonitor::SendRecvBidiDataFromPort( HANDLE hPort, DWORD dwAccessBit, LPCWSTR pAction, PBIDI_REQUEST_CONTAINER pReqData, PBIDI_RESPONSE_CONTAINER* ppResData )
{
	return TRUE;
}

//MONITORUI
BOOL WINAPI CPrinterMonitor::AddPortUI(PCWSTR pszServer, HWND hWnd, PCWSTR pszPortNameIn, PWSTR *ppszPortNameOut )
{
	if( ppszPortNameOut )
	{
		TCHAR szPort[] = _T("DwPort:");
		*ppszPortNameOut = (PWSTR)GlobalAlloc( GMEM_FIXED | GMEM_ZEROINIT, sizeof(szPort) );
		if( *ppszPortNameOut )
			CopyMemory( *ppszPortNameOut, szPort, sizeof(szPort) );
	}
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::ConfigurePortUI( PCWSTR pszServer, HWND hWnd, PCWSTR pszPortName )
{
	return TRUE;
}

BOOL WINAPI CPrinterMonitor::DeletePortUI( PCWSTR pszServer, HWND hWnd, PCWSTR pszPortName )
{
	return TRUE;
}


void CPrinterMonitor::LoadDefaultPorts()
{
	//Sleep( 20000 );
	DWORD dwFlags = PRINTER_ENUM_LOCAL;// | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
	//DWORD dwFlags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
	DWORD dwNeeded, dwReturned;
	EnumPrinters( dwFlags, NULL, 2, NULL, 0, &dwNeeded, &dwReturned );
	PBYTE pBuffer = new BYTE[ dwNeeded ];
	if( !EnumPrinters( dwFlags, NULL, 2, pBuffer, dwNeeded, &dwNeeded, &dwReturned ) )
	{
		delete [] pBuffer;
		return;
	}

	PRINTER_INFO_2 *pPrinterInfo = reinterpret_cast<PRINTER_INFO_2 *>(pBuffer);
	for( DWORD i = 0; i < dwReturned; i++ )
	{
		HANDLE hPrinter;
		PRINTER_DEFAULTS pd = { 0 };
		pd.DesiredAccess = PRINTER_ALL_ACCESS;

		if( OpenPrinter( pPrinterInfo[ i ].pPrinterName, &hPrinter, &pd ) )
		{
			if( lstrcmpiW( pPrinterInfo[ i ].pPortName, _T("DwPort:") ) )
			{
				if( ERROR_SUCCESS == SetPrinterDataEx( hPrinter, _T("Drainware"), _T("DwOldPort"), REG_SZ, (PBYTE)pPrinterInfo[ i ].pPortName, ( lstrlen(pPrinterInfo[ i ].pPortName) + 1 ) * sizeof( TCHAR ) ) )
				{
					pPrinterInfo[ i ].pPortName = _T("DwPort:");
					SetPrinter( hPrinter, 2, reinterpret_cast<LPBYTE>(&pPrinterInfo[ i ]), 0 );
				}
			}
			ClosePrinter( hPrinter );
		}
	}
	delete [] pBuffer;
}

void CPrinterMonitor::RestoreDefaultPorts()
{
	DWORD dwFlags = PRINTER_ENUM_LOCAL;// | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
	//DWORD dwFlags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
	DWORD dwNeeded, dwReturned;
	EnumPrinters( dwFlags, NULL, 2, NULL, 0, &dwNeeded, &dwReturned );
	PBYTE pBuffer = new BYTE[ dwNeeded ];
	if( !EnumPrinters( dwFlags, NULL, 2, pBuffer, dwNeeded, &dwNeeded, &dwReturned ) )
	{
		delete [] pBuffer;
		return;
	}

	PRINTER_INFO_2 *pPrinterInfo = reinterpret_cast<PRINTER_INFO_2 *>(pBuffer);
	for( DWORD i = 0; i < dwReturned; i++ )
	{
		HANDLE hPrinter;
		PRINTER_DEFAULTS pd = { 0 };
		pd.DesiredAccess = PRINTER_ALL_ACCESS;

		if( OpenPrinter( pPrinterInfo[ i ].pPrinterName, &hPrinter, &pd ) )
		{
			TCHAR szPortName[ 512 ] = { 0 };
			DWORD dwType = REG_SZ;
			DWORD dwSize = 512;
			if( ERROR_SUCCESS == GetPrinterDataEx( hPrinter, _T("Drainware"), _T("DwOldPort"), &dwSize, (PBYTE)szPortName, 512, &dwSize ) )
			{
				pPrinterInfo[ i ].pPortName = szPortName;
				SetPrinter( hPrinter, 2, reinterpret_cast<LPBYTE>(&pPrinterInfo[ i ]), 0 );
			}
			ClosePrinter( hPrinter );
		}
	}
	delete [] pBuffer;
}

void CPrinterMonitor::SetDwPorts()
{
	DWORD dwFlags = PRINTER_ENUM_LOCAL;// | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
	//DWORD dwFlags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_NETWORK | PRINTER_ENUM_REMOTE;
	DWORD dwNeeded, dwReturned;
	EnumPrinters( dwFlags, NULL, 2, NULL, 0, &dwNeeded, &dwReturned );
	PBYTE pBuffer = new BYTE[ dwNeeded ];
	if( !EnumPrinters( dwFlags, NULL, 2, pBuffer, dwNeeded, &dwNeeded, &dwReturned ) )
	{
		delete [] pBuffer;
		return;
	}

	PRINTER_INFO_2 *pPrinterInfo = reinterpret_cast<PRINTER_INFO_2 *>(pBuffer);
	for( DWORD i = 0; i < dwReturned; i++ )
	{
		if( lstrcmpi( pPrinterInfo[ i ].pPortName, _T("DwPort:") ) )
		{
			HANDLE hPrinter;
			PRINTER_DEFAULTS pd = { 0 };
			pd.DesiredAccess = PRINTER_ALL_ACCESS;

			if( OpenPrinter( pPrinterInfo[ i ].pPrinterName, &hPrinter, &pd ) )
			{
				DWORD dwError = SetPrinterDataEx( hPrinter, _T("Drainware"), _T("DwOldPort"), REG_SZ, (PBYTE)pPrinterInfo[ i ].pPortName, ( lstrlen(pPrinterInfo[ i ].pPortName) + 1 ) * sizeof( TCHAR ) );
				if( ERROR_SUCCESS == dwError )
				{
					pPrinterInfo[ i ].pPortName = _T("DwPort:");
					SetPrinter( hPrinter, 2, reinterpret_cast<LPBYTE>(&pPrinterInfo[ i ]), 0 );
				}
				else
					Sleep( 2000 );
				dwError = GetLastError();
				ClosePrinter( hPrinter );
			}
		}
	}
	delete [] pBuffer;
}


void CPrinterMonitor::InitThreadWatch()
{
	//Sleep( 20000 );
	//HRESULT hr = m_pDwService.CoCreateInstance( CLSID_DwService, NULL, CLSCTX_LOCAL_SERVER );

	//if( m_pDwService )
	//{
	//	m_DwServiceEvents.AddRef();
	//	hr = AtlAdvise( m_pDwService, &m_DwServiceEvents, IID__IDwServiceEvents, &m_dwCookie );
	//}
	//m_evtWatch.Create( NULL, FALSE, FALSE, NULL );
	m_evtWatch.Create( NULL, FALSE, FALSE, NULL );//_T("DrainwarePrintMonitorEvt") );
	m_evtWatchOn.Create( NULL, FALSE, FALSE, _T("DrainwarePrintMonitorEvtOn") );
	m_evtWatchOff.Create( NULL, FALSE, FALSE, _T("DrainwarePrintMonitorEvtOff") );
	m_hThreadWatch = CreateThread( NULL, 0, ThreadWatch, NULL,  0, NULL );
}

void CPrinterMonitor::CloseThreadWatch()
{
	if( m_hThreadWatch )
	{
		m_evtWatch.Set();
		WaitForSingleObject( m_hThreadWatch, INFINITE );
		CloseHandle( m_hThreadWatch );
		m_hThreadWatch = NULL;
	}
}

DWORD WINAPI CPrinterMonitor::ThreadWatch( PVOID pVoid )
{
	//Sleep( 5000 * 5 ); //Ensure that EnumPorts is called
	Sleep( 2000 ); //Ensure that EnumPorts is called
	LoadDefaultPorts();

	int n = 0;
	HANDLE aWaitOff[ 2 ] = { m_evtWatch, m_evtWatchOff };
	while( true )
	{
		DWORD dwResult = WaitForMultipleObjects( 2, aWaitOff, FALSE, 500 );
		if( dwResult != WAIT_TIMEOUT )
		{
			m_evtWatchOff.Set();
			break;
		}

		if( n++ < 6 ) //Check every 3 seconds
			continue;
		PrintFiles();
		SetDwPorts();
		n = 0;
		//if( ++n > 40 ) //2 min.
		//	break;
	}
	return 0;
}

//DWORD WINAPI CPrinterMonitor::ThreadWatch( PVOID pVoid )
//{
//	//Sleep( 5000 * 5 ); //Ensure that EnumPorts is called
//	Sleep( 2000 ); //Ensure that EnumPorts is called
//	LoadDefaultPorts();
//
//	HANDLE aWaitOn[ 2 ] = { m_evtWatch, m_evtWatchOn };
//	HANDLE aWaitOff[ 2 ] = { m_evtWatch, m_evtWatchOff };
//	int n = 0;
//	while( true )
//	{
//		if( m_bCloseService )
//			break;
//		DWORD dwResult = WaitForMultipleObjects( 2, aWaitOn, FALSE, INFINITE );
//
//		if( dwResult == WAIT_OBJECT_0 || m_bCloseService )
//			break;
//		while( true )
//		{
//			dwResult = WaitForMultipleObjects( 2, aWaitOff, FALSE, 500 );
//			if( dwResult != WAIT_TIMEOUT )
//			{
//				if( dwResult == WAIT_OBJECT_0 || m_bCloseService )
//				{
//					RestoreDefaultPorts();
//					return 0;
//				}
//				break;
//			}
//
//			if( n++ < 6 ) //Check every 3 seconds
//				continue;
//			PrintFiles();
//			SetDwPorts();
//			n = 0;
//			//if( ++n > 40 ) //2 min.
//			//	break;
//		}
//		RestoreDefaultPorts();
//	}
//
//	RestoreDefaultPorts();
//	return 0;
//}

void CPrinterMonitor::PrintFile()
{

	DwJob &dwJob = CPrinterPort::m_aJobs[ 0 ];

	CComPtr<IDwPrinterService> pPrinterService;
	HRESULT hr = pPrinterService.CoCreateInstance( CLSID_DwPrinterService, NULL, CLSCTX_LOCAL_SERVER );

	if( pPrinterService )
		pPrinterService->PrintJob( CComBSTR(dwJob.strDocName), CComBSTR(dwJob.strPath), CComBSTR(dwJob.strPrinter), CComBSTR(dwJob.strUserName) );

	//Print m_f, check our port
	DeleteFile( dwJob.strPath );
	CPrinterPort::m_aJobs.RemoveAt( 0 );
}


//void CPrinterMonitor::PrintFile()
//{
//
//	DwJob &dwJob = CPrinterPort::m_aJobs[ 0 ];
//
//	HANDLE hPrinter;
//	PRINTER_DEFAULTS pd = { 0 };
//	pd.DesiredAccess = PRINTER_ALL_ACCESS;
//
//	if( OpenPrinter( dwJob.strPrinter.GetBuffer(), &hPrinter, &pd ) )
//	{
//		DWORD dwSize = 0;
//		GetPrinter( hPrinter, 2, NULL, 0, &dwSize );
//		PBYTE pByte = new BYTE[ dwSize ];
//
//		if( GetPrinter( hPrinter, 2, pByte, dwSize, &dwSize ) )
//		{
//			//Set old port
//			PRINTER_INFO_2 &pi2 = *reinterpret_cast<PRINTER_INFO_2 *>(pByte);
//
//			TCHAR szPortName[ 512 ] = { 0 };
//			DWORD dwType = REG_SZ;
//			DWORD dwSize = 512;
//			GetPrinterDataEx( hPrinter, _T("Drainware"), _T("DwOldPort"), &dwSize, (PBYTE)szPortName, 512, &dwSize );
//
//
//			//pi2.pPortName = CPrinterMonitor::m_mapPrinterPorts[ pi2.pPrinterName ].GetBuffer();
//			pi2.pPortName = szPortName;
//			BOOL bRet = SetPrinter( hPrinter, 2, pByte, 0 );
//			DWORD dwError = GetLastError();
//			//ClosePrinter( hPrinter );
//			//OpenPrinter( dwJob.strPrinter.GetBuffer(), &hPrinter, NULL );
//
//			//Print data
//
//			CComPtr<IDwPrinterService> pPrinterService;
//			HRESULT hr = pPrinterService.CoCreateInstance( CLSID_DwPrinterService, NULL, CLSCTX_LOCAL_SERVER );
//
//			if( pPrinterService )
//			{
//				//ClosePrinter( hPrinter );
//				pPrinterService->PrintJob( CComBSTR(dwJob.strDocName), CComBSTR(dwJob.strPath), CComBSTR(dwJob.strPrinter), CComBSTR(dwJob.strUserName) );
//				//OpenPrinter( dwJob.strPrinter.GetBuffer(), &hPrinter, &pd );
//			}
//
//
//			//Restore drainware port
//			pi2.pPortName = _T("DwPort:");
//			SetPrinter( hPrinter, 2, reinterpret_cast<LPBYTE>(&pi2), 0 );
//
//			//m_csJobs.Enter();
//			//m_mapJobs.RemoveKey( dwJobID );
//			//m_csJobs.Leave();
//
//		}
//		delete [] pByte;
//		ClosePrinter( hPrinter );
//	}
//	//Print m_f, check our port
//	DeleteFile( dwJob.strPath );
//	CPrinterPort::m_aJobs.RemoveAt( 0 );
//}

void CPrinterMonitor::PrintFiles()
{
	if( CPrinterPort::m_aJobs.GetCount() )
	{
		if( CPrinterPort::m_cs.TryEnter() )
		{
			LONG nResult = InterlockedIncrement( &CPrinterPort::m_nCurrentDocs );
			if( nResult == 1 )
			{
				while( CPrinterPort::m_aJobs.GetCount() )
					PrintFile();
			}
			InterlockedDecrement( &CPrinterPort::m_nCurrentDocs );

			CPrinterPort::m_cs.Leave();
		}
	}
}

//Helpers
LONG CPrinterMonitor::DwOpenKey( HANDLE hMonitor, LPCTSTR pszSubKey, REGSAM samDesired, HANDLE *phkResult )
{
	if( hMonitor )
	{
		MONITORINIT *pMI = reinterpret_cast<MONITORINIT *>(hMonitor);
		return pMI->pMonitorReg->fpOpenKey( pMI->hckRegistryRoot, pszSubKey, samDesired, phkResult, pMI->hSpooler );
	}
	return ERROR_INVALID_DATA;
}

LONG CPrinterMonitor::DwCloseKey( HANDLE hMonitor, HANDLE hcKey )
{
	if( hMonitor )
	{
		MONITORINIT *pMI = reinterpret_cast<MONITORINIT *>(hMonitor);
		return pMI->pMonitorReg->fpCloseKey( hcKey, pMI->hSpooler );
	}
	return ERROR_INVALID_DATA;
}

LONG CPrinterMonitor::DwEnumKey( HANDLE hMonitor, HANDLE hcKey, DWORD dwIndex, LPTSTR pszName, PDWORD pcchName )
{
	if( hMonitor )
	{
		MONITORINIT *pMI = reinterpret_cast<MONITORINIT *>(hMonitor);
		FILETIME ft;
		return pMI->pMonitorReg->fpEnumKey( hcKey, dwIndex, pszName, pcchName, &ft, pMI->hSpooler );
	}
	return ERROR_INVALID_DATA;
}

LONG CPrinterMonitor::DwQueryValue(HANDLE hMonitor, HANDLE hcKey, LPCTSTR pszValue, PDWORD pType, PBYTE pData, PDWORD pcbData )
{
	if( hMonitor )
	{
		MONITORINIT *pMI = reinterpret_cast<MONITORINIT *>(hMonitor);
		return pMI->pMonitorReg->fpQueryValue( hcKey, pszValue, pType, pData, pcbData, pMI->hSpooler );
	}
	return ERROR_INVALID_DATA;
}
