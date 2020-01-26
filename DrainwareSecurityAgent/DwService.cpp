// DwService.cpp: implementación de CDwService

#include "stdafx.h"
#include "IUserNotify.h"
#include "UserData.h"
#include "DwService.h"
#include "ISecurityAgent.h"
//#include <atlhttp.h>
#include "..\..\DrainwareLibs\json-c\json.h"
#include "..\DwLib\DwLib.h"

extern ISecurityAgent *g_pSecurityAgent;


// CDwService

HRESULT CDwService::FinalConstruct()
{
	CComPtr<IServerSecurity> pServerSecurity;
	if( S_OK == CoGetCallContext( IID_IServerSecurity, reinterpret_cast<void**>(&pServerSecurity) ) )
	{
		pServerSecurity->ImpersonateClient();
		m_token.GetThreadToken( TOKEN_ALL_ACCESS, NULL, false );

		//Can save user toker for future use at Printing?
		TCHAR szName[ MAX_PATH ];
		DWORD dwSize = MAX_PATH;
		if( GetUserName( szName, &dwSize ) )
		{
			szName[ dwSize ] = 0;
			m_strUserName = szName;

			//TCHAR szNameOut[ MAX_PATH ] = { 0 };
			//DWORD dwOutLen = 0;
			//if( AtlEscapeUrl( szName, szNameOut, &dwOutLen,  MAX_PATH ) )
			//{
			//	szNameOut[dwOutLen ] = 0;
			//	m_strUserName = szNameOut;
			//}
			//else
			//	m_strUserName = szName;

//#if defined(_DEBUG)
//			m_strUserName = _T("mlojo");
//#endif
		}
		//m_strProxyServer

		//if( m_strUserName.GetLength() )
		//	LoadDDIConfig();

		pServerSecurity->RevertToSelf();
	}
	
	if( m_strUserName != _T("SYSTEM") )
		m_pUserData = g_pSecurityAgent->AddClient( this );

	return S_OK;
}

void CDwService::FinalRelease()
{
	g_pSecurityAgent->RemoveClient( this );
}

void CDwService::LoadDDIConfig()
{
}

void CDwService::LoadDDIConfig( CStringA &strConfig )
{
}

void CDwService::LoadDDIConfigFromRegistry()
{
	CRegKey rKey;
	CStringA strJSON;
	if( ERROR_SUCCESS == rKey.Open( HKEY_CURRENT_USER, _T("SOFTWARE\\Drainware\\SecurityEndpoint"), KEY_READ | KEY_WRITE | KEY_WOW64_32KEY ) )
	{
		ULONG nSize = 0;
		rKey.QueryBinaryValue( _T("Config"), NULL, &nSize );
		if( !nSize || nSize > 1024 * 1024 )
			return;
		PBYTE pBuffer = new BYTE[ nSize + 1 ];
		if( ERROR_SUCCESS == rKey.QueryBinaryValue( _T("Config"), pBuffer, &nSize ) )
		{
			pBuffer[ nSize ] = 0;
			strJSON = reinterpret_cast<char *>(pBuffer);
			LoadDDIConfig( strJSON );
		}

		delete [] pBuffer;
	}
}

void CDwService::SaveDDIConfig( const CStringA &strConfig )
{
	CRegKey rKey;

	if( ERROR_SUCCESS != rKey.Open( HKEY_CURRENT_USER, _T("SOFTWARE\\Drainware\\SecurityEndpoint"), KEY_READ | KEY_WRITE | KEY_WOW64_32KEY ) )
	{
		CRegKey rKeyParent;
		if( ERROR_SUCCESS != rKeyParent.Open( HKEY_CURRENT_USER, _T("SOFTWARE\\Drainware"), KEY_READ | KEY_WRITE | KEY_WOW64_32KEY ) )
			if( ERROR_SUCCESS != rKeyParent.Create( HKEY_CURRENT_USER, _T("SOFTWARE\\Drainware"), NULL, 0, KEY_READ | KEY_WRITE | KEY_WOW64_32KEY ) )
			{
				DWORD dwErr = GetLastError();
				return;
			}
		if( ERROR_SUCCESS != rKey.Create( HKEY_CURRENT_USER, _T("SOFTWARE\\Drainware\\SecurityEndpoint"), NULL, 0,  KEY_READ | KEY_WRITE | KEY_WOW64_32KEY ) )
			{
				DWORD dwErr = GetLastError();
				return;
			}
	}

	rKey.SetBinaryValue( _T("Config"), (const char *)strConfig, strConfig.GetLength() );
}


void CDwService::PrinterSetPort( PTSTR szPrinterName, PTSTR szNewPort )
{
	HANDLE hPrinter;
	PRINTER_DEFAULTS pd = { 0 };
	pd.DesiredAccess = PRINTER_ALL_ACCESS;

	if( OpenPrinter( szPrinterName, &hPrinter, &pd ) )
	{
		DWORD dwSize = 0;
		GetPrinter( hPrinter, 2, NULL, 0, &dwSize );
		PBYTE pByte = new BYTE[ dwSize ];
		if( GetPrinter( hPrinter, 2, pByte, dwSize, &dwSize ) )
		{
			PRINTER_INFO_2 &pi2 = *reinterpret_cast<PRINTER_INFO_2 *>(pByte);
			TCHAR szPortName[ 512 ] = { 0 };

			if( !szNewPort ) //Restore old port
			{
				DWORD dwType = REG_SZ;
				DWORD dwSize = 512;
				GetPrinterDataEx( hPrinter, _T("Drainware"), _T("DwOldPort"), &dwSize, (PBYTE)szPortName, 512, &dwSize );
				pi2.pPortName = szPortName;
			}
			else
				pi2.pPortName = szNewPort;

			BOOL bRet = SetPrinter( hPrinter, 2, pByte, 0 );
		}

		ClosePrinter( hPrinter );
	}
}

void CDwService::PrintJob( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName )
{
	CAtlFile f;
	f.Create( szRawFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING );
	CStringA strContent;
	DWORD dwSize = 4096;
	bool bPS = false;
	if( S_OK == f.Read( strContent.GetBufferSetLength( dwSize ), dwSize, dwSize ) )
	{
		strContent.Truncate( dwSize );
		bPS = strContent.Find( "%!PS-Adobe" ) != -1;
	}
	f.Close();

	if( bPS )
		PrintJobPS( szDocName, szRawFile, szPrinterName );
	else
		PrintJobImg( szDocName, szRawFile, szPrinterName );
}

void CDwService::PrintJobPS( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName )
{
	g_pSecurityAgent->Fire_ShowCheckDialog( m_strUserName, TYPE_PRINTER );
	CString strFile;
	CAtlFile f;
	GetTempFile( _T("prnPDF_%d.pdf"), f, strFile );
	f.Close();

	CString strCmd;
	GetModuleDirectory( strCmd );
	strCmd += _T("gs\\");
	SetCurrentDirectory( strCmd );
	strCmd += _T("gswin32c.exe\" ");
	strCmd.Insert( 0, _T('\"') );
	//strCmd += _T("-dNOPAUSE -sDEVICE=pngmono -r300 -sOutputFile=\"");
	strCmd += _T("-dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=\"");
	strCmd += strFile;
	strCmd += _T("\" \"");
	strCmd += szRawFile;
	strCmd += _T("\"");

	HANDLE hProc = NULL;
	RunProcess( strCmd.GetBuffer(), &hProc );
	WaitForSingleObject( hProc, INFINITE );
	CloseHandle( hProc );

	GetModuleDirectory( strCmd );
	SetCurrentDirectory( strCmd );
	strCmd += _T("bin\\pdftotext.exe\" \"");
	strCmd.Insert( 0, _T('\"') );
	strCmd += strFile;
	strCmd += _T("\" \"");
	strCmd += strFile; //tesseract.exe add extension .txt automatically
	strCmd += _T(".txt");
	strCmd += _T("\"");

	hProc = NULL;
	RunProcess( strCmd.GetBuffer(), &hProc );
	WaitForSingleObject( hProc, INFINITE );
	CloseHandle( hProc );

	DeleteFile( strFile );
	strFile += _T(".txt");

	VARIANT_BOOL bEraseText = VARIANT_FALSE;

	if( S_OK == f.Create( strFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
	{
		ULONGLONG nLen = 0;
		if( S_OK == f.GetSize( nLen ) )
		{
			CStringA strText;
			f.Read( strText.GetBufferSetLength( int(nLen) ), DWORD(nLen) );
			f.Close();
			CStringA strEvent;
			VARIANT_BOOL bScreenShot = VARIANT_FALSE;
			VARIANT_BOOL bShowMsg = VARIANT_FALSE;
			bool bSendEvent = false;
			//TODO: When to send events? only when block policy?
			CStringA strJSON = "{\"process_name\":\"spoolsv.exe\", \"description\":\"";
			strJSON += szPrinterName; 
			strJSON += _T("\", \"details\":\""); strJSON += szDocName;
			strJSON += _T("\"}");

			if( m_pUserData->CheckText( strText, TYPE_PRINTER, strJSON, strEvent, bScreenShot, bShowMsg, bEraseText ) )
			{
				m_pUserData->ClearScreenShot();
				if( bScreenShot == VARIANT_TRUE )
				{
					g_pSecurityAgent->Fire_ScreenShot( m_strUserName );
				}
				bSendEvent = true;
			}

			if( bShowMsg == VARIANT_TRUE )
				g_pSecurityAgent->Fire_ShowMsg( m_strUserName, TYPE_PRINTER | m_pUserData->ActionLevel() );
	
			if( bSendEvent )
			{
				m_pUserData->LockScreenShot();
				g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_pUserData->GetScreenShot() );
				m_pUserData->UnlockScreenShot();
			}
		}

	}
	else
	{
		DWORD dwError = GetLastError();
		dwError = 0;
	}
	g_pSecurityAgent->Fire_ShowCheckDialog( m_strUserName, 0 );
	DeleteFile( strFile );

	if( bEraseText == VARIANT_FALSE )
	{
		CAtlFile f;

		if( f.Create( szRawFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) != S_OK )
			return;

		PrinterSetPort( szPrinterName, NULL );
			
		m_token.Impersonate();

		HANDLE hPrinter;
		if( OpenPrinter( szPrinterName, &hPrinter, NULL ) )
		{
			DOC_INFO_1 di = { 0 };
			di.pDocName = szDocName;
			di.pOutputFile = NULL;
			di.pDatatype = _T("RAW");
			DWORD dwJobID = StartDocPrinter( hPrinter, 1, reinterpret_cast<PBYTE>(&di) );

			if( dwJobID  )
			{
				const DWORD nBufSize = 1024 * 16;
				BYTE Buffer[ nBufSize ];

				DWORD dwWritten = 0;
				DWORD dwRead = 0;
				do
				{
					f.Read( Buffer, nBufSize, dwRead );
					if( !WritePrinter( hPrinter, Buffer, dwRead, &dwWritten ) )
					{
						DWORD dwError = GetLastError();
						dwError = 0;
					}
				}while( dwRead == nBufSize );

				EndDocPrinter( hPrinter );
			}
			else
				AbortPrinter( hPrinter );

			//int n = 0;
			while( true )
			{
				DWORD dwNeeded = 0;
				if( !GetJob( hPrinter, dwJobID, 1, NULL, 0, &dwNeeded ) )
				{
					DWORD dwError = GetLastError();
					if( dwError != 122 )
						dwError = 0;
				}
				if( !dwNeeded || dwNeeded > 1024 * 1024 )
				{
					Sleep( 100 );
					break;
				}

				PBYTE pBuffer = new BYTE[ dwNeeded ];
				ZeroMemory( pBuffer, dwNeeded );
				JOB_INFO_1 *pJobInfo = reinterpret_cast<JOB_INFO_1 *>(pBuffer );
				if( !GetJob( hPrinter, dwJobID, 1, pBuffer, dwNeeded, &dwNeeded ) )
				{
					DWORD dwError = GetLastError();
					dwError = 0;
				}
				DWORD dwStatus = pJobInfo->Status;
				delete [] pBuffer;

#if (NTDDI_VERSION >= NTDDI_VISTA)
				if( dwStatus & ( JOB_STATUS_PRINTING | JOB_STATUS_RETAINED ) )
					continue;
#else
				if( dwStatus & ( JOB_STATUS_PRINTING ) )
					continue;
#endif
				if( dwStatus & JOB_STATUS_PRINTED )
					break;
				//++n;
				Sleep( 100 );
			}

			if( !ClosePrinter( hPrinter ) )
			{
				DWORD dwError = GetLastError();;
				dwError = 0;
			}
		}

		m_token.Revert();
		
		PrinterSetPort( szPrinterName );
	}
}

void CDwService::PrintJobImg( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName )
{
	g_pSecurityAgent->Fire_ShowCheckDialog( m_strUserName, TYPE_PRINTER );
	CString strFile;
	CAtlFile f;
	GetTempFile( _T("prnImage_%d.png"), f, strFile );
	strFile.Insert( strFile.GetLength() - 4, _T("_%d") );
	f.Close();

	CString strCmd;
	GetModuleDirectory( strCmd );
	strCmd += _T("gs\\");
	SetCurrentDirectory( strCmd );
	strCmd += "pcl6.exe\" ";
	strCmd.Insert( 0, _T('\"') );
	strCmd += _T("-dNOPAUSE -sDEVICE=pngmono -r300 -sOutputFile=\"");
	//strCmd += _T("-dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=\"");
	strCmd += strFile;
	strCmd += _T("\" \"");
	strCmd += szRawFile;
	strCmd += _T("\"");

	HANDLE hProc = NULL;
	RunProcess( strCmd.GetBuffer(), &hProc );
	WaitForSingleObject( hProc, INFINITE );
	CloseHandle( hProc );

	GetModuleDirectory( strCmd );
	SetCurrentDirectory( strCmd );

	CString strImg;
	int nFile = 1;
	CStringA strTxt;
	while( true )
	{
		strImg.Format( strFile, nFile++ );
		if( !FileExist( strImg ) )
			break;
		GetModuleDirectory( strCmd );
		strCmd += _T("tesseract.exe\" \"");
		strCmd.Insert( 0, _T('\"') );
		strCmd += strImg;
		strCmd += _T("\" \"");
		strCmd += strImg; //tesseract.exe add extension .txt automatically
		strCmd += _T("\"");

		hProc = NULL;
		RunProcess( strCmd.GetBuffer(), &hProc );
		WaitForSingleObject( hProc, INFINITE );
		CloseHandle( hProc );
		DeleteFile( strImg );
		strImg += _T(".txt");
		CAtlFile fTxt;
		if( S_OK == fTxt.Create( strImg, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
		{
			ULONGLONG nSize = 0;
			fTxt.GetSize( nSize );
			if( nSize )
			{
				int nLen = strTxt.GetLength();
				fTxt.Read( strTxt.GetBufferSetLength( nLen + int(nSize) ) + nLen, DWORD(nSize) );
			}
		}
		DeleteFile( strImg );
	}

	VARIANT_BOOL bEraseText = VARIANT_FALSE;

	if( strTxt.GetLength() )
	{
		ULONGLONG nLen = 0;
		CStringA strEvent;
		VARIANT_BOOL bScreenShot = VARIANT_FALSE;
		VARIANT_BOOL bShowMsg = VARIANT_FALSE;
		bool bSendEvent = false;
		//TODO: When to send events? only when block policy?
		CStringA strJSON = "{\"process_name\":\"spoolsv.exe\", \"description\":\"";
		strJSON += szPrinterName; 
		strJSON += _T("\", \"details\":\""); strJSON += szDocName;
		strJSON += _T("\"}");


		if( m_pUserData->CheckText( strTxt, TYPE_PRINTER, strJSON, strEvent, bScreenShot, bShowMsg, bEraseText ) )
		{
			m_pUserData->ClearScreenShot();
			if( bScreenShot == VARIANT_TRUE )
			{
				g_pSecurityAgent->Fire_ScreenShot( m_strUserName );
			}
			bSendEvent = true;
		}

		if( bShowMsg == VARIANT_TRUE )
			g_pSecurityAgent->Fire_ShowMsg( m_strUserName, TYPE_PRINTER | m_pUserData->ActionLevel() );
	
		if( bSendEvent )
		{
			m_pUserData->LockScreenShot();
			g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_pUserData->GetScreenShot() );
			m_pUserData->UnlockScreenShot();
		}
	}
	else
	{
		DWORD dwError = GetLastError();
		dwError = 0;
	}
	g_pSecurityAgent->Fire_ShowCheckDialog( m_strUserName, 0 );
	DeleteFile( strFile );

	if( bEraseText == VARIANT_FALSE )
	{
		CAtlFile f;

		if( f.Create( szRawFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) != S_OK )
			return;

		PrinterSetPort( szPrinterName, NULL );
			
		m_token.Impersonate();

		HANDLE hPrinter;
		if( OpenPrinter( szPrinterName, &hPrinter, NULL ) )
		{
			DOC_INFO_1 di = { 0 };
			di.pDocName = szDocName;
			di.pOutputFile = NULL;
			di.pDatatype = _T("RAW");
			DWORD dwJobID = StartDocPrinter( hPrinter, 1, reinterpret_cast<PBYTE>(&di) );

			if( dwJobID  )
			{
				const DWORD nBufSize = 1024 * 16;
				BYTE Buffer[ nBufSize ];

				DWORD dwWritten = 0;
				DWORD dwRead = 0;
				do
				{
					f.Read( Buffer, nBufSize, dwRead );
					if( !WritePrinter( hPrinter, Buffer, dwRead, &dwWritten ) )
					{
						DWORD dwError = GetLastError();
						dwError = 0;
					}
				}while( dwRead == nBufSize );

				EndDocPrinter( hPrinter );
			}
			else
				AbortPrinter( hPrinter );

			//int n = 0;
			while( true )
			{
				DWORD dwNeeded = 0;
				if( !GetJob( hPrinter, dwJobID, 1, NULL, 0, &dwNeeded ) )
				{
					DWORD dwError = GetLastError();
					if( dwError != 122 )
						dwError = 0;
				}
				if( !dwNeeded || dwNeeded > 1024 * 1024 )
				{
					Sleep( 100 );
					break;
				}

				PBYTE pBuffer = new BYTE[ dwNeeded ];
				ZeroMemory( pBuffer, dwNeeded );
				JOB_INFO_1 *pJobInfo = reinterpret_cast<JOB_INFO_1 *>(pBuffer );
				if( !GetJob( hPrinter, dwJobID, 1, pBuffer, dwNeeded, &dwNeeded ) )
				{
					DWORD dwError = GetLastError();
					dwError = 0;
				}
				DWORD dwStatus = pJobInfo->Status;
				delete [] pBuffer;

#if (NTDDI_VERSION >= NTDDI_VISTA)
				if( dwStatus & ( JOB_STATUS_PRINTING | JOB_STATUS_RETAINED ) )
					continue;
#else
				if( dwStatus & ( JOB_STATUS_PRINTING ) )
					continue;
#endif

				if( dwStatus & JOB_STATUS_PRINTED )
					break;
				//++n;
				Sleep( 100 );
			}

			if( !ClosePrinter( hPrinter ) )
			{
				DWORD dwError = GetLastError();;
				dwError = 0;
			}
		}

		m_token.Revert();
		
		PrinterSetPort( szPrinterName );
	}
}


//void CDwService::PrintJob( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName )
//{
//	g_pSecurityAgent->Fire_ShowCheckDialog( m_strUserName, TYPE_PRINTER );
//	CString strFile;
//	CAtlFile f;
//	GetTempFile( _T("prnImage_%d.png"), f, strFile );
//	f.Close();
//
//	CString strCmd;
//	GetModuleDirectory( strCmd );
//	strCmd += "pspcl6.exe\" ";
//	strCmd.Insert( 0, _T('\"') );
//	strCmd += _T("-dNOPAUSE -sDEVICE=pngmono -r300 -sOutputFile=\"");
//	//strCmd += _T("-dNOPAUSE -dBATCH -sDEVICE=pdfwrite -sOutputFile=\"");
//	strCmd += strFile;
//	strCmd += _T("\" \"");
//	strCmd += szRawFile;
//	strCmd += _T("\"");
//
//	HANDLE hProc = NULL;
//	RunProcess( strCmd.GetBuffer(), &hProc );
//	WaitForSingleObject( hProc, INFINITE );
//	CloseHandle( hProc );
//
//	GetModuleDirectory( strCmd );
//	strCmd += _T("tesseract.exe\" \"");
//	strCmd.Insert( 0, _T('\"') );
//	strCmd += strFile;
//	strCmd += _T("\" \"");
//	strCmd += strFile; //tesseract.exe add extension .txt automatically
//	strCmd += _T("\"");
//
//	hProc = NULL;
//	RunProcess( strCmd.GetBuffer(), &hProc );
//	WaitForSingleObject( hProc, INFINITE );
//	CloseHandle( hProc );
//
//	DeleteFile( strFile );
//	strFile += _T(".txt");
//
//	VARIANT_BOOL bEraseText = VARIANT_FALSE;
//
//	if( S_OK == f.Create( strFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
//	{
//		ULONGLONG nLen = 0;
//		if( S_OK == f.GetSize( nLen ) )
//		{
//			CStringA strText;
//			f.Read( strText.GetBufferSetLength( int(nLen) ), DWORD(nLen) );
//			f.Close();
//			CStringA strEvent;
//			VARIANT_BOOL bScreenShot = VARIANT_FALSE;
//			VARIANT_BOOL bShowMsg = VARIANT_FALSE;
//			bool bSendEvent = false;
//			//TODO: When to send events? only when block policy?
//			if( m_pUserData->CheckText( strText, TYPE_PRINTER, CStringA(szPrinterName), strEvent, bScreenShot, bShowMsg, bEraseText ) )
//			{
//				m_pUserData->ClearScreenShot();
//				if( bScreenShot == VARIANT_TRUE )
//				{
//					g_pSecurityAgent->Fire_ScreenShot( m_strUserName );
//				}
//				bSendEvent = true;
//			}
//
//			if( bShowMsg == VARIANT_TRUE )
//				g_pSecurityAgent->Fire_ShowMsg( m_strUserName, TYPE_PRINTER | m_pUserData->ActionLevel() );
//	
//			if( bSendEvent )
//			{
//				m_pUserData->LockScreenShot();
//				g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_pUserData->GetScreenShot() );
//				m_pUserData->UnlockScreenShot();
//			}
//		}
//
//	}
//	else
//	{
//		DWORD dwError = GetLastError();
//		dwError = 0;
//	}
//	g_pSecurityAgent->Fire_ShowCheckDialog( m_strUserName, 0 );
//	DeleteFile( strFile );
//
//	if( bEraseText == VARIANT_FALSE )
//	{
//		CAtlFile f;
//
//		if( f.Create( szRawFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) != S_OK )
//			return;
//
//		PrinterSetPort( szPrinterName, NULL );
//			
//		m_token.Impersonate();
//
//		HANDLE hPrinter;
//		if( OpenPrinter( szPrinterName, &hPrinter, NULL ) )
//		{
//			DOC_INFO_1 di = { 0 };
//			di.pDocName = szDocName;
//			di.pOutputFile = NULL;
//			di.pDatatype = _T("RAW");
//			DWORD dwJobID = StartDocPrinter( hPrinter, 1, reinterpret_cast<PBYTE>(&di) );
//
//			if( dwJobID  )
//			{
//				const DWORD nBufSize = 1024 * 16;
//				BYTE Buffer[ nBufSize ];
//
//				DWORD dwWritten = 0;
//				DWORD dwRead = 0;
//				do
//				{
//					f.Read( Buffer, nBufSize, dwRead );
//					if( !WritePrinter( hPrinter, Buffer, dwRead, &dwWritten ) )
//					{
//						DWORD dwError = GetLastError();
//						dwError = 0;
//					}
//				}while( dwRead == nBufSize );
//
//				EndDocPrinter( hPrinter );
//			}
//			else
//				AbortPrinter( hPrinter );
//
//			//int n = 0;
//			while( true )
//			{
//				DWORD dwNeeded = 0;
//				if( !GetJob( hPrinter, dwJobID, 1, NULL, 0, &dwNeeded ) )
//				{
//					DWORD dwError = GetLastError();
//					if( dwError != 122 )
//						dwError = 0;
//				}
//				if( !dwNeeded || dwNeeded > 1024 * 1024 )
//				{
//					Sleep( 100 );
//					break;
//				}
//
//				PBYTE pBuffer = new BYTE[ dwNeeded ];
//				ZeroMemory( pBuffer, dwNeeded );
//				JOB_INFO_1 *pJobInfo = reinterpret_cast<JOB_INFO_1 *>(pBuffer );
//				if( !GetJob( hPrinter, dwJobID, 1, pBuffer, dwNeeded, &dwNeeded ) )
//				{
//					DWORD dwError = GetLastError();
//					dwError = 0;
//				}
//				DWORD dwStatus = pJobInfo->Status;
//				delete [] pBuffer;
//
//				if( dwStatus & ( JOB_STATUS_PRINTING | JOB_STATUS_RETAINED ) )
//					continue;
//
//				if( dwStatus & JOB_STATUS_PRINTED )
//					break;
//				//++n;
//				Sleep( 100 );
//			}
//
//			if( !ClosePrinter( hPrinter ) )
//			{
//				DWORD dwError = GetLastError();;
//				dwError = 0;
//			}
//		}
//
//		m_token.Revert();
//		
//		PrinterSetPort( szPrinterName );
//	}
//}

void CDwService::Close( VARIANT_BOOL bUpdate )
{
	Fire_Close( bUpdate );
	if( m_thMonitor )
	{
		m_evtMonitor.Set();
		WaitForSingleObject( m_thMonitor, INFINITE );
	}
}

//bool CDwService::IsMappedDrive( PCTSTR szOrg, CString &strUNCPath )
//{
//	if( !szOrg || szOrg[ 0 ] == _T('\\') )
//		return false;
//	TCHAR szDrive[] = _T("X:\\");
//	szDrive[ 0 ] = szOrg[ 0 ];
//	if( GetDriveType( szDrive ) == DRIVE_REMOTE )
//	{
//		szDrive[ 2 ] = 0;
//		TCHAR szRemote[ 4096 ];
//		DWORD dwLength = 4096;
//		if( NO_ERROR == WNetGetConnection( szDrive, szRemote, &dwLength ) )
//		{
//			strUNCPath = szRemote;
//			if( strUNCPath.GetLength() && strUNCPath[ strUNCPath.GetLength() - 1 ] != _T('\\') )
//				strUNCPath += _T('\\');
//			strUNCPath += ( szOrg + 3 );
//			return true;
//		}
//	}
//
//	return false;
//}

bool CDwService::IsMappedDrive( PCTSTR szOrg, CString &strUNCPath )
{
	m_token.Impersonate();
	bool bRet = ::IsMappedDrive( szOrg, strUNCPath );
	m_token.Revert();
	return bRet;
}

DWORD WINAPI CDwService::ThreadMonitor( PVOID pVoid )
{
	CDwService *pThis = reinterpret_cast<CDwService *>(pVoid);

	pThis->m_evtMonitor.Create( NULL, FALSE, FALSE, NULL );
	HANDLE hProc = OpenProcess( SYNCHRONIZE, FALSE, pThis->m_dwClientProcID );

	HANDLE hMultiple[ 2 ] = { pThis->m_evtMonitor, hProc };

	CString strAgent;
	GetModuleDirectory( strAgent );
	strAgent += _T("DwUserAgent.exe");

	DWORD dwResult = WaitForMultipleObjects( 2, hMultiple, FALSE, INFINITE );

	CloseHandle( hProc );

	if( dwResult == WAIT_OBJECT_0 + 1 )
		RunProcessAsUser( pThis->m_token, strAgent.GetBuffer() );

	return 0;
}

STDMETHODIMP CDwService::CheckText( BSTR bstrText, TEXT_TYPE nTextType, BSTR bstrApp, VARIANT_BOOL* bEraseText )
{
	return CheckTextExt( bstrText, nTextType, bstrApp, bEraseText, NULL, 0 );
}

STDMETHODIMP CDwService::CheckTextExt( BSTR bstrText, TEXT_TYPE nTextType, BSTR bstrApp, VARIANT_BOOL* bEraseText, BYTE* pImage, DWORD cb )
{
	if( !bEraseText )
		return E_POINTER;
	CStringA strText;
	strText = bstrText;
	CStringA strApp;
	CW2A strA( bstrApp, CP_UTF8 );
	strApp = strA;

	CStringA strEvent;
	VARIANT_BOOL bScreenShot = VARIANT_FALSE;
	VARIANT_BOOL bShowMsg = VARIANT_FALSE;
	bool bSendEvent = false;
	//TODO: When to send events? only when block policy?
	if( m_pUserData->CheckText( strText, nTextType, strApp, strEvent, bScreenShot, bShowMsg, *bEraseText ) )
	{
		m_pUserData->ClearScreenShot();
		if( bScreenShot == VARIANT_TRUE )
		{
			if( nTextType == TYPE_OCR && pImage )
			{
				m_pUserData->SetScreenShot( pImage, cb );
			}
			else
				g_pSecurityAgent->Fire_ScreenShot( m_strUserName );
			//Fire_ScreenShot();
		}
		bSendEvent = true;
		//g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_strScreenShot );
	}

	if( bShowMsg == VARIANT_TRUE )
		g_pSecurityAgent->Fire_ShowMsg( m_strUserName, nTextType | m_pUserData->ActionLevel() );
	
	if( bSendEvent )
	{
		m_pUserData->LockScreenShot();
		g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_pUserData->GetScreenShot() );
		m_pUserData->UnlockScreenShot();
	}

	return S_OK;
}

STDMETHODIMP CDwService::GetProtectionType( ULONG *pt )
{
	if( !pt )
		return E_POINTER;
	*pt = g_pSecurityAgent->GetUserProtectionType( m_strUserName );
	return S_OK;
}

STDMETHODIMP CDwService::AddIfRemoteFile( BSTR bstrDestDir, BSTR bstrFileOrg )
{
	if( bstrDestDir && bstrFileOrg )
	{
		CString strRemoteUnit;
		CString strFileOrg;
		if( !IsMappedDrive( bstrFileOrg, strFileOrg ) )
			strFileOrg = bstrFileOrg;
		if( m_pUserData->IsRemoteUnit( strFileOrg, strRemoteUnit ) )
			g_pSecurityAgent->AddIfRemoteFile( m_strUserName, bstrDestDir, strFileOrg, strRemoteUnit );
	}
	else
		g_pSecurityAgent->AddIfRemoteFile( m_strUserName, NULL, NULL, NULL );
	return S_OK;
}

STDMETHODIMP CDwService::RemoveADS( BSTR bstrFileOrg )
{
	if( bstrFileOrg )
		g_pSecurityAgent->RemoveADS( bstrFileOrg );
	return S_OK;
}

STDMETHODIMP CDwService::AddProxy( BSTR bstrProxyServer, LONG bEnable )
{
	g_pSecurityAgent->AddProxy( bstrProxyServer, bEnable );
	return S_OK;
}

STDMETHODIMP CDwService::CheckFile( FILE_TYPE nFileType, BSTR bstrFileOrg, BSTR bstrFileDest, VARIANT_BOOL bDestIsExternFolder, VARIANT_BOOL *bDeleteFile )
{
	if( !bDeleteFile )
		return E_POINTER;

	if( bstrFileOrg && bDestIsExternFolder )
	{
		CString strUNCPath;
		if( IsMappedDrive( bstrFileOrg, strUNCPath ) )
			return CheckRemoteUnit( strUNCPath.GetBuffer(), bstrFileDest, bDestIsExternFolder, bDeleteFile );

		CAtlFile f;
		CString strFileOrg = bstrFileOrg;
		strFileOrg += _T(":dwr.dat");

		if( S_OK == f.Create( strFileOrg, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
		{
			CStringA strContent;
			ULONGLONG nSize = 0;
			if( S_OK == f.GetSize( nSize ) && nSize && S_OK == f.Read( strContent.GetBufferSetLength( int(nSize) ), DWORD(nSize) ) )
			{
				if( UncompressXOR( strContent ) )
				{
					DWORD nPos = 0;
					if( nPos + sizeof( DWORD ) <= DWORD(strContent.GetLength()) )
					{
						DWORD nFileOrgSize;
						CopyMemory( &nFileOrgSize, strContent.GetBuffer() + nPos, sizeof( DWORD ) );
						nPos += sizeof( DWORD );
						if( nPos + nFileOrgSize <= DWORD(strContent.GetLength()) )
						{
							CopyMemory( strFileOrg.GetBufferSetLength( nFileOrgSize / sizeof(TCHAR) ), strContent.GetBuffer() + nPos, nFileOrgSize );
							HRESULT hr = CheckRemoteUnit( strFileOrg.GetBuffer(), bstrFileDest, bDestIsExternFolder, bDeleteFile );
							if( *bDeleteFile == VARIANT_TRUE )
								return hr;
						}
					}
				}
			}
		}
	}

	CString strPath;
	strPath = bstrFileOrg ? bstrFileOrg : bstrFileDest;

	if( !bstrFileOrg )
	{
		if( m_pUserData->IsSkipedFile( strPath ) )
		{
			*bDeleteFile = VARIANT_FALSE;
			return S_OK;
		}
		if( m_pUserData->IsDeletedFile( strPath ) )
		{
			*bDeleteFile = VARIANT_TRUE;
			g_pSecurityAgent->Fire_ShowMsg( m_strUserName, TYPE_FILE | m_pUserData->ActionLevel() );
			return S_OK;
		}
	}

	CStringA strEvent;
	VARIANT_BOOL bShowMsg = VARIANT_FALSE;

	bool bScreenShot = false;
	bool bSendEvent = false;
	m_pUserData->ClearScreenShot();


	if( m_pUserData->CheckFile( nFileType, strPath, strEvent, *bDeleteFile, bScreenShot ) )
	{
		if( bScreenShot )
			g_pSecurityAgent->Fire_ScreenShot( m_strUserName );
		bSendEvent = true;
		bShowMsg = VARIANT_TRUE;
		//g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_strScreenShot );
	}

	if( bstrFileOrg )
	{
		if( *bDeleteFile == VARIANT_TRUE )
		{
			m_pUserData->FileToDelete( bstrFileDest );
			//bShowMsg = VARIANT_TRUE;
		}
		else
		{
			m_pUserData->SkipFile( bstrFileDest );
			//bShowMsg = VARIANT_FALSE;
		}
	}

	if( bShowMsg == VARIANT_TRUE )
		g_pSecurityAgent->Fire_ShowMsg( m_strUserName, TYPE_FILE | m_pUserData->ActionLevel() );

	if( bSendEvent )
	{
		m_pUserData->LockScreenShot();
		g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_pUserData->GetScreenShot() );
		m_pUserData->UnlockScreenShot();
	}

	return S_OK;
}

STDMETHODIMP CDwService::CheckRemoteUnit( BSTR bstrFileOrg, BSTR bstrFileDest, VARIANT_BOOL bDestIsExternFolder, VARIANT_BOOL *bDeleteFile )
{
	if( !bDeleteFile )
		return E_POINTER;

	CStringA strEvent;

	bool bScreenShot = false;
	bool bSendEvent = false;
	bool bShowMsg = false;
	*bDeleteFile = VARIANT_FALSE;
	m_pUserData->ClearScreenShot();

	if( bstrFileOrg && bDestIsExternFolder && m_pUserData->ActiveModules() & PROTECT_NETWORKDEVICE_DST )
	{
		if( m_pUserData->CheckRemoteUnit( bstrFileOrg, strEvent, *bDeleteFile, bScreenShot ) )
		{
			if( bScreenShot )
				g_pSecurityAgent->Fire_ScreenShot( m_strUserName );
			bSendEvent = true;
			bShowMsg = true;
			//g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_strScreenShot );
			//return S_OK;
		}
	}

	if( bShowMsg )
		g_pSecurityAgent->Fire_ShowMsg( m_strUserName, TYPE_FILE | m_pUserData->ActionLevel() );

	if( bSendEvent )
	{
		m_pUserData->LockScreenShot();
		g_pSecurityAgent->SendEvent( CStringA(m_strUserName), strEvent, m_pUserData->GetScreenShot() );
		m_pUserData->UnlockScreenShot();
	}

	return S_OK;
}

STDMETHODIMP CDwService::SkipFile( BSTR bstrFileDest )
{
	// TODO: agregar aquí el código de implementación
	m_pUserData->SkipFile( bstrFileDest );

	return S_OK;
}


STDMETHODIMP CDwService::MonitorProcess(ULONG dwProcId)
{
	m_dwClientProcID = dwProcId;
	m_thMonitor = CreateThread( NULL, 0, ThreadMonitor, reinterpret_cast<PVOID>(this), 0, NULL );
	return S_OK;
}

STDMETHODIMP CDwService::SetScreenShot( BYTE *pImage, DWORD cb )
{
	if( m_pUserData )
		m_pUserData->SetScreenShot( pImage, cb );
	return S_OK;
}

STDMETHODIMP CDwService::SendATPEvent( BSTR bstrUserName, BSTR bstrJSON )
{
	g_pSecurityAgent->SendEvent( CStringA(bstrUserName) ,CStringA(bstrJSON), CStringA(""), true );
	//TODO: Show Message and capture screenshot?
	g_pSecurityAgent->Fire_ShowMsg( m_strUserName, TYPE_ATP | TYPE_LEVEL_WARNING );
	return S_OK;
}

STDMETHODIMP CDwService::LoadATP( BSTR bstrProcName, VARIANT_BOOL* bLoad )
{
	if( !bLoad )
		return E_POINTER;

	if( g_pSecurityAgent->IsAtpProcess( bstrProcName ) )
		*bLoad = VARIANT_TRUE;
	else
		*bLoad = VARIANT_FALSE;

	return S_OK;
}

STDMETHODIMP CDwService::IsLicensed( VARIANT_BOOL *pbLicensed )
{
	if( !pbLicensed )
		return E_POINTER;
	//Sleep( 1000 * 100 );
	CString strPath;
	GetModuleDirectory( strPath );
	strPath += _T("sftt.tmp");

	if( !FileExist( strPath ) )
	{
		CAtlFile f;
		f.Create( strPath, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
	}


	*pbLicensed = VARIANT_FALSE;
	CRegKey rKey;
	if( rKey.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint") ) != ERROR_SUCCESS )
	{
		*pbLicensed = VARIANT_FALSE;
		return S_OK;
	}

	TCHAR szValue[ 64 ] = { 0 };
	ULONG nChars = 64;
	if( rKey.QueryStringValue( _T("DDI_LIC"), szValue, &nChars ) != ERROR_SUCCESS ) //not cloud version
	{
		*pbLicensed = VARIANT_TRUE;
		return S_OK;
	}

	CStringA strUrl;
	CStringA strServer;
	LONG nCode = -1;
	int nPort = 0;
	HRESULT hr = CheckLicense( szValue, nCode, strUrl, strServer, nPort );
	if( hr == S_OK )
	{
		if( nCode >= 0 )
		{
			CRegKey regDrainWare;
			if( regDrainWare.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware") ) != ERROR_SUCCESS )
				regDrainWare.Create( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware") );

			CRegKey regEndPoint;
			if( regEndPoint.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint") ) != ERROR_SUCCESS )
				regEndPoint.Create( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint") );

			CString strServerT;
			strServerT = strServer;
			if( nPort )
				regEndPoint.SetDWORDValue( _T("AMQP_PORT"), nPort );
			if( strServer.GetLength() )
			{
				regEndPoint.SetStringValue( _T("DDI_IP"), strServerT );
				g_pSecurityAgent->SetDDI_IP( strServer, nPort );
			}

		}
		if( !nCode || nCode == -2 )
			*pbLicensed = VARIANT_TRUE;
	}

	return S_OK;
}

HRESULT CDwService::CheckLicense( PCTSTR szValue, LONG &nCode, CStringA &strURL, CStringA &strServer, int &nPort )
{
		CStringA strPost;

		strPost = "license=";
		strPost += CT2A(szValue); strPost += "&";

		//Vol C: ID
		char szVolumeName[ 64 ] = { 0 };
		GetVolumeNameForVolumeMountPointA( "C:\\", szVolumeName, 64 );
		CStringA strGuid;
		strGuid.Append( szVolumeName + 10, 38 );

		strPost += "VOL_ID=";
		strPost += strGuid.GetBuffer(); strPost += "&";

		//CPU ID
		int cpuInfo[ 4 ];
		__cpuid( cpuInfo, 1 );
		char szCpuInfo[ 64 ] = { 0 };
		wsprintfA( szCpuInfo, "%04X%04X%04X%04X", cpuInfo[ 0 ], cpuInfo[ 1 ], cpuInfo[ 2 ], cpuInfo[ 3 ] );
		strPost += "CPU_ID=";
		strPost += szCpuInfo;

		CStringA strResult;
		//Post( "http://cloud.drainware.com/api/checkLic.php", strPost, strResult );
		if( !Post( "https://www.drainware.com/ddi/?module=cloud&action=validateLicense", strPost, strResult ) )
		{
			//No connection
			//return E_FAIL;
			if( g_pSecurityAgent->HaveLicense() )
			{
				nCode = -2;
				return S_OK; //If connection is not possible, continue
			}
			return  E_FAIL;
		}

		nCode = -1;
		if( strResult.GetLength() )
		{
			json_object *oJson = json_tokener_parse( strResult );
			if( !oJson )
				return g_pSecurityAgent->HaveLicense() ? S_OK : E_FAIL;
			json_object *oCode = json_object_object_get( oJson, "code" );
			if( oCode )
				nCode = json_object_get_int( oCode );
			json_object *oUrl = json_object_object_get( oJson, "url" );
			if( oUrl )
				strURL = json_object_get_string( oUrl );
			json_object *oServer = json_object_object_get( oJson, "server" );
			if( oServer )
				strServer = json_object_get_string( oServer );

			json_object *oPort = json_object_object_get( oJson, "port" );
			if( oPort )
				nPort = json_object_get_int( oPort );

			if( !nCode )
				return S_OK;
			return E_FAIL;
		}
	return g_pSecurityAgent->HaveLicense() ? S_OK : E_FAIL;
}

bool CDwService::Post( const char *szUrl, CStringA &strPost, CStringA &strResult )
{
	CString strURL;
	strURL = szUrl;

	bool bProxyEnable = false;
	const CAtlArray< CString > &aProxy = g_pSecurityAgent->ProxyServer( bProxyEnable );
	if( aProxy.GetCount() )
	{
		for( size_t i = 0; i < aProxy.GetCount(); i++ )
		{
			if( QueryWinHttp( strURL, strResult, 443, &strPost, _T("application/x-www-form-urlencoded"), aProxy[ i ], bProxyEnable ) )
				return true;
		}
	}
	else
		return QueryWinHttp( strURL, strResult, 443, &strPost, _T("application/x-www-form-urlencoded") );
	return false;
	//return QueryWinHttp( strURL, strResult, 443, &strPost, _T("application/x-www-form-urlencoded"), strProxy, bProxyEnable );
	//CAtlHttpClient cli;
	//CAtlNavigateData nd;
	//nd.SetPostData( (BYTE *)strPost.GetBuffer(), strPost.GetLength(), _T("application/x-www-form-urlencoded") );
	//nd.SetMethod( ATL_HTTP_METHOD_POST );

	//CString strUrl;
	//strUrl = szUrl;

	//if( cli.Navigate( strUrl, (ATL_NAVIGATE_DATA*)&nd ) )
	//{
	//	if( cli.GetStatus() == 200 )
	//	{
	//		CopyMemory( strResult.GetBufferSetLength( cli.GetBodyLength() ), cli.GetBody(), cli.GetBodyLength() );
	//		return true;
	//	}
	//}

	//return false;
}

STDMETHODIMP CDwService::SetLicense( BSTR bstrLic1, BSTR bstrLic2, BSTR bstrLic3, BSTR bstrLic4, BSTR *bstrUrl, LONG* pnCode )
{
	if( !bstrUrl || !pnCode )
		return E_POINTER;

	CString strLic;
	strLic += bstrLic1; strLic += _T("-"); strLic += bstrLic2; strLic += _T("-");
	strLic += bstrLic3; strLic += _T("-"); strLic += bstrLic4;

	CStringA strUrl;
	CStringA strServer;
	int nPort = 0;
	if( CheckLicense( strLic, *pnCode, strUrl, strServer, nPort ) == S_OK )
	{
		if( *pnCode >= 0 )
		{
			CRegKey regDrainWare;
			if( regDrainWare.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware") ) != ERROR_SUCCESS )
				regDrainWare.Create( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware") );

			CRegKey regEndPoint;
			if( regEndPoint.Open( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint") ) != ERROR_SUCCESS )
				regEndPoint.Create( HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Drainware\\SecurityEndpoint") );

			regEndPoint.SetStringValue( _T("DDI_LIC"), strLic );
			//regEndPoint.SetStringValue( _T("DDI_LIC_COPY"), strLic );
			//m_strUser = bstrLic1;
			//m_strUser += bstrLic2;
			//m_strPassword = bstrLic3;
			//m_strPassword += bstrLic4;
			CString strServerT;
			strServerT = strServer;
			if( strServer.GetLength() )
			{
				regEndPoint.SetStringValue( _T("DDI_IP"), strServerT );
				//m_strServer = strServer;
				//regCloud.SetStringValue( _T("Server"), m_strServer );
			}
			if( nPort )
				regEndPoint.SetDWORDValue( _T("AMQP_PORT"), nPort );
			g_pSecurityAgent->SetLicense( strLic, strServerT, nPort );
			//if( *pnCode == 0 )
			//	ConnectVPN();
		}
	}
	else
		*pnCode = -1;

	if( strUrl.GetLength() )
	{
		CComBSTR bstrU = strUrl;
		*bstrUrl = bstrU.Detach();
	}

	return S_OK;
}
