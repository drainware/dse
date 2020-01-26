#include "stdafx.h"
#include "PrinterPort.h"
#include "PrinterMonitor.h"
#include <new>
#include <atlsecurity.h>
#include "../DwLib/DwLib.h"

CAtlArray< DwJob > CPrinterPort::m_aJobs;
CCriticalSection CPrinterPort::m_cs;
volatile LONG CPrinterPort::m_nCurrentDocs;

CPrinterPort::CPrinterPort() : m_hMonitor( INVALID_HANDLE_VALUE ), m_dwJobID( 0 )//, m_hPrinter( INVALID_HANDLE_VALUE )
{}

CPrinterPort::~CPrinterPort()
{
	//if( m_hPrinter != INVALID_HANDLE_VALUE )
	//	ClosePrinter( m_hPrinter ), m_hPrinter = INVALID_HANDLE_VALUE;
}

BOOL CPrinterPort::CreatePort( HANDLE hMonitor, PTSTR szName, PHANDLE pHandle )
{
	//HGLOBAL hGlobal = GlobalAlloc( GPTR, sizeof(CPrinterPort) );
	//
	//CPrinterPort *pPort = reinterpret_cast<CPrinterPort *>(GlobalLock(hGlobal));

	//new(pPort) CPrinterPort();

	//pPort->m_hMonitor = hMonitor;

	//GlobalUnlock( hGlobal );
	//*pHandle = reinterpret_cast<HANDLE>(hGlobal);

    if( !szName )
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

	if( lstrcmp( szName, DW_PORT ) )
		return FALSE;

	CPrinterPort *pPort = new CPrinterPort();
	if( !pPort )
	{
		SetLastError( ERROR_NOT_ENOUGH_MEMORY );
		return FALSE;
	}

	pPort->m_hMonitor = hMonitor;
	pPort->m_strName = szName;
	*pHandle = reinterpret_cast<HANDLE>(pPort);
	return TRUE;
}

BOOL CPrinterPort::ClosePort( HANDLE hPort )
{
	//HGLOBAL hGlobal = reinterpret_cast<HGLOBAL>(hPort);
	//CPrinterPort *pPort = reinterpret_cast<CPrinterPort *>(GlobalLock(hGlobal));
	//pPort->~CPrinterPort();
	//GlobalUnlock( hGlobal );
	//GlobalFree( hGlobal );
	if( hPort )
		delete reinterpret_cast<CPrinterPort *>(hPort);
	return TRUE;
}

BOOL CPrinterPort::StartDoc( LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo )
{
	InterlockedIncrement( &m_nCurrentDocs );
	m_strPrinterName = pPrinterName;
	m_dwJobID = JobId;

	DOC_INFO_1 *pInfo = reinterpret_cast<DOC_INFO_1 *>(pDocInfo);
	if( pInfo )
		m_strDocName = pInfo->pDocName; //pDocName is the first member for all DOC_INFO_X structures
	else
		m_strDocName = _T("Drainware Monitor");

	HANDLE hPrinter;
	if( OpenPrinter( m_strPrinterName.GetBuffer(), &hPrinter, NULL ) )
	{
		//SetJob( hPrinter, m_dwJobID, 0, NULL, JOB_CONTROL_SENT_TO_PRINTER );
		DWORD dwSize = 0;
		GetJob( hPrinter, JobId, 1, NULL, 0, &dwSize );
		if( dwSize )
		{
			PBYTE pBuffer = new BYTE[ dwSize ];
			if( GetJob( hPrinter, JobId, 1, pBuffer, dwSize, &dwSize ) )
			{
				JOB_INFO_1 *pJob1 = reinterpret_cast<JOB_INFO_1 *>(pBuffer);
				m_strUserName = pJob1->pUserName;
			}
			delete [] pBuffer;
		}
		ClosePrinter( hPrinter );
	}


	GetTempFile( _T("dw_printer_%d.raw"), m_f, m_strFileName );
	//m_f.Create( _T("C:\\Drainware\\out_printer.txt"), GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );


	//if( !OpenPrinter( pPrinterName, &m_hPrinter, NULL ) )
	//	return FALSE;

	return TRUE;
}

BOOL CPrinterPort::EndDoc()
{
	HANDLE hPrinter;
	if( OpenPrinter( m_strPrinterName.GetBuffer(), &hPrinter, NULL ) )
	{
		SetJob( hPrinter, m_dwJobID, 0, NULL, JOB_CONTROL_SENT_TO_PRINTER );
		ClosePrinter( hPrinter );
	}

	//if( m_hPrinter != INVALID_HANDLE_VALUE )
	//{
	//	SetJob( m_hPrinter, m_dwJobID, 0, NULL, JOB_CONTROL_SENT_TO_PRINTER );
	//	ClosePrinter( m_hPrinter );
	//	m_hPrinter = INVALID_HANDLE_VALUE;
	//}
	m_f.Close();

	m_cs.Enter();
		DwJob &dwJob = m_aJobs[ m_aJobs.Add() ];
		dwJob.strPath = m_strFileName;//_T("C:\\Drainware\\out_printer.txt");
		dwJob.strPrinter = m_strPrinterName;
		dwJob.strDocName = m_strDocName;
		dwJob.strUserName = m_strUserName;
	m_cs.Leave();
	InterlockedDecrement( &m_nCurrentDocs );
	return TRUE;
}


BOOL CPrinterPort::Write( LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten )
{
	m_f.Write( pBuffer, cbBuf, pcbWritten );
	return TRUE;
}

void CPrinterPort::Abort()
{
	HANDLE hPrinter;
	if( OpenPrinter( m_strPrinterName.GetBuffer(), &hPrinter, NULL ) )
	{
		AbortPrinter( hPrinter );
		ClosePrinter( hPrinter );
	}
	if( m_f )
		m_f.Close();
	InterlockedDecrement( &m_nCurrentDocs );
}

