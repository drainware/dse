#pragma once

#define DW_PORT _T("DwPort:")

struct DwJob
{
	CString strPath;
	CString strPrinter;
	CString strDocName;
	CString strUserName;
};

class CPrinterPort
{
public:
	static BOOL CreatePort( HANDLE hMonitor, PTSTR szName, PHANDLE pHandle );
	static BOOL ClosePort( HANDLE hPort );

	BOOL StartDoc( LPWSTR pPrinterName, DWORD JobId, DWORD Level, LPBYTE pDocInfo );
	BOOL EndDoc();

	BOOL Write( LPBYTE pBuffer, DWORD cbBuf, LPDWORD pcbWritten );
private:
	CPrinterPort();
	~CPrinterPort();
	void Abort();
	//void Reset();
	
	HANDLE m_hMonitor;
	CString m_strName;
	CString m_strPrinterName;
	DWORD m_dwJobID;
	CString m_strDocName;
	CString m_strUserName;
	//HANDLE m_hPrinter;
	CString m_strDefaultPort;
	CString m_strFileName;

	CAtlFile m_f;
public:
	static CAtlArray< DwJob > m_aJobs;
	static CCriticalSection m_cs;
	static volatile LONG m_nCurrentDocs;
};
