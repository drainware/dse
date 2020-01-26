#pragma once


interface ISecurityAgent
{
	virtual CUserData *AddClient( CDwService *pClient ) = 0;
	virtual void AddIfRemoteFile( const CString &strUserName, const WCHAR *szDestDir, const WCHAR *szFileOrg, const WCHAR *szRemoteUnit ) = 0;
	virtual void RemoveADS( const WCHAR *szFileOrg ) = 0;
	virtual void AddProxy( const WCHAR *szProxyServer, LONG bEnable ) = 0;
	virtual const CAtlArray< CString > &ProxyServer( bool &bProxyEnable ) = 0;
	virtual void RemoveClient( CDwService *pClient ) = 0;
	virtual void PrintJob( PTSTR szDocName, PCTSTR szRawFile, PTSTR szPrinterName, PCTSTR szUserName ) = 0;
	virtual void SendEvent( const CStringA &strUserName, const CStringA &strEvent, CStringA &strScreenShot, bool bATP = false ) = 0;
	virtual bool IsAtpProcess( LPCTSTR szProcName ) = 0;
	virtual void SetLicense( const CString &strLic, const CString &strServer, int nPort ) = 0;
	virtual bool HaveLicense() = 0;
	virtual void SetDDI_IP( const CStringA &strIP, int nPort ) = 0;
	virtual void EnablePrinter( BOOL bEnable ) = 0;
	virtual ULONG GetUserProtectionType( CString &strUserName ) = 0;
	virtual bool IsClosing() = 0;
	virtual void Fire_ScreenShot( const CString &strUserName ) = 0;
	virtual void Fire_ShowMsg( const CString &strUserName, ULONG nType ) = 0;
	virtual void Fire_ShowCheckDialog( const CString &strUserName, ULONG nType ) = 0;
	virtual void Fire_ActiveModules( const CString &strUserName, ULONG nActiveModules ) = 0;
};
