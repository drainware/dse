#pragma once

interface IFileSystemDriver
{
	virtual void OnFileRename( CString &strOld, CString &strName, CString &strProc, CString &strUser ) = 0;
	//virtual bool OnFileRead( CString &strName, CString &strProc, CString &strUser ) = 0;
	//virtual void OnFileWrite( CString &strName, CString &strProc, CString &strUser ) = 0;
	virtual bool OnCheckProc( CString &strProc, CString &strUserName ) = 0;
	virtual bool CheckFile( CString &strName, CString &strUser, CString &strApp ) = 0;
	virtual bool Closed() = 0;
	virtual bool IsRemoteFile( const CString &strName, CString &strUser ) = 0;
};