#pragma once

#include "DrainwareSecurityAgent_i.h"
#include "DDI.h"

struct UserConcept
{
	CStringA m_strID;
	CStringA m_strSubConcept;
	CStringA m_strDescription;
	CStringA m_strVerify;
	CStringA m_strAction;
	CStringA m_strSeverity;
	CAtlList< CStringA > m_lstPolicies;
};

struct UserRule
{
	CStringA m_strID;
	CStringA m_strRule;
	CStringA m_strDescription;
	CStringA m_strAction;
	CStringA m_strSeverity;
	CStringA m_strVerify;
	CAtlList< CStringA > m_lstPolicies;
};

struct NetworkPlace
{
	CStringA m_strID;
	CStringA m_strURI;
	CStringA m_strDescription;
	CStringA m_strAction;
	CStringA m_strSeverity;
	CAtlList< CStringA > m_lstPolicies;

	void operator=( const NetworkPlace &src )
	{
		m_strID = src.m_strID;
		m_strURI = src.m_strURI;
		m_strDescription = src.m_strURI;
		m_strAction = src.m_strAction;
		m_strSeverity = src.m_strSeverity;

		m_lstPolicies.RemoveAll();
		POSITION pos = src.m_lstPolicies.GetHeadPosition();
		while( pos )
		{
			m_lstPolicies.AddTail( src.m_lstPolicies.GetAt( pos ) );
			src.m_lstPolicies.GetNext( pos );
		}
	}
};

struct UserApplication
{
	CStringA m_strID;
	CString m_strApp;
	CStringA m_strDescription;
	CAtlList< CStringA > m_lstPolicies;
};


class CUserData : public IUserNotify
{
public:
	enum ScreenShotLog
	{
		SC_NONE = 0,
		SC_LOW,
		SC_MEDIUM,
		SC_HIGH
	};

	CUserData( const CString &strName, IDDICtl *pDDI ) : m_strUserName( strName ), m_hThread( NULL ), m_nActiveModules( 0 ), m_pDDI( pDDI )
	{
		m_ulLastUpdate.QuadPart = 0;
	}

//IUserNotify
	void OnUserConfig( const CStringA &strJSON );
	void OnGroupChanged( const CStringA &strGroup, const CStringA &strJSON );
	const CAtlList< CStringA > &Groups() { return m_lstGroups; }
//Class Methods
	bool CheckText( const CStringA &strText, TEXT_TYPE nTextType, const CStringA &strApp, CStringA &strJSONEvent, VARIANT_BOOL &bScreenShot, VARIANT_BOOL &bShowMsg, VARIANT_BOOL &bBlock );
	bool CheckFile( FILE_TYPE nFileType, const CString &strFilePath, CStringA &strJSONEvent, VARIANT_BOOL &bBlock, bool &bScreenShot, const char *szApp = NULL );
	bool CheckRemoteUnit( const CString &strFilePath, CStringA &strJSONEvent, VARIANT_BOOL &bBlock, bool &bScreenShot, const char *szApp = NULL );
	bool IsRemoteUnit( const WCHAR *szFilePath, CString &strRemoteUnit );
	bool FindApp( const CString &strApp );
	void SkipFile( LPCTSTR szFile );
	void FileToDelete( LPCTSTR szFile );
	bool IsSkipedFile( LPCTSTR szFile );
	bool IsDeletedFile( LPCTSTR szFile );
	bool IsMimeTypeOfProc( const CString &strProc, const CString &strFileName );
	void ClearScreenShot();
	void SetScreenShot( BYTE *pImage, DWORD cb );
	inline void LockScreenShot() { m_csSC.Enter(); }
	inline void UnlockScreenShot() { m_csSC.Leave(); }
	inline CStringA &GetScreenShot() { return m_strScreenShot; }
	inline ULONG ActiveModules() const throw() { return m_nActiveModules; }
	bool GetRemoteFileName( CString &strFile, CString &strRemoteName );

	void LoadConfig();
	void AddGroup( const char *szGroup );
	void DeleteGroup( const char *szGroup );

	UINT ActionLevel();
	UINT LevelFromAction( CStringA &strAction );
	void SetActionFromLevel( UINT nAction );
	void SetActionFromJson( const CStringA &strJson );

	void SetToken( CAccessToken &token ) { m_ptoken = &token; }
	CAccessToken *GetToken() { return m_ptoken; }

	CString m_strUserName;

private:
	static DWORD WINAPI ThreadLoadConfig( PVOID pVoid );
	void RemoveGroups();
	int LevelFromSeverity( const CStringA &strSeverity );
	DWORD ExecuteCommand( CString &strCmd, CStringA &strResult );
	DWORD VerifyMatch( CStringA &strID, CStringA &strCode, const CStringA &strMatch );
	const char *GetFileType( FILE_TYPE nType );
	void ChangeSourceApp( CStringA &strJSONEvent, FILE_TYPE nFileType, const char *szApp );

	CAtlList< UserConcept > m_lstConcepts;
	CAtlList< UserRule > m_lstRules;
	CAtlList< CStringA > m_lstGroups;
	CAtlList< NetworkPlace > m_lstNetPlaces;
	CAtlList< UserApplication > m_lstApps;
	CAtlList< CStringA > m_lstGdriveDomains;
	CStringA m_strAction;
	CStringA m_strSeverity;
	CStringA m_strJSON;
	int m_nSCLevel;
	ULONG m_nActiveModules;
	CCriticalSection m_cs;
	CCriticalSection m_csFile;
	HANDLE m_hThread;

	CAtlMap< CString, DWORD > m_mapSkipFiles; //Files to skip from CheckFile
	CAtlMap< CString, DWORD >  m_mapDeleteFiles; //Files to delete ( from shell extension )
	//CAtlArray< CString > m_aNetworkPlaces;
	CCriticalSection m_csSkip;
	CCriticalSection m_csSC;
	CStringA m_strScreenShot;
	IDDICtl *m_pDDI;
	ULARGE_INTEGER m_ulLastUpdate;
	CAccessToken *m_ptoken;

};
