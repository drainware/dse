#include "stdafx.h"
#include "FileFollower.h"

CFileFollower::CFileFollower() : m_bClose( false )
{
	sqlite3 *pDB = NULL;

	CString strDir;
	GetModuleDirectory( strDir );
	strDir += _T("RmtFiles.db");
	m_strDB = strDir;
	if( sqlite3_open( m_strDB, &pDB ) == SQLITE_OK )
	{
		char *szTable = "CREATE TABLE IF NOT EXISTS RemoteFiles( szFile TEXT UNIQUE PRIMARY KEY ASC )";
		sqlite3_exec( pDB, szTable, NULL, NULL, NULL );
		ReloadDB( pDB );
	}

	if( pDB )
		sqlite3_close( pDB );
}

int CFileFollower::SQLiteCallback( void *pUserData, int argc, char **argv, char **azColName )
{
	CFileFollower *pThis = reinterpret_cast<CFileFollower*>(pUserData);
	CString strDir;
	for( int i = 0; i < argc; i++ )
	{
		strDir = argv[ i ];
		pThis->m_map[ strDir ] = IsDirectory( strDir );
	}

	return 0;
}

void CFileFollower::ReloadDB( sqlite3 *pDB )
{
	m_map.RemoveAll();
	sqlite3_exec( pDB, "SELECT szFile FROM RemoteFiles", SQLiteCallback, this, NULL );
}

void CFileFollower::InsertDirectory( const CString &strDir, CStringA &strSQL, sqlite3 *pDB )
{
	WIN32_FIND_DATA fd = { 0 };
	HANDLE hFind = FindFirstFile( strDir, &fd );

	if( hFind != INVALID_HANDLE_VALUE )
	{
		do
		{

		}while( FindNextFile( hFind, &fd ) );
		FindClose( hFind );
	}
}

void CFileFollower::InsertFile( const CString &strFile, CStringA &strSQL, sqlite3 *pDB )
{
	strSQL.Format( "INSERT INTO RemoteFiles VALUES('%s')", CStringA(strFile) );
	sqlite3_exec( pDB, strSQL, NULL, NULL, NULL );
}

void CFileFollower::Insert( const CString &strFile )
{
	CAutoCS acs( m_csMap );
	bool bDirectory = IsDirectory( strFile );
	m_map[ strFile ] = bDirectory;
	CStringA strSQL;

	sqlite3 *pDB = NULL;
	if( sqlite3_open( m_strDB, &pDB ) == SQLITE_OK )
	{
		InsertFile( strFile, strSQL, pDB );
		if( bDirectory )
			InsertDirectory( strFile, strSQL, pDB );
	}

	if( pDB )
		sqlite3_close( pDB );
	//INSERT INTO RemoteFiles VALUES('%s')
}

void CFileFollower::Rename( const CString &strOldName, const CString &strNewName )
{
	CAutoCS acs( m_csMap );
	POSITION pos = m_map.Lookup( strOldName );
	if( pos )
	{
		m_map.RemoveAtPos( pos );
		m_map[ strNewName ] = IsDirectory( strNewName );

		CStringA strSQL;
		strSQL.Format( "UPDATE RemoteFiles SET szFile = '%s' WHERE szFile = '%s'", CStringA(strNewName), CStringA(strOldName) );

		sqlite3 *pDB = NULL;
		if( sqlite3_open( m_strDB, &pDB ) == SQLITE_OK )
		{
			if( SQLITE_OK != sqlite3_exec( pDB, strSQL, NULL, NULL, NULL ) )
			{
				strSQL.Format( "INSERT INTO RemoteFiles VALUES('%s')", CStringA(strNewName) );
				sqlite3_exec( pDB, strSQL, NULL, NULL, NULL );
			}
		}

		if( pDB )
			sqlite3_close( pDB );

	}
	else
		Insert( strNewName );
}
