#pragma once

class CFileFollower
{
public:
	CFileFollower();
	inline void Stop() throw() { m_bClose = true; }
	inline bool Closed() const throw() { return m_bClose; }
	void Insert( const CString &strFile );
	void Rename( const CString &strOldName, const CString &strNewName );
private:
	void ReloadDB( sqlite3 *pDB );
	void InsertDirectory( const CString &strDir, CStringA &strSQL, sqlite3 *pDB );
	void InsertFile( const CString &strFile, CStringA &strSQL, sqlite3 *pDB );
	static int SQLiteCallback( void *pUserData, int argc, char **argv, char **azColName );
	volatile bool m_bClose;
	CAtlMap< CString, bool > m_map;
	CStringA m_strDB;
	CCriticalSection m_csMap;
};
