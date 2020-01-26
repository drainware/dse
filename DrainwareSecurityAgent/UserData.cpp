#include "stdafx.h"
#include "IUserNotify.h"
#include "UserData.h"
#include "..\..\DrainwareLibs\json-c\json.h"
#include "..\DwLib\DwLib.h"
#undef min
#include <re2/re2.h>
#include "DwService.h"
#include "ISecurityAgent.h"
#include <ws2tcpip.h>

//#include "Crypt.h"

//extern CCrypt g_crypt;

#define Max(a,b)            (((a) > (b)) ? (a) : (b))
#define Min(a,b)            (((a) < (b)) ? (a) : (b))


extern ISecurityAgent  *g_pSecurityAgent;
extern DWORD ExecutePHP( CStringA &strPHP, CStringA &strResult );

static const char *GetJsonString( json_object *pObject, const char *szName )
{
    json_object *pItem = json_object_object_get( pObject, szName );
    if( !pItem )
        return NULL;
    return json_object_get_string( pItem );
}

static void CreateTempJSON( CString &strFileName, CAtlFile &file )
{
	CString strTemp;
	GetTempPath( strTemp );
	strTemp += _T("dwJson_%d.json");
	int nTemp = 0;
	while( true )
	{
		//TODO:Use a temp directory
		strFileName.Format( strTemp, nTemp );
		if( !FileExist( strFileName ) && 
			S_OK == file.Create( strFileName, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS ) )
			break;
		++nTemp;
	}
}

inline bool IsSpace( char nChar )
{
	return nChar == ' ' || nChar == '\t' || nChar == '\n';
}

static void GetContext( const CStringA &strText, int nBegin, CStringA &strContext )
{
	strContext.Empty();
	if( nBegin >= strText.GetLength() )
		return;
	int nLength = strText.GetLength();
	int nLeftPos = nBegin;
	int nLeftEnd = Max( 0, nBegin - 160 ); //Max number of left characters
	int nLeftSpaces = 0;
	while( nLeftPos > nLeftEnd )
	{
		if( IsSpace( strText[ nLeftPos-- ] ) )
			++nLeftSpaces;
		if( nLeftSpaces >= 20 )
			break;
	}

	int nRightPos = nBegin;
	int nRightEnd = Min( nLength, nBegin + 160 );//Max number of right characters
	int nRightSpaces = 0;
	while( nRightPos < nRightEnd )
	{
		if( IsSpace( strText[ nRightPos++ ] ) )
			++nRightSpaces;
		if( nRightSpaces >= 20 )
			break;
	}

	strContext.SetString( ((const char *)strText) + nLeftPos, nRightPos - nLeftPos );
}

bool CUserData::CheckText( const CStringA &strText, TEXT_TYPE nTextType, const CStringA &strApp, CStringA &strJSONEvent, VARIANT_BOOL &bScreenShot, VARIANT_BOOL &bShowMsg, VARIANT_BOOL &bBlock )
{
	if( !strText.GetLength() )
		return false;

	CAutoCS acs(m_cs);

	bool bRet = false;
	bool bActionBlock = false;
	int nSeverity = SC_NONE;
	UINT nActionLevel = TYPE_LEVEL_INFO;

    json_object *pRoot = json_object_new_object();
    json_object *pResults = json_object_new_array();
    json_object *pResults2 = json_object_new_object();
    json_object *pCoincidences = json_object_new_array();

	POSITION pos = m_lstConcepts.GetHeadPosition();
	CStringA strContext;

	while( pos )
	{
		UserConcept &uc = m_lstConcepts.GetAt( pos );

		if( uc.m_strSubConcept.GetLength() )
		{
			re2::StringPiece strPiece( strText, strText.GetLength() );

			RE2 pattern( uc.m_strSubConcept.GetBuffer() );
			re2::StringPiece spMatch;

			json_object *pMatches = json_object_new_array();
			json_object *pContexts = json_object_new_array();
			int nMatches = 0;
			while( pattern.Match( strPiece, 0, strPiece.size(), RE2::UNANCHORED, &spMatch, 1 ) )
			{
				int nBegin = 0;
				if( !uc.m_strVerify.GetLength() || VerifyMatch( uc.m_strID, uc.m_strVerify, spMatch.as_string().c_str()  ) )
				{
					++nMatches;
					bRet = true;
					//json_object_array_add( pMatches, json_object_new_string( spMatch.as_string().c_str() ) );
					nBegin = int(spMatch.end() - strPiece.begin());
					GetContext( strText, nBegin, strContext );
					json_object *pEl = json_object_new_object();
					json_object_object_add( pEl, "match", json_object_new_string( spMatch.as_string().c_str() ) );
					json_object_object_add( pEl, "context", json_object_new_string( strContext ) );
					json_object_array_add( pMatches, pEl );
				}
				if( !nBegin )
					break;
				strPiece.set( strPiece.begin() + nBegin, strPiece.size() - nBegin );
			}
			if( nMatches )
			{
				json_object *pCoincidence = json_object_new_object();
				//json_object_object_add( pCoincidence, "Action", json_object_new_string( m_strAction ) );
				json_object_object_add( pCoincidence, "Action", json_object_new_string( uc.m_strAction ) );
				if( uc.m_strAction == "block" )
					bActionBlock = true;
				UINT nAction = LevelFromAction( uc.m_strAction );
				if( nAction > nActionLevel )
					nActionLevel = nAction;
				json_object_object_add( pCoincidence, "Matches", pMatches );
				json_object_object_add( pCoincidence, "Type", json_object_new_string( "subconcept" ) );
				json_object_object_add( pCoincidence, "Id", json_object_new_string( uc.m_strID ) );
				//json_object_object_add( pCoincidence, "Severity", json_object_new_string( m_strSeverity ) );
				json_object_object_add( pCoincidence, "Severity", json_object_new_string( uc.m_strSeverity ) );
				nSeverity = max( nSeverity, LevelFromSeverity( uc.m_strSeverity ) );

				json_object *pPolicies = json_object_new_array();

				POSITION posPol = uc.m_lstPolicies.GetHeadPosition();
				while( posPol )
				{
					json_object_array_add( pPolicies, json_object_new_string( uc.m_lstPolicies.GetAt( posPol ) ) );
					uc.m_lstPolicies.GetNext( posPol );
				}
				json_object_object_add( pCoincidence, "Policies", pPolicies );
				json_object_array_add( pCoincidences, pCoincidence );
			}
		}
		m_lstConcepts.GetNext( pos );
	}

	pos = m_lstRules.GetHeadPosition();
	while( pos )
	{
		UserRule &ur = m_lstRules.GetAt( pos );

		if( ur.m_strRule.GetLength() )
		{
			re2::StringPiece strPiece( strText, strText.GetLength() );
			RE2 pattern( ur.m_strRule.GetBuffer() );
			re2::StringPiece spMatch;

			json_object *pMatches = json_object_new_array();
			int nMatches = 0;
			while( pattern.Match( strPiece, 0, strPiece.size(), RE2::UNANCHORED, &spMatch, 1 ) )
			{
				int nBegin = 0;
				if( !ur.m_strVerify.GetLength() || VerifyMatch( ur.m_strID, ur.m_strVerify, spMatch.as_string().c_str()  ) ) //Comment for not verify
				{

					++nMatches;
					bRet = true;
					//json_object_array_add( pMatches, json_object_new_string( spMatch.as_string().c_str() ) );
					int nBegin = int(spMatch.end() - strPiece.begin());
					GetContext( strText, nBegin, strContext );
					json_object *pEl = json_object_new_object();
					json_object_object_add( pEl, "match", json_object_new_string( spMatch.as_string().c_str() ) );
					json_object_object_add( pEl, "context", json_object_new_string( strContext ) );
					json_object_array_add( pMatches, pEl );
				}
				if( !nBegin ) break;//Comment for not verify
				strPiece.set( strPiece.begin() + nBegin, strPiece.size() - nBegin );
			}

			if( nMatches )
			{
				json_object *pCoincidence = json_object_new_object();
				//json_object_object_add( pCoincidence, "Action", json_object_new_string( m_strAction ) );
				json_object_object_add( pCoincidence, "Action", json_object_new_string( ur.m_strAction ) );
				if( ur.m_strAction == "block" )
					bActionBlock = true;

				UINT nAction = LevelFromAction( ur.m_strAction );
				if( nAction > nActionLevel )
					nActionLevel = nAction;

				json_object_object_add( pCoincidence, "Matches", pMatches );
				json_object_object_add( pCoincidence, "Type", json_object_new_string( "rule" ) );
				json_object_object_add( pCoincidence, "Id", json_object_new_string( ur.m_strID ) );
				//json_object_object_add( pCoincidence, "Severity", json_object_new_string( m_strSeverity ) );
				json_object_object_add( pCoincidence, "Severity", json_object_new_string( ur.m_strSeverity ) );
				nSeverity = max( nSeverity, LevelFromSeverity( ur.m_strSeverity ) );
                
				json_object *pPolicies = json_object_new_array();
                
				POSITION posPol = ur.m_lstPolicies.GetHeadPosition();
				while( posPol )
				{
					json_object_array_add( pPolicies, json_object_new_string( ur.m_lstPolicies.GetAt( posPol ) ) );
					ur.m_lstPolicies.GetNext( posPol );
				}
				json_object_object_add( pCoincidence, "Policies", pPolicies );
				json_object_array_add( pCoincidences, pCoincidence );
			}
		}
		m_lstRules.GetNext( pos );
	}

	if( !bRet )
	{
		json_object_put( pRoot );
		return false;
	}

    json_object_object_add( pResults2, "Coincidences", pCoincidences );

	static const char *aSources[] = { "clipboard text", "keylogger", "clipboard image", "printer" };
	int nSource = 0;
	if( nTextType & TYPE_KEYLOGGER )
		nSource = 1;
	else if( nTextType & TYPE_OCR )
		nSource = 2;
	else if( nTextType & TYPE_PRINTER )
		nSource = 3;
    json_object_object_add( pRoot, "Source", json_object_new_string( aSources[ nSource ] ) );


	if( strApp.GetLength() )
	{
		json_object *oApp = json_tokener_parse( strApp );
		json_object_object_add( pRoot, "Application", oApp );
	}

	
	//if( strApp.GetLength() )
 //       json_object_object_add( pResults2, "Application", json_object_new_string(strApp) );
 //   else
 //       json_object_object_add( pResults2, "Application", json_object_new_string("NoApp") );



    json_object_array_add( pResults, pResults2 );
    json_object_object_add( pRoot, "Results", pResults );

    strJSONEvent = json_object_to_json_string( pRoot );
	json_object_put( pRoot );

	if( bRet /*&& m_strAction != "log"*/ )
		bShowMsg = VARIANT_TRUE;

	if( bRet && m_nSCLevel != SC_NONE && nSeverity >= m_nSCLevel )
		bScreenShot = VARIANT_TRUE;

	//{
	//	CAtlFile f;
	//	f.Create( _T("C:\\Drainware\\event_json.txt"), GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
	//	f.Write( strJSON.c_str(), strJSON.size() );
	//}

	//if( bRet && m_strAction == "block" )

	SetActionFromLevel( nActionLevel );

	if( bRet && bActionBlock )
		bBlock = VARIANT_TRUE;

	return bRet;
}


/********************************************************
 *	0 : screenshot=0 remove_file=0 report_to_ddi=0		*
 *	1 : screenshot=0 remove_file=0 report_to_ddi=1		*
 *	2 : screenshot=1 remove_file=0 report_to_ddi=1		*
 *	3 : screenshot=0 remove_file=1 report_to_ddi=1		*
 *	4 : screenshot=1 remove_file=1 report_to_ddi=1		*
 ********************************************************/
bool CUserData::CheckFile( FILE_TYPE nFileType, const CString &strFilePath, CStringA &strJSONEvent, VARIANT_BOOL &bBlock, bool &bScreenShot, const char *szApp )
{

	if( !m_strJSON.GetLength() )
	{
		bBlock = VARIANT_FALSE;
		return false;
	}

	CString strCmd;
	//if( false ) //TODO: Cristian test
	{
		CAtlFile f;
		strCmd = strFilePath;
		strCmd += _T(":dwa.dat");
		strCmd.Insert( strCmd.GetLength() - 4, m_strUserName );

		if( S_OK == f.Create( strCmd, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
		{
			CStringA strContent;
			ULONGLONG nSize = 0;
			if( S_OK == f.GetSize( nSize ) && nSize && S_OK == f.Read( strContent.GetBufferSetLength( int(nSize) ), DWORD(nSize) ) )
			{
				//if( g_crypt.Decrypt( strEncContent, strContent ) )
				if( UncompressXOR( strContent ) )
				{
					SYSTEMTIME st;
					CopyMemory( &st, strContent.GetBuffer(), sizeof(SYSTEMTIME) );
					FILETIME ft1, ft2;
					SystemTimeToFileTime( &st, &ft1 );
					GetSystemTime( &st );
					SystemTimeToFileTime( &st, &ft2 );
					ULARGE_INTEGER ul1, ul2;
					ul1.LowPart = ft1.dwLowDateTime;
					ul1.HighPart = ft1.dwHighDateTime;
					ul2.LowPart = ft2.dwLowDateTime;
					ul2.HighPart = ft2.dwHighDateTime;


					bool bChanged = false;
					{
						CAtlFile fTime;
						if( fTime.Create( strFilePath, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING ) == S_OK )
						{
							FILETIME ftLastWrite;
							GetFileTime( fTime, NULL, NULL, &ftLastWrite );
							ULARGE_INTEGER ulLastWrite;
							ulLastWrite.LowPart = ftLastWrite.dwLowDateTime;
							ulLastWrite.HighPart = ftLastWrite.dwHighDateTime;
							bChanged = ulLastWrite.QuadPart > ul1.QuadPart + 10000 * 2000; //two second window ( last write can be ads )
#ifdef _DEBUG
							SYSTEMTIME stADS, stFile;
							FileTimeToSystemTime( &ftLastWrite, &stFile );
							FileTimeToSystemTime( &ft1, &stADS );
							int n = 0;
							n = 1;
#endif
						}
					}

					if( !m_ulLastUpdate.QuadPart || ( m_ulLastUpdate.QuadPart < ul1.QuadPart && !bChanged ) )// && ( ( ul2.QuadPart - ul1.QuadPart ) / 10000L ) < 1000 * 60 * 5 ) ) //Less than 5 minutes
					{
						DWORD nPos = sizeof( SYSTEMTIME );
						DWORD dwResult;
						if( nPos + sizeof( DWORD ) <= DWORD(strContent.GetLength()) )
						{
							CopyMemory( &dwResult, strContent.GetBuffer() + nPos, sizeof( DWORD ) );
							nPos += sizeof(DWORD);
							if(  nPos + sizeof( DWORD ) <= DWORD(strContent.GetLength()) )
							{
								DWORD dwSize = 0;
								CopyMemory( &dwSize, strContent.GetBuffer() + nPos, sizeof( DWORD ) );
								nPos += sizeof( DWORD );
								if( dwSize && nPos + dwSize <= DWORD(strContent.GetLength()) )
								{
									CopyMemory( strJSONEvent.GetBufferSetLength( dwSize ), strContent.GetBuffer() + nPos, dwSize );
									bBlock = ( dwResult == 3 || dwResult == 4 ) ? VARIANT_TRUE : VARIANT_FALSE;
									bScreenShot = ( dwResult == 2 || dwResult == 4 );
									SetActionFromJson( strJSONEvent );
									ChangeSourceApp( strJSONEvent, nFileType, szApp );
									//CString strDbg;
									//strDbg.Format( _T("DwFilter: ADS File %s CHECKED BY ADS\n"), strFilePath );
									//::OutputDebugString( strDbg );
									return dwResult ? true : false;
								}
								else
									strJSONEvent.Empty();
							}
						}
					}
				}
			}
		}
		strCmd.Empty();
	}


	//CString strDir;
	//GetModuleDirectory( strDir );
	//strDir += _T("analyzefile\\");

	//CString strPythonCmd = strDir;
	//strPythonCmd += "bin\\python2.6.exe";
	//CString strPythonFile = strDir;
	//strPythonFile += "analyze_file.py";
	////json_object_put( pOut );
	//////json_object_put( pFiles );

	//strCmd += "\"";
	//strCmd += strPythonCmd;
	//strCmd += "\" \"";
	//strCmd += strPythonFile;
	//strCmd += "\" \"--analyze\" \"";

	//CStringA strFileName;
	//strFileName = strFilePath;
	//strCmd += strFileName;
	//strCmd += "\" \"";

	//CString strJSONFile;
	//{
	//	CAtlFile f;
	//	CreateTempJSON( strJSONFile, f );
	//	f.Write( m_strJSON.GetBuffer(), m_strJSON.GetLength() );
	//}

	//strCmd += strJSONFile;

	//strCmd += "\"";

	//DWORD dwResult = ExecuteCommand( strCmd, strJSONEvent );

	CStringA strPHP = "analyzeFile( '";
	strPHP += strFilePath;
	strPHP += _T("', '");
	strPHP += m_strJSON;
	strPHP += _T("', '");
	strPHP += GetFileType( nFileType );
	if( szApp )
	{
		strPHP += _T("', '");
		strPHP += szApp;
	}
	strPHP += _T("' );");
	strPHP.Replace( "\\", "\\\\" );
	DWORD dwResult = ExecutePHP( strPHP, strJSONEvent );

	bBlock = ( dwResult == 3 || dwResult == 4 ) ? VARIANT_TRUE : VARIANT_FALSE;
	bScreenShot = ( dwResult == 2 || dwResult == 4 );
	//DeleteFile( strJSONFile );

	CAtlFile fLog;
	fLog.Create( _T("C:\\drainware\\analyze.log"), GENERIC_WRITE, FILE_SHARE_READ, OPEN_ALWAYS );
	if( fLog )
	{
		CStringA strWrite = "-------------------------------------------------------\r\n";
		strPHP = strFilePath;
		fLog.Seek( 0, SEEK_END );
		fLog.Write( strWrite.GetBuffer(), strWrite.GetLength() );

		strWrite.Format( "Analyzing: %s\r\nResult: %d, Block = %d, ScreenShot = %d\r\n", strPHP.GetBuffer(), dwResult, bBlock ? 1 : 0, bScreenShot ? 1 : 0 );
		strWrite.Append( strJSONEvent );
		fLog.Write( strWrite.GetBuffer(), strWrite.GetLength() );
	}

	//Save Data to an associated stream
	strCmd = strFilePath;
	strCmd += _T(":dwa.dat");
	strCmd.Insert( strCmd.GetLength() - 4, m_strUserName );

	if( strJSONEvent.GetLength() )
	{
		CAtlFile f;
		if( f.Create( strCmd, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS ) == S_OK )
		{
			CStringA strContent;
			strContent.GetBufferSetLength( sizeof(SYSTEMTIME) + sizeof(DWORD) * 3 + strJSONEvent.GetLength() );
			DWORD nPos = 0;
			SYSTEMTIME st;
			GetSystemTime( &st );
			CopyMemory( strContent.GetBuffer(), &st, sizeof(SYSTEMTIME) ); nPos += sizeof(SYSTEMTIME);
			CopyMemory( strContent.GetBuffer() + nPos, &dwResult, sizeof(DWORD) ); nPos += sizeof(DWORD);
			DWORD dwSize = strJSONEvent.GetLength();
			CopyMemory( strContent.GetBuffer() + nPos, &dwSize, sizeof(DWORD) ); nPos += sizeof(DWORD);
			CopyMemory( strContent.GetBuffer() + nPos, strJSONEvent.GetBuffer(), dwSize );
			CompressXOR( strContent );
			f.Write( strContent.GetBuffer(), strContent.GetLength() );
		}
	}
	SetActionFromJson( strJSONEvent );

	strCmd.Format( _T("DwFilter: ANALYZE_FILE File %s CHECKED BY ANALYZE_FILE.PY\n"), strFilePath );
	::OutputDebugString( strCmd );


	return dwResult ? true : false;
}

bool CUserData::CheckRemoteUnit( const CString &strFilePath, CStringA &strJSONEvent, VARIANT_BOOL &bBlock, bool &bScreenShot, const char *szApp )
{
	CString strUpper = strFilePath;
	strUpper.MakeUpper();
	CString strURI;

	POSITION pos = m_lstNetPlaces.GetHeadPosition();
	while( pos )
	{
		NetworkPlace &np = m_lstNetPlaces.GetAt( pos );
		strURI = np.m_strURI;
		strURI.MakeUpper();
		if( strUpper.Find( strURI ) != -1 )
		{
			CAutoCS acs(m_cs);

			//bool bRet = false;
			int nSeverity = SC_NONE;
			json_object *pRoot = json_object_new_object();
			json_object *pResults = json_object_new_array();
			json_object *pResults2 = json_object_new_object();
			json_object *pCoincidences = json_object_new_array();

				CStringA strSource( strFilePath );
				json_object *pCoincidence = json_object_new_object();
				//json_object_object_add( pCoincidence, "Action", json_object_new_string( m_strAction ) );
				json_object_object_add( pCoincidence, "Action", json_object_new_string( np.m_strAction ) );
				json_object_object_add( pCoincidence, "Matches", json_object_new_string(strSource) );
				json_object_object_add( pCoincidence, "Type", json_object_new_string( "network_place" ) );
				json_object_object_add( pCoincidence, "Id", json_object_new_string( np.m_strID ) );
				//json_object_object_add( pCoincidence, "Severity", json_object_new_string( m_strSeverity ) );
				json_object_object_add( pCoincidence, "Severity", json_object_new_string( np.m_strSeverity ) );

				nSeverity = max( nSeverity, LevelFromSeverity( np.m_strSeverity ) );

				json_object *pPolicies = json_object_new_array();

				POSITION posPol = np.m_lstPolicies.GetHeadPosition();
				while( posPol )
				{
					json_object_array_add( pPolicies, json_object_new_string( np.m_lstPolicies.GetAt( posPol ) ) );
					np.m_lstPolicies.GetNext( posPol );
				}
				json_object_object_add( pCoincidence, "Policies", pPolicies );
				json_object_array_add( pCoincidences, pCoincidence );

			json_object_object_add( pResults2, "Coincidences", pCoincidences );
			CStringA strFilePathA; 
			int nFind = strFilePath.ReverseFind( _T('\\' ) );
			if( nFind == -1 )
				strFilePathA = strFilePath;
			else
				strFilePathA = strFilePath.Right( strFilePath.GetLength() - nFind - 1 );

			json_object_object_add( pResults2, "Filename", json_object_new_string( strFilePathA ) );
    
			json_object_array_add( pResults, pResults2 );
			json_object_object_add( pRoot, "Source", json_object_new_string( "network device src" ) );

			if( szApp )
			{
				json_object *oApp = json_tokener_parse( szApp );
				json_object_object_add( pRoot, "Application", oApp );
			}


			json_object_object_add( pRoot, "Results", pResults );

			strJSONEvent = json_object_to_json_string( pRoot );
			json_object_put( pRoot );

			if( /*bRet &&*/ m_nSCLevel != SC_NONE && nSeverity >= m_nSCLevel )
				bScreenShot = true;
			
			SetActionFromJson( strJSONEvent );

			if( /*bRet &&*/ m_strAction == "block" )
				bBlock = VARIANT_TRUE;
			return true;
		}
		m_lstNetPlaces.GetNext( pos );
	}
	return false;
}

bool CUserData::IsRemoteUnit( const WCHAR *szFilePath, CString &strRemoteUnit )
{
	CString strUpper = szFilePath;
	strUpper.MakeUpper();
	CString strURI;

	POSITION pos = m_lstNetPlaces.GetHeadPosition();
	while( pos )
	{
		NetworkPlace &np = m_lstNetPlaces.GetAt( pos );
		strURI = np.m_strURI;
		strURI.MakeUpper();
		if( strURI.GetLength() && strUpper.Find( strURI ) != -1 )
		{
			strRemoteUnit = np.m_strURI;
			return true;
		}
		m_lstNetPlaces.GetNext( pos );
	}

	return false;
}

bool CUserData::FindApp( const CString &strApp )
{
	POSITION pos = m_lstApps.GetHeadPosition();
	while( pos )
	{
		if( !m_lstApps.GetAt( pos ).m_strApp.CompareNoCase( strApp ) )
		{
			//::OutputDebugString( _T("DwFilter: Found application to check\n") );
			return true;
		}
		m_lstApps.GetNext( pos );
	}
	return false;
}

void CUserData::SkipFile( LPCTSTR szFile )
{
	CAutoCS acs(m_csSkip);
	m_mapSkipFiles[ szFile ] = GetTickCount();
}

void CUserData::FileToDelete( LPCTSTR szFile )
{
	CAutoCS acs(m_csSkip);
	m_mapDeleteFiles[ szFile ] = GetTickCount();
}

bool CUserData::IsSkipedFile( LPCTSTR szFile )
{
	//TODO: Files skiped should be deleted from map after a time
	CAutoCS acs(m_csSkip);
	CAtlMap< CString, DWORD >::CPair *pPair = m_mapSkipFiles.Lookup( szFile );
	if( pPair )
	{
		if( GetTickCount() - pPair->m_value > 10000 ) //10 seconds
			return false;
		//m_mapSkipFiles.RemoveKey( szFile );
		return true;
	}
	return false;
}

bool CUserData::IsDeletedFile( LPCTSTR szFile )
{
	CAutoCS acs(m_csSkip);
	if( m_mapDeleteFiles.Lookup( szFile ) )
	{
		m_mapDeleteFiles.RemoveKey( szFile );
		return true;
	}
	return false;
}

bool CUserData::IsMimeTypeOfProc( const CString &strProc, const CString &strFileName )
{
	POSITION pos = m_lstApps.GetHeadPosition();
	while( pos )
	{
		if( !m_lstApps.GetAt( pos ).m_strApp.CompareNoCase( strProc ) )
		{
			return true;
			//if( strFileName.Find( _T(".txt") ) )
			//	return true;
			//else
			//	return false;
		}
		m_lstApps.GetNext( pos );
	}
	return false;
}

void CUserData::ClearScreenShot()
{
	CAutoCS acs(m_csSC);
	m_strScreenShot.Empty();
}

void CUserData::SetScreenShot( BYTE *pImage, DWORD cb )
{
	CAutoCS acs(m_csSC);
	m_strScreenShot.Empty();
	char *pBuffer = m_strScreenShot.GetBufferSetLength( cb );
	CopyMemory( pBuffer, pImage, cb );
}


int CUserData::LevelFromSeverity( const CStringA &strSeverity )
{
	if( strSeverity == "high" || strSeverity == "High" )
		return SC_HIGH;
	if( strSeverity == "medium" || strSeverity == "Medium" )
		return SC_MEDIUM;
	if( strSeverity == "low" || strSeverity == "Low" )
		return SC_LOW;
	return SC_NONE;
}

void CUserData::OnUserConfig( const CStringA &strJSON )
{
	RemoveGroups();
	CString strUserPath;
	GetModuleDirectory( strUserPath );

	strUserPath += _T("users");
	CreateDirectory( strUserPath, NULL );

	DWORD dwAttr = GetFileAttributes( strUserPath );

	if( ( dwAttr & ( FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM ) ) != ( FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM ) )
		SetFileAttributes( strUserPath, dwAttr | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM );

	strUserPath += _T("\\");
	strUserPath += m_strUserName;

	CreateDirectory( strUserPath, NULL );

	json_object *oJson = json_tokener_parse( strJSON );
	json_object *oArgs = json_object_object_get( oJson, "args" );
	m_lstGroups.RemoveAll();

	//CAtlFile f;
	//f.Create( _T("C:\\drainware\\UserConfig.txt"), GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
	//f.Write( strJSON.GetBuffer(), strJSON.GetLength() );

	if( json_object_get_type( oArgs ) == json_type_array )
	{
		CString strGroup;
		CStringA strContent;
        int nLen = json_object_array_length( oArgs );
        for( int i = 0; i < nLen; i++ )
		{

			json_object *pGroup = json_object_array_get_idx( oArgs, i );
			json_object *pGroupsUser = json_object_object_get( pGroup, "groups_user" );
			strContent = json_object_to_json_string( pGroup );

			if( json_object_get_type( pGroupsUser ) == json_type_array )
			{
				int nLen = json_object_array_length( pGroupsUser );
				for( int i = 0; i < nLen; i++ )
				{
					json_object *pName = json_object_array_get_idx( pGroupsUser, i );
					strGroup = strUserPath;
					strGroup += _T('\\');
					const char *szGroup = json_object_get_string( pName );
					strGroup += szGroup;
					m_lstGroups.AddTail( szGroup );
					CAutoCS acs( m_csFile );
					CAtlFile f;
					f.Create( strGroup, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
					f.Write( strContent.GetBuffer(), strContent.GetLength() );
				}
			}
			else
			{
				strGroup = strUserPath;
				strGroup += _T('\\');
				const char *szGroup = json_object_get_string( pGroupsUser );
				strGroup += szGroup;
				m_lstGroups.AddTail( szGroup );
				CAutoCS acs( m_csFile );
				CAtlFile f;
				f.Create( strGroup, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
				f.Write( strContent.GetBuffer(), strContent.GetLength() );
			}
		}
	}

	json_object_put( oJson );

	LoadConfig();
}

void CUserData::OnGroupChanged( const CStringA &strGroup, const CStringA &strJSON )
{

	json_object *oJson = json_tokener_parse( strJSON );
	if( oJson )
	{
		json_object *oCommand = json_object_object_get( oJson, "command" );
		if( oCommand )
		{
			json_object *oArgs = json_object_object_get( oJson, "args" );
			json_object *oID = json_object_object_get( oJson, "id" );
			const char *szID = oID ? json_object_get_string( oID ) : NULL;
			CStringA strCmd = json_object_get_string( oCommand );
				
			if( strCmd == "delete" )
			{
				json_object *pGroup = json_object_object_get( oArgs, "group" );
				const char *szGroup = json_object_get_string( pGroup );
				json_object *pUser = json_object_object_get( oArgs, "user" );
				if( json_object_get_type( pUser ) == json_type_array )
				{
					int nLen = json_object_array_length( pUser );
					CString strUser;
					for( int i = 0; i < nLen; i++ )
					{
						json_object *pExt = json_object_array_get_idx( pUser, i );
						strUser = json_object_get_string( pExt );
						DwUnEscapeUrl( strUser );
						if( m_strUserName == strUser )
							DeleteGroup( szGroup );
					}
				}
				else
				{
					const char *szUser  = json_object_get_string( pUser );
					CString strUser;
					strUser = szUser;
					DwUnEscapeUrl( strUser );
					if( szUser && m_strUserName == szUser )
						DeleteGroup( szGroup );
				}
				json_object_put( oJson );
				return;
			}
		}
	}


	CString strGroupFile;
	GetModuleDirectory( strGroupFile );

	strGroupFile += _T("users");
	CreateDirectory( strGroupFile, NULL );

	strGroupFile += _T("\\");
	strGroupFile += m_strUserName;

	CreateDirectory( strGroupFile, NULL );

	strGroupFile += _T('\\');

	//if( strGroup != "default" )
	//{
	//	CString strDefault = strGroupFile;
	//	strDefault += _T("default");
	//	DeleteFile( strDefault );
	//}

	strGroupFile += strGroup;
	CAutoCS acs( m_csFile );
	CAtlFile f;
	f.Create( strGroupFile, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );


	//oJson = json_tokener_parse( strJSON );
	json_object *oArgs = json_object_object_get( oJson, "args" );
	CStringA strContent = json_object_to_json_string( oArgs );
	json_object_put( oJson );
	//CStringA strContent = strJSON;
	f.Write( strContent.GetBuffer(), strContent.GetLength() );
	if( !m_hThread )
	{
		m_hThread = CreateThread( NULL, 0, ThreadLoadConfig, reinterpret_cast<PVOID>(this), 0, NULL );
		CloseHandle( m_hThread );
	}
}

DWORD WINAPI CUserData::ThreadLoadConfig( PVOID pVoid )
{
	CUserData *pThis = reinterpret_cast<CUserData*>(pVoid);
	Sleep( 5000 ); //Wait 5 seconds and join
	pThis->LoadConfig();
	pThis->m_hThread = NULL;
	return 0;
}

//Old call to the python unify inside of LoadConfig
	//{
	//	CAutoCS acs(m_csFile);
	//	CString strDir;
	//	GetModuleDirectory( strDir );
	//	CString strUserPath = strDir;
	//	strDir += _T("analyzefile\\");
	//	strUserPath += _T("users\\");
	//	strUserPath += m_strUserName;

	//	CString strPythonCmd = strDir;
	//	strPythonCmd += "bin\\python2.6.exe";

	//	CString strCmd;

	//	strCmd += _T("\"");
	//	strCmd += strDir;
	//	strCmd += _T("bin\\python2.6.exe");
	//	strCmd += _T("\" \"");
	//	strCmd += strDir;
	//	strCmd += _T("unify_policies.py");
	//	strCmd += _T("\" \"");
	//	strCmd += strUserPath;
	//	strCmd += _T("\"");

	//	ExecuteCommand( strCmd, strJSON );
	//}


static bool ConvertToIP_Name( CStringA &strSrv )
{
	if( strSrv[ 0 ] == '\\' && strSrv[ 1 ] == '\\' )
	{
		int nFind = strSrv.Find( '\\', 2 );
		if( nFind != -1 )
		{
			CStringA strS = strSrv.Mid( 2, nFind - 2 );

			unsigned long nAddr = inet_addr( strS );
			if( nAddr != INADDR_NONE )
			{
				struct sockaddr_in saServer;
				saServer.sin_family = AF_INET;
				saServer.sin_addr.s_addr = nAddr;
				saServer.sin_port = 0;//htons(5150);
				char szName[ 256 ];
				if( !getnameinfo( (SOCKADDR *)&saServer, sizeof(sockaddr_in), szName, 256, NULL, 0,  0 ) )
				{
					strSrv.Delete( 2, nFind - 2 );
					strSrv.Insert( 2, szName );
					return true;
				}
				else
				{
					DWORD dwError = WSAGetLastError();
					struct hostent *remoteHost = gethostbyaddr( (const char *)&saServer, 4, AF_INET );
					if( !remoteHost )
						remoteHost = gethostbyaddr( (const char *)&saServer, 4, AF_NETBIOS );
					if( remoteHost )
					{
						CStringA strName = *remoteHost->h_aliases;
						strSrv.Delete( 2, nFind - 2 );
						strSrv.Insert( 2, strName );
					}
					
				}
			}
			else
			{
				struct hostent *pHost = gethostbyname( strS );
				if( !pHost )
					return false;
				if( pHost->h_addrtype == AF_INET && pHost->h_addr_list[ 0 ] )
				{
					struct in_addr addr;
					CopyMemory( &addr, pHost->h_addr_list[ 0 ], sizeof(struct in_addr) );
					strSrv.Delete( 2, nFind - 2 );
					strSrv.Insert( 2, inet_ntoa( addr ) );
					return true;
				}
			}
		}
	}
	return false;
}

void CUserData::LoadConfig()
{
	CStringA strJSON;

	CString strUserPath;
	GetModuleDirectory( strUserPath );
	strUserPath += _T("users\\");
	strUserPath += m_strUserName;

	strUserPath.Insert( 0, _T("unify( '") );
	strUserPath.Append( _T("' );") );
	strUserPath.Replace( _T("\\"), _T("\\\\" ) );
	ExecutePHP( CStringA(strUserPath), strJSON );

	if( !strJSON.GetLength() )
		return;

	{
		CAtlFile f;
		if( S_OK == f.Create( _T("C:\\Drainware\\json.txt"), GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS ) )
			f.Write( ( const char *)strJSON, strJSON.GetLength() );
	}

	//RemoveGroups();

	CAutoCS acs(m_cs);
	
	m_lstConcepts.RemoveAll();
	m_lstRules.RemoveAll();
	m_lstNetPlaces.RemoveAll();
	m_strAction.Empty();
	m_strSeverity.Empty();
	m_nSCLevel = SC_NONE;
	ULONG nOldActiveModules = m_nActiveModules;
	m_nActiveModules = 0;

	m_strJSON = strJSON;
	json_object *oJson = json_tokener_parse( strJSON );

	//json_object *oItem = json_object_object_get( oJson, "action" );
	//if( oItem )
	//	m_strAction = json_object_get_string( oItem );

	//oItem = json_object_object_get( oJson, "severity" );
	//if( oItem )
	//	m_strSeverity = json_object_get_string( oItem );

	json_object *oItem = json_object_object_get( oJson, "screenshot_severity" );
	if( oItem )
		m_nSCLevel = LevelFromSeverity( json_object_get_string( oItem ) );

	oItem = json_object_object_get( oJson, "endpoint_modules" );
	if( oItem && json_object_get_type( oItem ) == json_type_array )
	{
		static ULONG aModuleFlags[] = { PROTECT_PRINTER, PROTECT_CLIPBOARD_IMG, PROTECT_GOOGLEDRIVE, PROTECT_DROPBOX, PROTECT_SKYDRIVE, PROTECT_PENDRIVE, PROTECT_NETWORKDEVICE_SRC, PROTECT_NETWORKDEVICE_DST, PROTECT_CLIPBOARD_TXT, PROTECT_KEYLOGGER };
		static const char*aModuleNames[] = { "printer", "clipboard image", "google drive", "dropbox", "skydrive", "pendrive", "network device src", "network device dst", "clipboard text", "keylogger" };
		static int nItems = sizeof(aModuleFlags) / sizeof(ULONG);

        int nLen = json_object_array_length( oItem );
        for( int i = 0; i < nLen; i++ )
        {
            json_object *oModule = json_object_array_get_idx( oItem, i );
            if( oModule )
			{
				const char *pszName = json_object_get_string( oModule );
				for( int j = 0; j < nItems; j++ )
				{
					if( !lstrcmpA( pszName, aModuleNames[ j ] ) )
						m_nActiveModules |= aModuleFlags[ j ];
				}
			}
		}
		//for( int i = 0; i < nItems; i++ )
		//{
		//	json_object *oModule = json_object_object_get( oItem, aModuleNames[ i ] );
		//	if( oModule )
		//		m_nActiveModules |= aModuleFlags[ i ];
		//}
	}


    json_object *pSubConcepts = json_object_object_get( oJson, "subconcepts" );
    if( pSubConcepts && json_object_get_type( pSubConcepts ) == json_type_array )
    {
        int nLen = json_object_array_length( pSubConcepts );
        for( int i = 0; i < nLen; i++ )
        {
            json_object *pSubConcept = json_object_array_get_idx( pSubConcepts, i );
            if( pSubConcept )
            {
				UserConcept &uc = m_lstConcepts.GetAt( m_lstConcepts.AddTail() );
                uc.m_strID = GetJsonString( pSubConcept, "id" );
                uc.m_strSubConcept = GetJsonString( pSubConcept, "subconcept" );
                uc.m_strDescription = GetJsonString( pSubConcept, "description" );
				uc.m_strAction = GetJsonString( pSubConcept, "action" );
				uc.m_strSeverity = GetJsonString( pSubConcept, "severity" );

                const char *pszVerify = GetJsonString( pSubConcept, "verify" );
                if( pszVerify && strcmp( pszVerify, "null" ) )
                    uc.m_strVerify = DwBase64Decode( pszVerify, lstrlenA(pszVerify) );

                json_object *pPolicies = json_object_object_get( pSubConcept, "policies_id" );
                if( pPolicies && json_object_get_type( pPolicies ) == json_type_array )
                {
                    int nPolicies = json_object_array_length( pPolicies );
                    for( int j = 0; j < nPolicies; j++ )
                    {
                        json_object *pPolicy = json_object_array_get_idx( pPolicies, j );
                        if( pPolicy )
                        {
                            const char *pszPolicy = json_object_get_string( pPolicy );
                            if( pPolicy )
								uc.m_lstPolicies.AddTail( pszPolicy );
                        }
                    }
                }
            }
        }
    }

    json_object *pRules = json_object_object_get( oJson, "rules" );
    if( pRules && json_object_get_type( pRules ) == json_type_array )
    {
        int nLen = json_object_array_length( pRules );
        for( int i = 0; i < nLen; i++ )
        {
            json_object *pRule = json_object_array_get_idx( pRules, i );
            if( pRule )
            {
				UserRule &ur = m_lstRules.GetAt( m_lstRules.AddTail() );
                ur.m_strID = GetJsonString( pRule, "id" );
                ur.m_strRule = GetJsonString( pRule, "rule" );
                ur.m_strDescription = GetJsonString( pRule, "description" );
				ur.m_strAction = GetJsonString( pRule, "action" );
				ur.m_strSeverity = GetJsonString( pRule, "severity" );

                const char *pszVerify = GetJsonString( pRule, "verify" );
                if( pszVerify && strcmp( pszVerify, "null" ) )
                    ur.m_strVerify = DwBase64Decode( pszVerify, lstrlenA(pszVerify) );


                json_object *pPolicies = json_object_object_get( pRule, "policies_id" );
                if( pPolicies && json_object_get_type( pPolicies ) == json_type_array )
                {
                    int nPolicies = json_object_array_length( pPolicies );
                    for( int j = 0; j < nPolicies; j++ )
                    {
                        json_object *pPolicy = json_object_array_get_idx( pPolicies, j );
                        if( pPolicy )
                        {
                            const char *pszPolicy = json_object_get_string( pPolicy );
                            if( pPolicy )
                                ur.m_lstPolicies.AddTail( pszPolicy );
                        }
                    }
                }
            }
        }
    }


    json_object *pNetworkPlaces = json_object_object_get( oJson, "network_places" );
    if( pNetworkPlaces && json_object_get_type( pNetworkPlaces ) == json_type_array )
    {
        int nLen = json_object_array_length( pNetworkPlaces );
        for( int i = 0; i < nLen; i++ )
        {
            json_object *pPlace = json_object_array_get_idx( pNetworkPlaces, i );
            if( pPlace )
            {

				NetworkPlace &np = m_lstNetPlaces.GetAt( m_lstNetPlaces.AddTail() );
                np.m_strID = GetJsonString( pPlace, "id" );
                np.m_strURI = GetJsonString( pPlace, "network_uri" );
                np.m_strDescription = GetJsonString( pPlace, "description" );
				np.m_strAction = GetJsonString( pPlace, "action" );
				np.m_strSeverity = GetJsonString( pPlace, "severity" );
                
                json_object *pPolicies = json_object_object_get( pPlace, "policies_id" );
                if( pPolicies && json_object_get_type( pPolicies ) == json_type_array )
                {
                    int nPolicies = json_object_array_length( pPolicies );
                    for( int j = 0; j < nPolicies; j++ )
                    {
                        json_object *pPolicy = json_object_array_get_idx( pPolicies, j );
                        if( pPolicy )
                        {
                            const char *pszPolicy = json_object_get_string( pPolicy );
                            if( pPolicy )
								np.m_lstPolicies.AddTail( pszPolicy );
                        }
                    }
                }

				//Add ip copy
				CStringA strSrv = np.m_strURI;
				if( ConvertToIP_Name( strSrv ) )
				{
					NetworkPlace &np2 = m_lstNetPlaces.GetAt( m_lstNetPlaces.AddTail() );
					np2 = np;
					np2.m_strURI = strSrv;
				}

			}
		}
	}

    json_object *pApplications = json_object_object_get( oJson, "applications" );
    if( pApplications && json_object_get_type( pApplications ) == json_type_array )
    {
        int nLen = json_object_array_length( pApplications );
        for( int i = 0; i < nLen; i++ )
        {
            json_object *pApp = json_object_array_get_idx( pApplications, i );
            if( pApp )
            {
				UserApplication &ua = m_lstApps.GetAt( m_lstApps.AddTail() );
                ua.m_strID = GetJsonString( pApp, "id" );
                ua.m_strApp = GetJsonString( pApp, "application" );
                ua.m_strDescription = GetJsonString( pApp, "description" );

                json_object *pPolicies = json_object_object_get( pApp, "policies_id" );
                if( pPolicies && json_object_get_type( pPolicies ) == json_type_array )
                {
                    int nPolicies = json_object_array_length( pPolicies );
                    for( int j = 0; j < nPolicies; j++ )
                    {
                        json_object *pPolicy = json_object_array_get_idx( pPolicies, j );
                        if( pPolicy )
                        {
                            const char *pszPolicy = json_object_get_string( pPolicy );
                            if( pPolicy )
                                ua.m_lstPolicies.AddTail( pszPolicy );
                        }
                    }
                }
            }
        }
    }

    json_object *pGdriveDomains = json_object_object_get( oJson, "gdrive_domain_exceptions" );
    if( pGdriveDomains && json_object_get_type( pGdriveDomains ) == json_type_array )
	{
        int nDomains = json_object_array_length( pGdriveDomains );
        for( int j = 0; j < nDomains; j++ )
        {
            json_object *pDomain = json_object_array_get_idx( pGdriveDomains, j );
            if( pDomain )
            {
                const char *pszPolicy = json_object_get_string( pDomain );
                if( pDomain )
                    m_lstGdriveDomains.AddTail( pszPolicy );
            }
        }
	}

	json_object_put( oJson );
	g_pSecurityAgent->EnablePrinter( m_nActiveModules & PROTECT_PRINTER );
	//g_pSecurityAgent->EnablePrinter( TRUE );
	g_pSecurityAgent->Fire_ActiveModules( m_strUserName, m_nActiveModules );



	CRegKey rKeyUsers;
	CString strKey = _T("SOFTWARE\\Drainware\\SecurityEndpoint\\Users");
	if( !GetRegKey( strKey, rKeyUsers ) )
		return;
	CRegKey rKeyUser;
	strKey += _T("\\");
	strKey += m_strUserName;
	if( !GetRegKey( strKey, rKeyUser ) )
		return;

	bool bNewJSON = true;
	
	strKey += _T("\\");
	ULONG nSize = 0;
	LONG nRet = rKeyUser.QueryBinaryValue( _T("CurrentPolicies"), NULL, &nSize );
	SYSTEMTIME st;
	
	if( nRet != ERROR_FILE_NOT_FOUND )
	{
		CStringA strOld;
		if( ERROR_SUCCESS == rKeyUser.QueryBinaryValue( _T("CurrentPolicies"), strOld.GetBufferSetLength( nSize ), &nSize ) )
		{
			nSize = sizeof(SYSTEMTIME);
			if( strOld == strJSON && ERROR_SUCCESS == rKeyUser.QueryBinaryValue( _T("TimeStamp"), &st, &nSize ) )
			{
				bNewJSON = false;
			}
		}
	}

	if( bNewJSON )
	{
		GetSystemTime( &st );
		rKeyUser.SetBinaryValue( _T("CurrentPolicies"), strJSON.GetBuffer(), strJSON.GetLength() );
		rKeyUser.SetBinaryValue( _T("TimeStamp"), &st, sizeof(SYSTEMTIME) );
	}

	FILETIME ft;
	SystemTimeToFileTime( &st, &ft );
	m_ulLastUpdate.LowPart = ft.dwLowDateTime;
	m_ulLastUpdate.HighPart = ft.dwHighDateTime;
}

void CUserData::AddGroup( const char *szGroup )
{
	m_lstGroups.AddTail( szGroup );
	//if( szGroup && lstrcmpA( szGroup, "default" ) )
	//{
	//	CString strUserDir;
	//	GetModuleDirectory( strUserDir );
	//	strUserDir += _T("users\\");
	//	strUserDir += m_strUserName;
	//	strUserDir += _T("\\default");
	//	DeleteFile( strUserDir );
	//}
}

void CUserData::DeleteGroup( const char *szGroup )
{
	CString strUserDir;
	GetModuleDirectory( strUserDir );
	strUserDir += _T("users\\");
	strUserDir += m_strUserName;
	strUserDir += _T('\\');
	strUserDir += szGroup;

	POSITION pos = m_lstGroups.Find( szGroup );
	if( pos )
		m_lstGroups.RemoveAt( pos );

	if( m_pDDI )
	{
		CStringA strUserA;
		strUserA = m_strUserName;
		m_pDDI->UnsubscribeUserToGroup( strUserA, szGroup );
	}


	if( FileExist( strUserDir ) )
	{
		DeleteFile( strUserDir );
		LoadConfig();
	}
}

void CUserData::RemoveGroups()
{
	CString strUserDir;
	GetModuleDirectory( strUserDir );
	strUserDir += _T("users\\");
	strUserDir += m_strUserName;
	strUserDir += _T("\\*");
	WIN32_FIND_DATA fd = { 0 };
	HANDLE hFind = FindFirstFile( strUserDir, &fd );
	strUserDir.TrimRight( _T('*') );
	if( hFind != INVALID_HANDLE_VALUE )
	{
		CString strFile;
		int nFile = 0;
		while( true )
		{
			strFile = strUserDir;
			strFile += fd.cFileName;
			if( ++nFile > 2 )
				DeleteFile( strFile );
			if( !FindNextFile( hFind, &fd ) )
				break;
		}
		FindClose( hFind );
	}
}

static void NormalizeBuffer( const char *szBuffer, char *szBuffer2, DWORD dwRead )
{
	for( DWORD i = 0; i < dwRead; i++ )
	{
		if( *szBuffer )
			*szBuffer2++ = *szBuffer;
		++szBuffer;
	}
}

DWORD CUserData::ExecuteCommand( CString &strCmd, CStringA &strResult )
{
	SECURITY_ATTRIBUTES saAttr; 
	ZeroMemory( &saAttr, sizeof(SECURITY_ATTRIBUTES) );
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 

	HANDLE hPipeRead = NULL;
	HANDLE hPipeWrite = NULL;

	CreatePipe(  &hPipeRead, &hPipeWrite, &saAttr, 0 );
	
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	si.cb = sizeof( STARTUPINFO );
	si.hStdInput = hPipeRead;
	si.hStdOutput = hPipeWrite; //GetStdHandle( STD_OUTPUT_HANDLE );
	si.hStdError = hPipeWrite;//GetStdHandle( STD_ERROR_HANDLE );
	si.dwFlags = STARTF_USESTDHANDLES;
	_wputenv( L"CYGWIN=nodosfilewarning" );
	//_putenv( "nodosfilewarning=0" );
	if( !CreateProcess( NULL, strCmd.GetBuffer(), NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi ) )
	{
		DWORD dwError = GetLastError();
		dwError = 0;
		CloseHandle( hPipeRead ); CloseHandle( hPipeWrite );
		return 0;
	}

	const int nBufferSize = 4096;
	CHAR szBuffer[ nBufferSize + 1 ];

	DWORD dwRead = 0;
	CStringA strOutput;
	
	CloseHandle( hPipeWrite );

	while( PeekNamedPipe( hPipeRead, NULL, 0, NULL, &dwRead, NULL ) && !dwRead )
		::Sleep( 1 );

	if( dwRead > nBufferSize )
		dwRead = nBufferSize;
	//while( ReadFile( hPipeRead, szBuffer, dwRead, &dwRead, NULL ) )
	while( ReadFile( hPipeRead, szBuffer, nBufferSize, &dwRead, NULL ) )
	{
		if( !dwRead )
			break;
		szBuffer[ dwRead ] = 0;
		CHAR szBuffer2[ nBufferSize  + 1 ] = { 0 };
		NormalizeBuffer( szBuffer, szBuffer2, dwRead );
		strOutput += szBuffer2;
		dwRead = nBufferSize;
	}
	DWORD dwError = GetLastError();

	CloseHandle( hPipeRead );
	//CloseHandle( hPipeWrite );
	WaitForSingleObject( pi.hProcess, INFINITE );
	DWORD dwExitCode = 0;
	GetExitCodeProcess( pi.hProcess, &dwExitCode );
	CloseHandle( pi.hProcess );
	CloseHandle( pi.hThread );

	int nFind = strOutput.Find( '{' );
	if( nFind != -1 )
		strResult = strOutput.GetBuffer() + nFind;
	else // Python error
	{
		CAtlFile f;
		f.Create( _T("C:\\Drainware\\PythonError.txt"), GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
		if( f )
			f.Write( strOutput.GetBuffer(), strOutput.GetLength() );
	}
	//else
	//{
	//	MessageBoxA( GetActiveWindow(), strOutput, "No JSON returned by python", MB_ICONWARNING );
	//}
	return dwExitCode;
}

DWORD CUserData::VerifyMatch( CStringA &strID, CStringA &strCode, const CStringA &strMatch )
{
	CStringA strMatch64 = DwBase64Encode( strMatch, strMatch.GetLength() );
	CStringA strCode64 = DwBase64Encode( strCode, strCode.GetLength() );
	CStringA strResult;
	//"verify_id"
	
	CStringA strPHP = "VerifyMatch( '";
	strPHP += strCode64; strPHP += "', '";
	strPHP += strMatch64; strPHP += "' );";
	return ExecutePHP( strPHP, strResult );
}

//DWORD CUserData::VerifyMatch( CStringA &strCode, const CStringA &strMatch )
//{
//	CString strDir;
//	GetModuleDirectory( strDir );
//	strDir += _T("analyzefile\\");
//
//	CString strPythonCmd = strDir;
//	strPythonCmd += "bin\\python2.6.exe";
//
//	CString strTempDir;
//	GetTempPath( strTempDir );
//
//	TCHAR szTempFileName[ MAX_PATH ];
//	GetTempFileName( strTempDir, _T("DWS"), 0, szTempFileName );
//
//	CAtlFile f;
//	f.Create( szTempFileName, GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS );
//	f.Write( strCode.GetBuffer(), strCode.GetLength() );
//	f.Close();
//
//	CString strCmd;
//
//	strCmd += _T("\"");
//	strCmd += strPythonCmd;
//	strCmd += _T("\" \"");
//	strCmd += szTempFileName;
//	strCmd += _T("\" \"");
//
//	CStringA strMatch64 = DwBase64Encode( strMatch, strMatch.GetLength() );
//	strCmd += strMatch64;
//
//	CStringA strResult;
//	DWORD dwRet = ExecuteCommand( strCmd, strResult );
//	DeleteFile( szTempFileName );
//	return dwRet;
//}

UINT CUserData::ActionLevel()
{
	return LevelFromAction( m_strAction );
}

UINT CUserData::LevelFromAction( CStringA &strAction )
{
	if( strAction == "block" )
		return TYPE_LEVEL_ERROR;
	if( strAction == "alert" )
		return TYPE_LEVEL_WARNING;
	return TYPE_LEVEL_INFO;
}


void CUserData::SetActionFromLevel( UINT nAction )
{
	if( nAction == TYPE_LEVEL_ERROR )
		m_strAction = "block";
	else
		if( nAction == TYPE_LEVEL_WARNING )
			m_strAction = "alert";
		else
			m_strAction = "log";
}

void CUserData::SetActionFromJson( const CStringA &strJson )
{
	if( strJson.Find( "\"Action\":\"block\"" ) != -1 || strJson.Find( "\"Action\": \"block\"" ) != -1 )
		m_strAction = "block";
	else
	if( strJson.Find( "\"Action\":\"alert\"" ) != -1 || strJson.Find( "\"Action\": \"alert\"" ) != -1 )
		m_strAction = "alert";
	else
		m_strAction = "log";
}

const char *CUserData::GetFileType( FILE_TYPE nType )
{
	switch( nType )
	{
	case TYPE_NETWORK_DEVICE:
		return "network device dst";
	case TYPE_PENDRIVE:
		return "pendrive";
	case TYPE_SKY_DRIVE:
		return "skydrive";
	case TYPE_DROPBOX:
		return "dropbox";
	case TYPE_GOOGLE_DRIVE:
		return "google drive";
	case TYPE_APPLICATION_FILTER:
		return "application filter";
	}
	return "";
}

void CUserData::ChangeSourceApp( CStringA &strJSONEvent, FILE_TYPE nFileType, const char *szApp )
{
	int nFind = strJSONEvent.Find( "Source" );
	if( nFind != -1 )
	{
		//"S":"App",
		int nFirstQuote = strJSONEvent.Find( _T('\"'), nFind + 7 );
		int nLastQuote = strJSONEvent.Find( _T('\"'), nFirstQuote + 1 );
		if( nLastQuote - nFirstQuote > 1 )
			strJSONEvent.Delete( nFirstQuote + 1, nLastQuote - nFirstQuote - 1 );
		strJSONEvent.Insert( nFirstQuote + 1, GetFileType( nFileType ) );
	}
	nFind = strJSONEvent.Find( "Application" );
	if( nFind != -1 && szApp )
	{
		//"S":"App",
		if( szApp[ 0 ] != '{' )
		{
			int nFirstQuote = strJSONEvent.Find( _T('\"'), nFind + 12 );
			int nLastQuote = strJSONEvent.Find( _T('\"'), nFirstQuote + 1 );
			if( nLastQuote - nFirstQuote > 1 )
				strJSONEvent.Delete( nFirstQuote + 1, nLastQuote - nFirstQuote - 1 );
			if( szApp )
				strJSONEvent.Insert( nFirstQuote + 1, szApp );
		}
		else
		{
			int nFirstQuote = strJSONEvent.Find( _T('{'), nFind + 12 );
			int nLastQuote = strJSONEvent.Find( _T('}'), nFirstQuote + 1 );
			if( nLastQuote - nFirstQuote > 1 )
				strJSONEvent.Delete( nFirstQuote, nLastQuote - nFirstQuote + 1 );
			if( szApp )
				strJSONEvent.Insert( nFirstQuote, szApp );
		}
	}
}


bool CUserData::GetRemoteFileName( CString &strFile, CString &strRemoteName )
{
	CAtlFile f;
	CString strFileOrg = strFile;
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
						CopyMemory( strRemoteName.GetBufferSetLength( nFileOrgSize / sizeof(TCHAR) ), strContent.GetBuffer() + nPos, nFileOrgSize );
						return true;
					}
				}
			}
		}
	}
	return false;
}