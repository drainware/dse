#include "stdafx.h"
extern "C"
{
#define ZEND_WIN32
#define PHP_WIN32
#define ZTS 1
#define ZEND_DEBUG 0
#include <main\php.h>
#include <sapi\embed\php_embed.h>
}


static CEvent evtPHP;
static CEvent evtEndCommand;
static HANDLE hThreadPHP = NULL;
static bool bShutDown = false;
static DWORD dwResult = 0;
CCriticalSection csPHP;
CStringA strExcute;
CStringA strOutResult;

static int PhpWriteCallback( const char *str, uint str_length TSRMLS_DC )
{
	strOutResult.Append( str, str_length );
	return str_length;
}

static void PhpLogCallback( char *message TSRMLS_DC )
{
	CAtlFile f;
	f.Create( _T("C:\\drainware\\php.log"), GENERIC_WRITE, FILE_SHARE_READ, OPEN_ALWAYS );
	if( f )
	{
		f.Seek( 0, FILE_END );
		const char szSep[] = "\r\n------------------------------------------\r\n";
		f.Write( szSep, sizeof(szSep) );
		f.Write( message, lstrlenA( message ) );
	}
}

#define DW_PHP_NAME "Drainware PHP Execution"

DWORD WINAPI PhpThread( PVOID pVoid )
{
	zval ret_value;
	int exit_status;

	strOutResult.Empty();
	void ***tsrm_ls;
	//Sleep( 20000 );
	//InitPHP
	{
		php_embed_module.ub_write = PhpWriteCallback;
		php_embed_module.log_message = PhpLogCallback;
		php_embed_init( 0, NULL PTSRMLS_CC );
		char *szIncludeUnify = "include 'res:///PHP/unify_policies.php';";
		char *szIncludeAnalyze = "include 'res:///PHP/analyze_file.php';";

		CStringA strInclude;
		CString strAnalyze;
		GetModuleDirectory( strAnalyze );
		strAnalyze += _T("analyze_file.php");
		
		if( FileExist( strAnalyze ) ) {
			strInclude = "include '";
			strInclude += strAnalyze;
			strInclude += "';";
			strInclude.Replace( "\\", "\\\\" );
			szIncludeAnalyze = strInclude.GetBuffer();
		}


		zend_first_try
		{
			PG(during_request_startup) = 0;
			zend_eval_string( szIncludeUnify, &ret_value, DW_PHP_NAME TSRMLS_CC );
			zend_eval_string( szIncludeAnalyze, &ret_value, DW_PHP_NAME TSRMLS_CC );
			exit_status= Z_LVAL(ret_value);
			dwResult = exit_status;
		}
		zend_catch
		{
			exit_status = EG(exit_status);
			dwResult = exit_status;
		}
		zend_end_try();
	}

	while( true )
	{
		if( WaitForSingleObject( evtPHP, INFINITE ) != WAIT_OBJECT_0 )
			break;
		if( bShutDown )
			break;
		strOutResult.Empty();
		zend_first_try
		{
			PG(during_request_startup) = 0;
			zend_eval_string( strExcute.GetBuffer(), &ret_value, DW_PHP_NAME TSRMLS_CC );
			exit_status= Z_LVAL(ret_value);
			dwResult = exit_status;
		}
		zend_catch
		{
			exit_status = EG(exit_status);
			dwResult = exit_status;
			//php_embed_shutdown(TSRMLS_C);
			//php_embed_init( 0, NULL PTSRMLS_CC );
			//php_embed_module.ub_write = PhpWriteCallback;
		}
		zend_end_try();
		evtEndCommand.Set();
	}

	php_embed_shutdown(TSRMLS_C);

	return 0;
}

void InitPHP()
{
	evtPHP.Create( NULL, FALSE, FALSE, NULL );
	evtEndCommand.Create( NULL, FALSE, FALSE, NULL );
	hThreadPHP = ::CreateThread( NULL, 0, PhpThread, NULL, 0, NULL );
}

void ShutdownPHP()
{
	bShutDown = true;
	evtPHP.Set();
	WaitForSingleObject( hThreadPHP, INFINITE );
	evtPHP.Close();
	evtEndCommand.Close();
}

DWORD WINAPI PhpCheck( CStringA &strExecute, CStringA &strOutResult )
{
	zval ret_value;
	int exit_status;

	strOutResult.Empty();
	void ***tsrm_ls;
	//Sleep( 20000 );
	//InitPHP
	{
		php_embed_module.ub_write = PhpWriteCallback;
		php_embed_module.log_message = PhpLogCallback;
		php_embed_init( 0, NULL PTSRMLS_CC );
		char *szIncludeUnify = "include 'res:///PHP/unify_policies.php';";
		char *szIncludeAnalyze = "include 'res:///PHP/analyze_file.php';";

		CStringA strInclude;
		CString strAnalyze;
		GetModuleDirectory( strAnalyze );
		strAnalyze += _T("analyze_file.php");
		
		if( FileExist( strAnalyze ) ) {
			strInclude = "include '";
			strInclude += strAnalyze;
			strInclude += "';";
			strInclude.Replace( "\\", "\\\\" );
			szIncludeAnalyze = strInclude.GetBuffer();
		}


		zend_first_try
		{
			PG(during_request_startup) = 0;
			zend_eval_string( szIncludeUnify, &ret_value, DW_PHP_NAME TSRMLS_CC );
			zend_eval_string( szIncludeAnalyze, &ret_value, DW_PHP_NAME TSRMLS_CC );
			exit_status= Z_LVAL(ret_value);
			dwResult = exit_status;
		}
		zend_catch
		{
			exit_status = EG(exit_status);
			dwResult = exit_status;
		}
		zend_end_try();
	}

	while( true )
	{
		strOutResult.Empty();
		zend_first_try
		{
			PG(during_request_startup) = 0;
			zend_eval_string( strExcute.GetBuffer(), &ret_value, DW_PHP_NAME TSRMLS_CC );
			exit_status= Z_LVAL(ret_value);
			dwResult = exit_status;
		}
		zend_catch
		{
			exit_status = EG(exit_status);
			dwResult = exit_status;
			//php_embed_shutdown(TSRMLS_C);
			//php_embed_init( 0, NULL PTSRMLS_CC );
			//php_embed_module.ub_write = PhpWriteCallback;
		}
		zend_end_try();
		evtEndCommand.Set();
	}

	php_embed_shutdown(TSRMLS_C);

	return dwResult;
}

//DWORD ExecutePHP( CStringA &strPHP, CStringA &strResult )
//{
//	return PhpCheck( strPHP, strResult );
//}
DWORD ExecutePHP( CStringA &strPHP, CStringA &strResult )
{
	CAutoCS acs( csPHP );
	strExcute = strPHP;
	::OutputDebugStringA( "DwFilter: BEFORE execute PHP: "); ::OutputDebugStringA( strPHP ); ::OutputDebugStringA( "\n");
	evtPHP.Set();
	WaitForSingleObject( evtEndCommand, INFINITE );
	::OutputDebugStringA( "DwFilter: AFTER PHP: "); ::OutputDebugStringA( strPHP ); ::OutputDebugStringA( "\n");
	strResult = strOutResult;
	return dwResult;
}
