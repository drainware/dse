#include "StdAfx.h"
#include "IUserNotify.h"
#include "Crypt.h"
#include "DDI.h"
#include <winhttp.h>
//extern CCrypt g_crypt;

//CStringA g_strProxy;
//int g_nProxyPort = 0;

extern "C"
{

int amqp_ssl_socket_open_proxy( void *base, const char *host, int port, struct timeval *timeout, char const *szProxy, int bProxyEnable, int nProxyPort );
//amqp_socket_t * amqp_ssl_socket_new2( amqp_connection_state_t state );
//void ddi_get_proxy_info( const char **szProxy, int *nProxyPort )
//{
//	if( g_strProxy.GetLength() )
//	{
//		*szProxy = g_strProxy.GetBuffer();
//		*nProxyPort = g_nProxyPort;
//	}
//	LPWSTR pszURL;
//	if( WinHttpDetectAutoProxyConfigUrl( WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A, &pszURL ) )
//	{
//		//TODO:
//		GlobalFree(pszURL);
//	}
//}

}

#pragma comment(lib,"Crypt32.lib")

class CAutoRun
{
public:
	CAutoRun( volatile bool &bR ) : m_bR( bR )
	{
		//m_bR = true;
	}

	~CAutoRun()
	{
		m_bR = false;
	}

	volatile bool &m_bR;
};


static uint64_t now_microseconds(void)
{
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	return (((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime) / 10;
}

static void microsleep(int usec)
{
	Sleep(usec / 1000);
}

static bool IsAmqpError( amqp_rpc_reply_t xResult )
{
	//char szMsg[ 1024 ];
	switch( xResult.reply_type )
	{
	case AMQP_RESPONSE_NORMAL:
		return false;
	case AMQP_RESPONSE_NONE:
		//fprintf(stderr, "%s: missing RPC reply type!\n", context);
		return true;
	case AMQP_RESPONSE_LIBRARY_EXCEPTION:
		//sprintf( szMsg, "%s\n", amqp_error_string( xResult.library_error));
		return true;
	case AMQP_RESPONSE_SERVER_EXCEPTION:
		switch( xResult.reply.id )
		{
			case AMQP_CONNECTION_CLOSE_METHOD:
			{
			  amqp_connection_close_t *m = (amqp_connection_close_t *) xResult.reply.decoded;
			  //fprintf(stderr, "server connection error %d, message: %.*s\n",
				  //m->reply_code,
				  //(int) m->reply_text.len, (char *) m->reply_text.bytes);
			}
			break;
		}
		return true;
	case AMQP_CHANNEL_CLOSE_METHOD:
		//{
		//	amqp_channel_close_t *m = (amqp_channel_close_t *) x.reply.decoded;
		//	fprintf(stderr, "%s: server channel error %d, message: %.*s\n",
		//		context,
		//		m->reply_code,
		//		(int) m->reply_text.len, (char *) m->reply_text.bytes);
		//}
		return true;
	default:
		//fprintf(stderr, "%s: unknown server error, method id 0x%08X\n", context, x.reply.id);
		return true;
	}
  return false;
}

AMQP_PUBLIC_FUNCTION amqp_queue_bind_ok_t * AMQP_CALL amqp_queue_bind_dw(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_bytes_t exchange, amqp_bytes_t routing_key, amqp_table_t arguments)
{
  amqp_queue_bind_t req;
  req.ticket = 0;
  req.queue = queue;
  req.exchange = exchange;
  req.routing_key = routing_key;
  req.nowait = 1;
  req.arguments = arguments;

  return (amqp_queue_bind_ok_t *)amqp_simple_rpc_decoded( state, channel, AMQP_QUEUE_BIND_METHOD, AMQP_QUEUE_BIND_OK_METHOD, &req );
}

AMQP_PUBLIC_FUNCTION amqp_queue_bind_ok_t * AMQP_CALL amqp_queue_bind_sw(amqp_connection_state_t state, amqp_channel_t channel, amqp_bytes_t queue, amqp_bytes_t exchange, amqp_bytes_t routing_key, amqp_table_t arguments)
{
	//return amqp_queue_bind_dw( state, channel, queue, exchange, routing_key, arguments );
	return amqp_queue_bind( state, channel, queue, exchange, routing_key, arguments );
}

//Proxy helper functions

/*
** Translation Table as described in RFC1113
*/
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
** encodeblock
**
** encode 3 8-bit binary bytes as 4 '6-bit' characters
*/
static void encodeblock( unsigned char *in, unsigned char *out, int len )
{
	out[0] = (unsigned char) cb64[ (int)(in[0] >> 2) ];
	out[1] = (unsigned char) cb64[ (int)(((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)) ];
	out[2] = (unsigned char) (len > 1 ? cb64[ (int)(((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6)) ] : '=');
	out[3] = (unsigned char) (len > 2 ? cb64[ (int)(in[2] & 0x3f) ] : '=');
}

/*
** encode
**
** base64 encode a stream adding padding and line breaks as per spec.
*/
static int encode( unsigned char *instr, unsigned char *outstr )
{
	unsigned char in[3];
	int i, len, blocksout = 0;
	int retcode = 0;
	int in_ptr = 0, out_ptr = 0;

	*in = (unsigned char) 0;
	while( in_ptr < (int)strlen((char*)instr) ) {
		len = 0;
		for( i = 0; i < 3; i++ ) {
			in[i] = instr[in_ptr];

			if( in_ptr < (int)strlen((char*)instr) ) {
				len++;
				in_ptr++;
			}
			else {
				in[i] = (unsigned char) 0;
			}
		}
		if( len > 0 ) {
			encodeblock( in, &outstr[out_ptr], len );
			out_ptr += 4;
		}
	}
	return( out_ptr );
}

static bool GetProxyConf( const char *szHostName, CStringA &strProxy, int &nPort )
{
	char userpass[256], userpass_[256];

	memset(userpass, 0, 256);
	memset(userpass_, 0, 256);
	strcat_s( userpass, 256, "jpalanco" );
	strcat_s(userpass, 256, ":");
	strcat_s(userpass, 256, "decdec" );
	encode( (unsigned char *)userpass, (unsigned char *)userpass_ );

	strProxy.Empty();
	strProxy += "5.9.23.53";
	strProxy += ":CONNECT ";
	strProxy += szHostName;
	strProxy += ":";
	strProxy += "443";
	strProxy += " HTTP/1.1\r\n";
	strProxy += "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:22.0) Gecko/20100101 Firefox/22.0\r\n";
	strProxy += "Proxy-Connection: keep-alive\r\n";
	strProxy += "Connection: keep-alive\r\n";
	strProxy += "Host: ";
	strProxy += szHostName;
	strProxy += "\r\n";
	strProxy += "Proxy-Authorization: Basic ";
	strProxy += userpass_;
	strProxy += "\r\n\r\n";
	nPort = 3128;
	return true;
}


CDDI::CDDI() : m_bStop( false ), m_bClose( false ), m_bStopping( false ), m_bRunning( false ), /*m_nSocketFD( 0 ), */m_pDDINotify( NULL ),
	m_connRecv( NULL ), m_connSend( NULL ), m_bProxyEnable( 0 )
{
	m_evtStop.Create( NULL, FALSE, FALSE, NULL );
}

CDDI::~CDDI()
{
}

void CDDI::AddUser( const char *szUser, IUserNotify *pUserNotify )
{
	CAutoCS acs( m_cs );
	CStringA strUserNameEscape;
	DwEscapeUrl( szUser, strUserNameEscape );

	UserInfo &ui = m_mapUsers[ strUserNameEscape ];
	if( !ui.m_strName.GetLength() )
		ui.m_strName = strUserNameEscape;
	ui.m_pUserNotify = pUserNotify;
	//ui.m_aUserNotifies.Add( pUserNotify );
}

void CDDI::AddUserGroup( const char *szUser, const char *szGroup )
{
	CStringA strUserNameEscape;
	DwEscapeUrl( szUser, strUserNameEscape );
	UserInfo &ui = m_mapUsers[ strUserNameEscape ];
	ui.m_mapGroups[ szGroup ] = true;
	if( !m_mapGroups.Lookup( szGroup ) )
	{
		m_mapGroups[ szGroup ] = true;
		amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(szGroup), amqp_empty_table );	
	}
}

//void CDDI::AddProxy( const WCHAR *szProxy, LONG bEnable )
//{
//	CStringA str;
//	str = szProxy;
//	int nStartPos = 0;
//	int nFind = str.Find( _T(';'), nStartPos );
//
//	while( nFind != -1 )
//	{
//		CStringA &strNew = m_aProxy[ m_aProxy.Add() ];
//		strNew.SetString( str.GetBuffer() + nStartPos, nFind - nStartPos );
//		nStartPos = nFind + 1;
//		nFind = str.Find( _T(';'), nStartPos );
//	}
//
//	m_aProxy[ m_aProxy.Add() ].SetString( str.GetBuffer() + nStartPos );
//
//	m_bProxyEnable = int(bEnable);
//}

void CDDI::AddProxy( CAtlArray<CString> &aProxy, bool bEnable )
{
	m_aProxy.RemoveAll();
	for( size_t i = 0; i < aProxy.GetCount(); i++ )
	{
		CStringA &str = m_aProxy[ m_aProxy.Add() ];
		str = aProxy[ i ];
	}
	m_bProxyEnable = bEnable ? 1 : 0;
}

void CDDI::SetDDINotify( IDDINotify *pNotify )
{
	m_pDDINotify = pNotify;
}


static bool GetProxyInfo( CStringA &str, CStringA &strProxy, int &nPort )
{
	int nFind = str.Find( ':' );
	if( nFind == -1 )
		return false;
	strProxy.SetString( str, nFind );
	nPort = atoi( str.GetBuffer() + nFind + 1 );
	return true;
}

bool CDDI::ConnectSend()
{
	m_connSend = amqp_new_connection();
	//{SSL

	amqp_socket_t *pSockSend = amqp_ssl_socket_new( m_connSend );
	amqp_ssl_socket_set_cacert( pSockSend, "cacert.pem" );
	amqp_ssl_socket_set_key( pSockSend, "key.pem", "cert.pem" );
	amqp_ssl_socket_set_verify( pSockSend, 0 );
	
	//if( amqp_socket_open( pSockSend, m_strHost,  m_nPort ) < 0 )
	struct timeval tv;
	tv.tv_sec = 4;
	tv.tv_usec = 0;

	int nResult = -1;
	if( m_bProxyEnable && m_aProxy.GetCount() )
	{
		CStringA strProxy;
		int nPort = 0;
		for( size_t i = 0; i < m_aProxy.GetCount(); i++ )
		{
			if( GetProxyInfo( m_aProxy[ i ], strProxy, nPort ) )
				nResult = amqp_ssl_socket_open_proxy( pSockSend, m_strHost,  m_nPort, &tv, strProxy, 1, nPort );
		}
	}
	if( nResult < 0 ) //try without proxy
		nResult = amqp_ssl_socket_open_proxy( pSockSend, m_strHost,  m_nPort, &tv, NULL, 0, 0 );

	if( nResult < 0 )
	{
		//TODO: possible leak not destroying pSockSend, but destroying it crashes application
		amqp_destroy_connection( m_connSend );
		m_connSend = NULL;
		return false;
	}

	if( IsAmqpError( amqp_login( m_connSend, "/", 0, 131072, 60, AMQP_SASL_METHOD_PLAIN, m_strUser, m_strPassword ) ) )
	{
		CloseSend();
		return false;
	}

	amqp_channel_open( m_connSend, 1 );

	if( IsAmqpError( amqp_get_rpc_reply( m_connSend ) ) )
	{
		CloseSend();
		return false;
	}

	return true;
}

void CDDI::CloseSend()
{
	if( m_connSend )
	{
		amqp_channel_close( m_connSend, 1, AMQP_REPLY_SUCCESS );
		amqp_connection_close( m_connSend, AMQP_REPLY_SUCCESS );
		amqp_destroy_connection( m_connSend );
		m_connSend = NULL;
	}
}

bool CDDI::Connect( const char *szHostName, int nPort, const char *szUser, const char *szPassword )
{
	m_bStop = m_bStopping = false;
	//Client

	m_strHost = szHostName;
	m_nPort = nPort;
	m_strUser = szUser;
	m_strPassword = szPassword;

	//Server
	m_connRecv = amqp_new_connection();
	amqp_socket_t *pSock = amqp_ssl_socket_new( m_connRecv );
	amqp_ssl_socket_set_cacert( pSock, "cacert.pem" );
	amqp_ssl_socket_set_key( pSock, "key.pem", "cert.pem" );
	amqp_ssl_socket_set_verify( pSock, 0 );

	struct timeval tv;
	tv.tv_sec = 4;
	tv.tv_usec = 0;

	int nResult = -1;
	if( m_bProxyEnable && m_aProxy.GetCount() )
	{
		CStringA strProxy;
		int nPortProxy = 0;
		for( size_t i = 0; i < m_aProxy.GetCount(); i++ )
		{
			if( GetProxyInfo( m_aProxy[ i ], strProxy, nPortProxy ) )
				nResult = amqp_ssl_socket_open_proxy( pSock, szHostName,  nPort, &tv, strProxy, 1, nPortProxy );
		}
	}
	if( nResult < 0 ) //try without proxy
		nResult = amqp_ssl_socket_open_proxy( pSock, szHostName,  nPort, &tv, NULL, 0, 0 );

	if( nResult < 0 )
	//if( amqp_ssl_socket_open_proxy( pSock, szHostName,  nPort, &tv, g_strProxy, m_bProxyEnable, g_nProxyPort ) < 0 )
	{
		//TODO: possible leak not destroying pSock, but destroying it crashes application
		amqp_destroy_connection( m_connRecv );
		m_connRecv = NULL;
		return false;
	}

	if( IsAmqpError( amqp_login( m_connRecv, "/", 0, 131072, 60, AMQP_SASL_METHOD_PLAIN, szUser, szPassword ) ) )
	{
		Close();
		return false;
	}

	amqp_channel_open( m_connRecv, 1 );

	if( IsAmqpError( amqp_get_rpc_reply( m_connRecv ) ) )
	{
		Close();
		return false;
	}

	amqp_queue_declare_ok_t *r = amqp_queue_declare( m_connRecv, 1, amqp_cstring_bytes(m_strThisMachine.GetBuffer()), 0, 0, 0, 1, amqp_empty_table );
    if( IsAmqpError( amqp_get_rpc_reply( m_connRecv ) ) )
		return false;

    m_queueRecv = amqp_bytes_malloc_dup( r->queue );
    if( m_queueRecv.bytes == NULL )
      return false;


	
	amqp_basic_consume( m_connRecv, 1, m_queueRecv, amqp_empty_bytes, 0, 1, 0, amqp_empty_table );

	//Durable = true (1) //client durable
	//amqp_exchange_declare_ok_t_ *pResult = amqp_exchange_declare( m_conn, 1, amqp_cstring_bytes("client"), amqp_cstring_bytes("direct"), 0, 1, amqp_empty_table );
	amqp_exchange_declare_ok_t_ *pResult = amqp_exchange_declare( m_connRecv, 1, amqp_cstring_bytes("server"), amqp_cstring_bytes("direct"), 0, 0, amqp_empty_table );

	//Durable = false (0)
	//amqp_exchange_declare( m_conn, 1, amqp_cstring_bytes("direct_policies"), amqp_cstring_bytes("direct"), 0, 0, amqp_empty_table );

	//Suscribe to * channel
	amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes("*"), amqp_empty_table );

	//Suscribe to LICENSE channel
	if( m_strLicense.GetLength() )
		amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(m_strLicense), amqp_empty_table );

	//Suscribe to NOMBREDELEQUIPO_IP channel
	amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(m_strThisMachine), amqp_empty_table );

	//Suscribe to atp channel
	//amqp_queue_bind_sw( m_conn, 1, m_queue, amqp_cstring_bytes("direct_policies"), amqp_cstring_bytes("rpc_atp_queue"), amqp_empty_table );

	if( m_mapGroups.GetCount() )
	{
		POSITION pos = m_mapGroups.GetStartPosition();
		while( pos )
		{
			amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(m_mapGroups.GetAt( pos )->m_key), amqp_empty_table );
			m_mapGroups.GetNext( pos );
		}
	}

	if( IsAmqpError( amqp_get_rpc_reply( m_connRecv ) ) )
		return false;


	//Make socket asynch here?

	return true;
}

bool CDDI::Publish( const char *szUser, const char *szRoutingKey, CStringA &strMsg )
{
	if( m_bStop || !m_bRunning )
		return false;
	//return InternalPublish( szUser, szRoutingKey, strMsg );
	CAutoCS acs( m_csMsg );

	//MsgInfo &msg = m_aMsg[ m_aMsg.Add() ];
	//msg.strUser = szUser;
	//msg.strRoutingKey = szRoutingKey;
	//msg.strMsg = strMsg;
	return InternalPublish( szUser, szRoutingKey, strMsg );
	//return true;
}

bool CDDI::InternalPublish( const char *szUser/*, const char *szExchange*/, const char *szRoutingKey, CStringA &strMsg )
{
	if( m_bStop || !m_bRunning )
		return false;

	CStringA strUserNameEscape;
	DwEscapeUrl( szUser, strUserNameEscape );

	ConnectSend();
    amqp_basic_properties_t props;
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG | AMQP_BASIC_REPLY_TO_FLAG | AMQP_BASIC_CORRELATION_ID_FLAG;
    //props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG | AMQP_BASIC_REPLY_TO_FLAG | AMQP_BASIC_CORRELATION_ID_FLAG | AMQP_BASIC_USER_ID_FLAG;
    props.content_type = amqp_cstring_bytes("text/plain");
    props.delivery_mode = 2; /* persistent delivery mode */
    props.reply_to = amqp_bytes_malloc_dup(m_queueRecv);
    if (props.reply_to.bytes == NULL) {
      fprintf(stderr, "Out of memory while copying queue name");
	  CloseSend();
      return false;
    }
	//props.user_id = amqp_cstring_bytes(szUser);
    //props.correlation_id = amqp_cstring_bytes("1");
	props.correlation_id = amqp_cstring_bytes(strUserNameEscape);

    /*
      publish
    */

	//CStringA strEncrypted;
	//g_crypt.Encrypt( strMsg, strEncrypted );
	//if( !strEncrypted.GetLength() )
	//	strEncrypted = strMsg;
	amqp_bytes_t stMsg;
	stMsg.len = strMsg.GetLength();
	stMsg.bytes = strMsg.GetBuffer();
    int nError = amqp_basic_publish( m_connSend, 1, amqp_cstring_bytes("client"), amqp_cstring_bytes(szRoutingKey), 0, 0, &props, stMsg );
	//int nError = amqp_basic_publish( m_conn, 1, amqp_cstring_bytes(""), amqp_cstring_bytes(szRoutingKey), 0, 0, &props, stMsg );
    amqp_bytes_free(props.reply_to);
	CloseSend();
	return nError >= 0;
}

void CDDI::Close()
{
	CAutoCS acs(m_csStop);
	{
		CAutoCS acs( m_csMsg ); //ensure that we are not sending a message
		CloseSend();
	}
	if( m_connRecv )
	{
		amqp_channel_close( m_connRecv, 1, AMQP_REPLY_SUCCESS );
		amqp_connection_close( m_connRecv, AMQP_REPLY_SUCCESS );
		amqp_destroy_connection( m_connRecv );
		m_connRecv = NULL;
	}
}

#define SUMMARY_EVERY_US 1000000

int CDDI::WaitFrame( amqp_connection_state_t state, amqp_frame_t *decoded_frame )
{
	return amqp_simple_wait_frame( state, decoded_frame ); //AMQP_STATUS_TIMEOUT
	//if( !amqp_data_in_buffer( state ) && !amqp_frames_enqueued( state ) )
	//{
	//	u_long nRead = 0;
	//	ioctlsocket( amqp_socket_get_sockfd( m_sock ), FIONREAD, &nRead );

	//	while( !nRead && !m_bStop && !m_bRestart )
	//	{
	//		if( m_aMsg.GetCount() )
	//		{
	//			CAutoCS acs( m_csMsg );
	//			for( size_t i = 0; i < m_aMsg.GetCount(); i++ )
	//			{
	//				InternalPublish( m_aMsg[ i ].strUser, m_aMsg[ i ].strRoutingKey, m_aMsg[ i ].strMsg );
	//			}
	//			m_aMsg.RemoveAll();
	//		}
	//		Sleep( 100 );
	//		ioctlsocket( amqp_socket_get_sockfd( m_sock ), FIONREAD, &nRead );
	//	}
	//}

	//if( m_bStop || m_bRestart )
	//	return 0;
	//int nRet = amqp_simple_wait_frame( state, decoded_frame );
	//return nRet;
}

void CDDI::Run()
{
	//Sleep( 20000 );
	uint64_t start_time = now_microseconds();
	int received = 0;
	int previous_received = 0;
	uint64_t previous_report_time = start_time;
	uint64_t next_summary_time = start_time + SUMMARY_EVERY_US;

	amqp_frame_t frame;
	int result;
	size_t body_received;
	size_t body_target;

	uint64_t now;

	CStringA strMsg;
	CStringA strExchange;
	CStringA strRoutingKey;
	CStringA strUser;

	CAutoRun ar( m_bRunning );

	while( 1 )
	{
		if( m_bStop )
			return;
		strMsg.Empty();
		now = now_microseconds();
		if( now > next_summary_time )
		{
			int countOverInterval = received - previous_received;
			double intervalRate = countOverInterval / ((now - previous_report_time) / 1000000.0);
			//printf("%d ms: Received %d - %d since last report (%d Hz)\n",
			//	(int)(now - start_time) / 1000, received, countOverInterval, (int) intervalRate);

			previous_received = received;
			previous_report_time = now;
			next_summary_time += SUMMARY_EVERY_US;
		}

		amqp_maybe_release_buffers( m_connRecv );
		m_bRunning = true;
		result = WaitFrame( m_connRecv, &frame);
		if( result < 0 || m_bStop )
			return;

		if( frame.frame_type != AMQP_FRAME_METHOD )
			continue;

		if( frame.payload.method.id == AMQP_BASIC_CANCEL_OK_METHOD )
		{
			OnCancel();
			break;
		}

		if( frame.payload.method.id != AMQP_BASIC_DELIVER_METHOD )
			continue;

		amqp_basic_deliver_t *d = (amqp_basic_deliver_t *) frame.payload.method.decoded;
		strExchange.SetString( (char *) d->exchange.bytes, (int)d->exchange.len );
		strRoutingKey.SetString( (char *) d->routing_key.bytes, (int)d->routing_key.len );

		result = WaitFrame( m_connRecv, &frame );
		if (result < 0 || m_bStop )
			return;

		if (frame.frame_type != AMQP_FRAME_HEADER)
		{
			//fprintf(stderr, "Expected header!");
			return;
		}

		body_target = (size_t)frame.payload.properties.body_size;
		body_received = 0;

		while( body_received < body_target )
		{
			result = WaitFrame( m_connRecv, &frame );
			if( result < 0 || m_bStop )
				return;
			if( frame.frame_type != AMQP_FRAME_BODY )
			{
				fprintf(stderr, "Expected body!");
				return;
			}

			body_received += frame.payload.body_fragment.len;
			strMsg.Append( (const char *)frame.payload.body_fragment.bytes, int(frame.payload.body_fragment.len) );

			//assert(body_received <= body_target);
		}

		if( strMsg.GetLength() )
		{
			amqp_basic_properties_t *p = (amqp_basic_properties_t *) frame.payload.properties.decoded;
			if( p->_flags & AMQP_BASIC_CORRELATION_ID_FLAG )
				strUser.SetString( (char *)p->correlation_id.bytes, (int)p->correlation_id.len );
			else
				strUser.Empty();

			OnRececiveMsg( frame.channel, strUser, strExchange, strRoutingKey, strMsg );
		}

		received++;
	}
}

void CDDI::UnbindGroups()
{
	if( m_mapGroups.GetCount() )
	{
		POSITION pos = m_mapGroups.GetStartPosition();
		while( pos )
		{
			amqp_queue_unbind( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(m_mapGroups.GetAt( pos )->m_key), amqp_empty_table );
			amqp_get_rpc_reply( m_connRecv );
			m_mapGroups.GetNext( pos );
		}
	}
}

void CDDI::UnsubscribeAll()
{
	amqp_queue_unbind_ok_t *pResult = amqp_queue_unbind( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes("*"), amqp_empty_table ); 
	amqp_get_rpc_reply( m_connRecv );
	if( m_strLicense.GetLength() )
	{
		pResult = amqp_queue_unbind( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(m_strLicense), amqp_empty_table );
		amqp_get_rpc_reply( m_connRecv );
	}
	pResult = amqp_queue_unbind( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(m_strThisMachine), amqp_empty_table );
	amqp_get_rpc_reply( m_connRecv );
	UnbindGroups();

	amqp_queue_delete( m_connRecv, 1, amqp_cstring_bytes(m_strThisMachine.GetBuffer()), 0, 0 );
	amqp_get_rpc_reply( m_connRecv );
}

void CDDI::Stop( bool bClose )
{ 
	CAutoCS acs(m_csStop);
	m_bStopping = true;
	m_pDDINotify->OnDDIClose();
	WaitForSingleObject( m_evtStop, 14000 );
	m_bStop = true;
	m_bClose = bClose;
	//while( m_bRunning  && m_connRecv )
	//{
	//	//int nSocket = amqp_socket_get_sockfd( amqp_get_sockfd( m_connRecv ) );
	//	int nSocket = amqp_get_sockfd( m_connRecv );
	//	if( nSocket )
	//		::closesocket( nSocket );
	//	Sleep( 1 );
	//}
}

//Events

void CDDI::OnCancel()
{
}

//void CDDI::SubscribeGroup( const char *szGroup )
//{
//	CAutoCS acs( m_cs );
//	if( !m_mapGroups.Lookup( szGroup ) ) //suscribe to group channel
//	{
//		m_mapGroups[ szGroup ] = true;
//		amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(szGroup), amqp_empty_table );
//	}
//}

void CDDI::SubscribeUserToGroup( const char *szUser, const char *szGroup, IUserNotify *pUserNotify )
{
	CAutoCS acs( m_cs );


	CStringA strUserNameEscape;
	DwEscapeUrl( szUser, strUserNameEscape );

	UserInfo &ui = m_mapUsers[ strUserNameEscape ];
	ui.m_mapGroups[ szGroup ] = true;
	ui.m_pUserNotify = pUserNotify;
	if( !m_mapGroups.Lookup( szGroup ) )
	{
		m_mapGroups[ szGroup ] = true;
		amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(szGroup), amqp_empty_table );	
	}

	if( lstrcmpiA( "default", szGroup ) )
		UnsubscribeUserToGroup( strUserNameEscape, "default" );
}


void CDDI::UnsubscribeUser( const char *szUser )
{
	CAutoCS acs( m_cs );

	CStringA strUserNameEscape;
	DwEscapeUrl( szUser, strUserNameEscape );

	UserInfo &ui = m_mapUsers[ strUserNameEscape ];
	
	POSITION pos = ui.m_mapGroups.GetStartPosition();
	CStringA strGroup;
	while( pos )
	{
		strGroup = ui.m_mapGroups.GetAt(pos)->m_key;
		POSITION posOld = pos;
		ui.m_mapGroups.GetNext( pos );
		ui.m_mapGroups.RemoveAtPos( posOld );

		//Check if any one continues using group, else unbind it

		bool bInUse = false;
		POSITION posU = m_mapUsers.GetStartPosition();
		while( posU )
		{
			if( 
				m_mapUsers.GetAt( posU )->m_value.m_strName != ui.m_strName &&
				m_mapUsers.GetAt( posU )->m_value.m_mapGroups.Lookup( strGroup )
				)
			{
				bInUse = true;
				break;
			}

			m_mapUsers.GetNext( posU );
		}

		if( !bInUse )
		{
			amqp_queue_unbind( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(strGroup), amqp_empty_table );
			amqp_get_rpc_reply( m_connRecv );
			POSITION posG = m_mapGroups.Lookup( strGroup );
			if( posG )
				m_mapGroups.RemoveAtPos( posG );
		}
	}
}

void CDDI::UnsubscribeUserToGroup( const char *szUser, const char *szGroup )
{
	CAutoCS acs( m_cs );

	CStringA strUserNameEscape;
	DwEscapeUrl( szUser, strUserNameEscape );

	UserInfo &ui = m_mapUsers[ strUserNameEscape ];
	POSITION pos = ui.m_mapGroups.Lookup( szGroup );
	if( pos )
	{
		ui.m_mapGroups.RemoveAtPos( pos );

		//Check if any one continues using group, else unbind it

		bool bInUse = false;
		POSITION posU = m_mapUsers.GetStartPosition();
		while( posU )
		{
			if( m_mapUsers.GetAt( posU )->m_value.m_mapGroups.Lookup( szGroup ) )
			{
				bInUse = true;
				break;
			}

			m_mapUsers.GetNext( posU );
		}

		if( !bInUse )
		{
			amqp_queue_unbind( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(szGroup), amqp_empty_table );
			amqp_get_rpc_reply( m_connRecv );
			POSITION posG = m_mapGroups.Lookup( szGroup );
			if( posG )
				m_mapGroups.RemoveAtPos( posG );
		}
	}
}

void CDDI::OnRececiveMsg( int nChannel, const CStringA &strUser, const CStringA &strExchange, const CStringA &strRoutingKey, CStringA &strMsg )
{
	if( m_bStopping )
	{
		UnsubscribeAll();
		m_bStop = true;
		m_evtStop.Set();
		return;
	}
	CAutoCS acs( m_cs );
	if( strUser.GetLength() )
	{
		CAtlMap< CStringA, UserInfo >::CPair *pPair = m_mapUsers.Lookup( strUser );
		if( pPair )
		{
			UserInfo &ui = pPair->m_value;
			//CAtlArray< IUserNotify * > &un = pPair->m_value.m_aUserNotifies;
			//for( size_t i = 0; i < un.GetCount(); i++ )
			IUserNotify *pUserNotify = pPair->m_value.m_pUserNotify;
			if( pUserNotify )
			{
				pUserNotify->OnUserConfig( strMsg );
				const CAtlList< CStringA > &lstGroups = pUserNotify->Groups();
				POSITION pos = lstGroups.GetHeadPosition();
				while( pos )
				{
					const CStringA &strGroup = lstGroups.GetAt( pos );
					ui.m_mapGroups[ strGroup ] = true;
					if( !m_mapGroups.Lookup( strGroup ) ) //suscribe to group channel
					{
						m_mapGroups[ strGroup ] = true;
						amqp_queue_bind_sw( m_connRecv, 1, m_queueRecv, amqp_cstring_bytes("server"), amqp_cstring_bytes(strGroup), amqp_empty_table );
						if( lstrcmpiA( "default", strGroup ) )
							UnsubscribeUserToGroup( strUser, "default" );

					}
					lstGroups.GetNext( pos );
				}
			}
		}
	}
	else if( strRoutingKey == "*" || strRoutingKey == m_strLicense ) //Channel * message
	{
		if( m_pDDINotify )
			m_pDDINotify->OnDDICommand( strMsg );
	}
	else if( strRoutingKey == m_strThisMachine ) //Channel ESTEEQUIPO_IP message
	{
		if( m_pDDINotify )
			m_pDDINotify->OnDDICommand( strMsg );
	}
	//else if( strMsg.Find( "{\"atp\"") == 0 )
	//{
	//	if( m_pDDINotify )
	//		m_pDDINotify->OnAtpConfig( strMsg );
	//}
	else
	{
		POSITION pos = m_mapUsers.GetStartPosition();

		while( pos )
		{
			CAtlMap< CStringA, UserInfo >::CPair *pPair = m_mapUsers.GetAt( pos );

			if( pPair->m_value.m_mapGroups.Lookup( strRoutingKey ) )
			{
				IUserNotify *pUserNotify = pPair->m_value.m_pUserNotify;
				if( pUserNotify )
					pUserNotify->OnGroupChanged( strRoutingKey, strMsg );
			}

			m_mapUsers.GetNext( pos );
		}

	}
}
