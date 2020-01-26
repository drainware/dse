#ifndef __cplusplus
# define inline __inline
#endif

#include <amqp_ssl_socket.h>
#include <amqp_socket.h>
#include <amqp_private.h>
//#include <threads.h>

#include <ctype.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>

struct amqp_ssl_socket_t {
  const struct amqp_socket_class_t *klass;
  SSL_CTX *ctx;
  int sockfd;
  SSL *ssl;
  char *buffer;
  size_t length;
  amqp_boolean_t verify;
  int internal_error;
};

int amqp_ssl_socket_open2( void *base, const char *host, int port, struct timeval *timeout);
amqp_socket_open_fn old_open = NULL;
static struct amqp_socket_class_t amqp_ssl_socket_class2 = { 0 };

typedef struct amqp_socket_class_t * DW_ASC;

amqp_socket_t * amqp_ssl_socket_new2( amqp_connection_state_t state )
{
	amqp_socket_t *pSocket = amqp_ssl_socket_new( state );
	if( !old_open )
	{
		struct amqp_socket_class_t *pKlass = (struct amqp_socket_class_t*)pSocket;
		old_open = pSocket->klass->open;
		pKlass->open = amqp_ssl_socket_open2;
		//memcpy( &amqp_ssl_socket_class2, pSocket->klass, sizeof(amqp_ssl_socket_class2) );
		//amqp_ssl_socket_class2.open = amqp_ssl_socket_open2;
	}
	//pSocket->klass = &amqp_ssl_socket_class2;
	return pSocket;
}

struct amqp_hook_socket_t {
  struct amqp_socket_class_t *klass;
  SSL_CTX *ctx;
  int sockfd;
  SSL *ssl;
  char *buffer;
  size_t length;
  amqp_boolean_t verify;
  int internal_error;
};

void amqp_hook_socket_open( amqp_socket_t *pSocket )
{
	struct amqp_hook_socket_t *pS = (struct amqp_hook_socket_t*)pSocket;
	pS->klass->open = amqp_ssl_socket_open2;
}


static int
amqp_ssl_socket_verify_hostname(void *base, const char *host)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  unsigned char *utf8_value = NULL, *cp, ch;
  int pos, utf8_length, status = 0;
  ASN1_STRING *entry_string;
  X509_NAME_ENTRY *entry;
  X509_NAME *name;
  X509 *peer;
  peer = SSL_get_peer_certificate(self->ssl);
  if (!peer) {
    goto error;
  }
  name = X509_get_subject_name(peer);
  if (!name) {
    goto error;
  }
  pos = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
  if (0 > pos) {
    goto error;
  }
  entry = X509_NAME_get_entry(name, pos);
  if (!entry) {
    goto error;
  }
  entry_string = X509_NAME_ENTRY_get_data(entry);
  if (!entry_string) {
    goto error;
  }
  utf8_length = ASN1_STRING_to_UTF8(&utf8_value, entry_string);
  if (0 > utf8_length) {
    goto error;
  }
  while (utf8_length > 0 && utf8_value[utf8_length - 1] == 0) {
    --utf8_length;
  }
  if (utf8_length >= 256) {
    goto error;
  }
  if ((size_t)utf8_length != strlen((char *)utf8_value)) {
    goto error;
  }
  for (cp = utf8_value; (ch = *cp) != '\0'; ++cp) {
    if (isascii(ch) && !isprint(ch)) {
      goto error;
    }
  }
#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif
  if (strcasecmp(host, (char *)utf8_value)) {
    goto error;
  }
#ifdef _MSC_VER
#undef strcasecmp
#endif
exit:
  OPENSSL_free(utf8_value);
  return status;
error:
  status = -1;
  goto exit;
}

void ddi_get_proxy_info( const char **szProxy, int *nProxyPort );

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

int amqp_open_socket_noblock_proxy( char const *hostname, int portnumber, struct timeval *timeout )
{
	char szConnect[ 4096 ];
	char szResponse[ 4096 ];
	const char *szProxy = NULL;
	int nProxyPort = 0;
	int nFD = -1;

	ddi_get_proxy_info( &szProxy, &nProxyPort );
	if( !szProxy || !nProxyPort )
		return -1;

	nFD = amqp_open_socket_noblock( szProxy, nProxyPort, timeout );

	if( 0 > nFD )
		return -1;

	//try without autentication
	sprintf_s( szConnect, 4096,
"CONNECT %s:%d HTTP/1.1\r\n\
User-Agent: Drainware Proxy client\r\n\
Proxy-Connection: keep-alive\r\n\
Connection: keep-alive\r\n\
\r\n\r\n", hostname, portnumber );

  {
	int nLoop = 10000;
	int nIndex = 0;
	if( SOCKET_ERROR == send( nFD, szConnect, strlen(szConnect), 0) )
	{
		closesocket( nFD );
		return -1;
	}

	while( nLoop-- )
	{
		int nRecv = recv( nFD, szResponse + nIndex, 4096 - nIndex, 0 );
		if( nRecv == SOCKET_ERROR )
		{
			closesocket( nFD );
			return -1;
		}
		if( strstr( szResponse, "\r\n\r\n" ) )
			break;
		Sleep(1);
	}

	if( strstr( szResponse, "HTTP/1.1 200" ) || strstr( szResponse, "HTTP/1.0 200" ) )
		return nFD;
  }		

	//try with BASIC autentication
  //if( strstr( szResponse, "Proxy-Authenticate: Basic" ) )
//  {
//	int nLoop = 10000;
//	char szResponse[ 4096 ];
//	int nIndex = 0;
//	char userpass[256], userpass_[256];
//
//	memset(userpass, 0, 256);
//	memset(userpass_, 0, 256);
//	strcat_s( userpass, 256, "jpalanco" );
//	strcat_s(userpass, 256, ":");
//	strcat_s(userpass, 256, "decdec" );
//	encode( (unsigned char *)userpass, (unsigned char *)userpass_ );
//
//	sprintf_s( szConnect, 4096,
//"CONNECT %s:%d HTTP/1.1\r\n\
//User-Agent: Drainware Proxy client\r\n\
//Proxy-Connection: keep-alive\r\n\
//Connection: keep-alive\r\n\
//Proxy-Authorization: Basic %s\r\n\
//\r\n\r\n", hostname, portnumber, userpass_ );
//
//
//	if( SOCKET_ERROR == send( nFD, szConnect, strlen(szConnect), 0) )
//	{
//		closesocket( nFD );
//		return -1;
//	}
//
//	while( nLoop-- )
//	{
//		int nRecv = recv( nFD, szResponse + nIndex, 4096 - nIndex, 0 );
//		if( nRecv == SOCKET_ERROR )
//		{
//			closesocket( nFD );
//			return -1;
//		}
//		if( strstr( szResponse, "\r\n\r\n" ) )
//			break;
//		Sleep(1);
//	}
//
//	if( strstr( szResponse, "HTTP/1.1 200" ) || strstr( szResponse, "HTTP/1.0 200" ) )
//		return nFD;
//  }
//  //if( strstr( szResponse, "Proxy-Authenticate: NTLM" ) ) //TODO:implement :-)

	return -1;
}


int amqp_ssl_socket_open2( void *base, const char *host, int port, struct timeval *timeout)
{
  struct amqp_ssl_socket_t *self = (struct amqp_ssl_socket_t *)base;
  long result;
  int status;
  ERR_clear_error();

  self->ssl = SSL_new(self->ctx);
  if (!self->ssl) {
    self->internal_error = ERR_peek_error();
    status = AMQP_STATUS_SSL_ERROR;
    goto exit;
  }

  SSL_set_mode(self->ssl, SSL_MODE_AUTO_RETRY);
  self->sockfd = amqp_open_socket_noblock(host, port, timeout);
  if( 0 > self->sockfd ) // try proxy
	  self->sockfd = amqp_open_socket_noblock_proxy( host, port, timeout );
  if (0 > self->sockfd) {
    status = self->sockfd;
    self->internal_error = amqp_os_socket_error();
    self->sockfd = -1;
    goto error_out1;
  }

  status = SSL_set_fd(self->ssl, self->sockfd);
  if (!status) {
    self->internal_error = SSL_get_error(self->ssl, status);
    status = AMQP_STATUS_SSL_ERROR;
    goto error_out2;
  }

  status = SSL_connect(self->ssl);
  if (!status) {
    self->internal_error = SSL_get_error(self->ssl, status);
    status = AMQP_STATUS_SSL_CONNECTION_FAILED;
    goto error_out2;
  }

  result = SSL_get_verify_result(self->ssl);
  if (X509_V_OK != result) {
    self->internal_error = result;
    status = AMQP_STATUS_SSL_PEER_VERIFY_FAILED;
    goto error_out3;
  }
  if (self->verify) {
    int status = amqp_ssl_socket_verify_hostname(self, host);
    if (status) {
      self->internal_error = 0;
      status = AMQP_STATUS_SSL_HOSTNAME_VERIFY_FAILED;
      goto error_out3;
    }
  }

  self->internal_error = 0;
  status = AMQP_STATUS_OK;

exit:
  return status;

error_out3:
  SSL_shutdown(self->ssl);
error_out2:
  amqp_os_socket_close(self->sockfd);
  self->sockfd = -1;
error_out1:
  SSL_free(self->ssl);
  self->ssl = NULL;
  goto exit;
}
