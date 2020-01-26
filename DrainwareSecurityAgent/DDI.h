#pragma once

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>

struct UserInfo
{
	CStringA m_strName;
	//CAtlArray< IUserNotify * > m_aUserNotifies;
	IUserNotify *m_pUserNotify;
	CAtlMap< CStringA, bool > m_mapGroups;
	UserInfo() : m_pUserNotify( NULL )
	{}
};

struct MsgInfo
{
	CStringA strUser;
	CStringA strRoutingKey;
	CStringA strMsg;
};

class CDDI : public IDDICtl
{
public:
	CDDI();
	~CDDI();

	void AddUser( const char *szUser, IUserNotify *pUserconfig );
	void AddUserGroup( const char *szUser, const char *szGroup );
	//void AddProxy( const WCHAR *szProxy, LONG bEnable );
	void AddProxy( CAtlArray<CString> &aProxy, bool bEnable );
	void SetDDINotify( IDDINotify *pNotify );
	bool Connect( const char *szHostName, int nPort, const char *szUser = "guest", const char *szPassword = "guest" );
	bool Publish( const char *szUser/*, const char *szExchange*/, const char *szRoutingKey, CStringA &strMsg );
	void Close();
	void Run();
	void Stop( bool bClose = false );

	bool IsRunning() const throw() { return m_bRunning; }
	bool IsClosing() const throw() { return m_bClose; }
	void SetMachineName( const CStringA &str ){ m_strThisMachine = str; }
	void SetLicense( const CStringA &str ){ m_strLicense = str; }
	const CStringA &GetMachineName() const throw() { return m_strThisMachine; }
	//void SubscribeGroup( const char *szGroup );
	void SubscribeUserToGroup( const char *szUser, const char *szGroup, IUserNotify *pUserNotify );
	void UnsubscribeUser( const char *szUser );
	void UnsubscribeUserToGroup( const char *szUser, const char *szGroup );
private:
	bool ConnectSend();
	void CloseSend();
	int WaitFrame( amqp_connection_state_t state, amqp_frame_t *decoded_frame );
	bool GetFreeChannel() const throw();
	bool InternalPublish( const char *szUser/*, const char *szExchange*/, const char *szRoutingKey, CStringA &strMsg );
	void UnsubscribeAll();
	void UnbindGroups();

	//Events
	void OnCancel();
	void OnRececiveMsg( int nChannel, const CStringA &strUser, const CStringA &strExchange, const CStringA &strRoutingKey, CStringA &strMsg );

	amqp_connection_state_t m_connRecv;
	amqp_bytes_t m_queueRecv;

	amqp_connection_state_t m_connSend;
	amqp_bytes_t m_queueSend;

	CStringA m_strExchange;
	CStringA m_strBindingKey;
	CStringA m_strThisMachine;
	CStringA m_strLicense;
	CStringA m_strHost;
	CStringA m_strUser;
	CStringA m_strPassword;
	int		m_nPort;
	bool m_bStop;
	bool m_bClose;
	bool m_bStopping;
	CEvent m_evtStop;
	CAtlMap< CStringA, UserInfo > m_mapUsers;
	CAtlMap< CStringA, bool > m_mapGroups;
	IDDINotify * m_pDDINotify;
	CCriticalSection m_cs;
	volatile bool m_bRunning;
	//int m_nSocketFD;
	//amqp_socket_t *m_sock;
	CCriticalSection m_csMsg;
	CCriticalSection m_csStop;
	CAtlArray< MsgInfo > m_aMsg;
	CAtlArray< CStringA > m_aProxy;
	int m_bProxyEnable;
};
