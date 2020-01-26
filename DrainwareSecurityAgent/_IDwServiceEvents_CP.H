
// Clase de proxy del punto de conexión generada por el asistente
// ADVERTENCIA: el asistente puede volver a generar este archivo


#pragma once

template<class T>
class CProxy_IDwServiceEvents :
	public ATL::IConnectionPointImpl<T, &__uuidof(_IDwServiceEvents)>
{
public:

	void Fire_Close( VARIANT_BOOL bUpdate )
	{
		T* pT = static_cast<T*>(this);
		int i;
		int nConnections = m_vec.GetSize();

		for( i = 0; i < nConnections; i++ )
		{
			pT->Lock();
			CComPtr<IUnknown> sp = m_vec.GetAt(i);
			pT->Unlock();
			
			_IDwServiceEvents *pEvents = reinterpret_cast<_IDwServiceEvents *>(sp.p);
			if( pEvents )
				pEvents->OnClose( bUpdate );
		}
	}

	bool Fire_ShowMsg( ULONG nType )
	{
		T* pT = static_cast<T*>(this);
		int i;
		int nConnections = m_vec.GetSize();

		for( i = 0; i < nConnections; i++ )
		{
			pT->Lock();
			CComPtr<IUnknown> sp = m_vec.GetAt(i);
			pT->Unlock();
			
			_IDwServiceEvents *pEvents = reinterpret_cast<_IDwServiceEvents *>(sp.p);
			if( pEvents )
			{
				VARIANT_BOOL bShown = VARIANT_FALSE;
				pEvents->OnShowTrayWindow( nType, &bShown );
				if( bShown == VARIANT_TRUE )
					return true;
			}
		}
		return false;
	}

	bool Fire_ShowCheckDialog( ULONG nType )
	{
		T* pT = static_cast<T*>(this);
		int i;
		int nConnections = m_vec.GetSize();

		for( i = 0; i < nConnections; i++ )
		{
			pT->Lock();
			CComPtr<IUnknown> sp = m_vec.GetAt(i);
			pT->Unlock();
			
			_IDwServiceEvents *pEvents = reinterpret_cast<_IDwServiceEvents *>(sp.p);
			if( pEvents )
			{
				VARIANT_BOOL bShown = VARIANT_FALSE;
				pEvents->OnShowCheckDialog( nType, &bShown );
				if( bShown == VARIANT_TRUE )
					return true;
			}
		}
		return false;
	}

	bool Fire_ScreenShot()
	{
		T* pT = static_cast<T*>(this);
		int i;
		int nConnections = m_vec.GetSize();

		for( i = 0; i < nConnections; i++ )
		{
			pT->Lock();
			CComPtr<IUnknown> sp = m_vec.GetAt(i);
			pT->Unlock();
			
			_IDwServiceEvents *pEvents = reinterpret_cast<_IDwServiceEvents *>(sp.p);
			if( pEvents )
			{
				VARIANT_BOOL bShown = VARIANT_FALSE;
				pEvents->OnGetScreenShot( &bShown );
				if( bShown == VARIANT_TRUE )
					return true;
			}
		}
		return false;
	}

	bool Fire_ShowUserMessage( BSTR bstrMsg)
	{
		T* pT = static_cast<T*>(this);
		int i;
		int nConnections = m_vec.GetSize();

		for( i = 0; i < nConnections; i++ )
		{
			pT->Lock();
			CComPtr<IUnknown> sp = m_vec.GetAt(i);
			pT->Unlock();
			
			_IDwServiceEvents *pEvents = reinterpret_cast<_IDwServiceEvents *>(sp.p);
			if( pEvents )
			{
				VARIANT_BOOL bShown = VARIANT_FALSE;
				pEvents->OnShowUserMessage( bstrMsg );
			}
		}
		return false;
	}

	void Fire_ActiveModules( ULONG nActiveModules )
	{
		T* pT = static_cast<T*>(this);
		int i;
		int nConnections = m_vec.GetSize();

		for( i = 0; i < nConnections; i++ )
		{
			pT->Lock();
			CComPtr<IUnknown> sp = m_vec.GetAt(i);
			pT->Unlock();
			
			_IDwServiceEvents *pEvents = reinterpret_cast<_IDwServiceEvents *>(sp.p);
			if( pEvents )
				pEvents->OnActiveModules( nActiveModules );
		}
	}
};

