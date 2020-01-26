#pragma once

#include "..\DrainwareSecurityAgent\DrainwareSecurityAgent_i.h"

#define DW_RPC_S_SERVER_UNAVAILABLE 0X800706BA

class CSrvMngr
{
public:
	bool Init( IUnknown *pUnk )
	{
		m_pUnk = pUnk;
		HRESULT hr = m_pDwService.CoCreateInstance( CLSID_DwService, NULL, CLSCTX_LOCAL_SERVER );
		if( hr == S_OK  && pUnk )
		{
			hr = AtlAdvise( m_pDwService, pUnk, IID__IDwServiceEvents, &m_dwCookie );
			return true;
		}
		return false;
	}

	void MonitorProcess()
	{
		if( m_pDwService )
			m_pDwService->MonitorProcess( GetProcessId( GetCurrentProcess() ) ); 
	}

	void ReInit()
	{
		Close();
		Init( m_pUnk );
		MonitorProcess();
	}

	void Close()
	{
		if( m_pDwService )
		{
			HRESULT hr = AtlUnadvise( m_pDwService, IID__IDwServiceEvents, m_dwCookie );
			if( hr == S_OK )
				m_dwCookie = 0;
			//m_pDwService.Release();
		}
	}

	operator bool() const throw() { return m_pDwService ? true : false; }

    HRESULT IsLicensed( VARIANT_BOOL *bLicensed )
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->IsLicensed( bLicensed );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->IsLicensed( bLicensed );
		}
		return hr;
	}

	HRESULT SetLicense( BSTR bstrLic1, BSTR bstrLic2, BSTR bstrLic3, BSTR bstrLic4, BSTR *bstrUrl, LONG *pnCode )
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->SetLicense( bstrLic1, bstrLic2, bstrLic3, bstrLic4, bstrUrl, pnCode );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->SetLicense( bstrLic1, bstrLic2, bstrLic3, bstrLic4, bstrUrl, pnCode );
		}
		return hr;
	}

    HRESULT GetProtectionType( ULONG *pt)
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->GetProtectionType( pt );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->GetProtectionType( pt );
		}
		return hr;
	}

    HRESULT SetScreenShot( BYTE *pImage, DWORD cb )
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->SetScreenShot( pImage, cb );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->SetScreenShot( pImage, cb );
		}
		return hr;
	}

	HRESULT STDMETHODCALLTYPE CheckText(  BSTR bstrText, TEXT_TYPE nTextType, BSTR bstrApp, VARIANT_BOOL *bEraseText )
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->CheckText( bstrText, nTextType, bstrApp, bEraseText );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->CheckText( bstrText, nTextType, bstrApp, bEraseText );
		}
		return hr;
	}

    HRESULT CheckTextExt( BSTR bstrText, TEXT_TYPE nTextType, BSTR bstrApp, VARIANT_BOOL *bEraseText, BYTE *pImage, DWORD cb )
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->CheckTextExt( bstrText, nTextType, bstrApp, bEraseText, pImage, cb );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->CheckTextExt( bstrText, nTextType, bstrApp, bEraseText, pImage, cb );
		}
		return hr;
	}

    HRESULT CheckFile( BSTR bstrFileOrg, BSTR bstrFileDest, VARIANT_BOOL bDestIsExternFolder, VARIANT_BOOL *bDeleteFile )
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->CheckFile( TYPE_PENDRIVE, bstrFileOrg, bstrFileDest, bDestIsExternFolder, bDeleteFile );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->CheckFile( TYPE_PENDRIVE, bstrFileOrg, bstrFileDest, bDestIsExternFolder, bDeleteFile );
		}
		return hr;
	}

    HRESULT AddProxy( BSTR bstrProxyServer, DWORD bEnable )
	{
		if( !m_pDwService )
			return E_FAIL;
		HRESULT hr = m_pDwService->AddProxy( bstrProxyServer, bEnable );
		if( hr == DW_RPC_S_SERVER_UNAVAILABLE || hr == RPC_E_CONNECTION_TERMINATED || hr == RPC_E_SERVER_DIED )
		{
			ReInit();
			return m_pDwService->AddProxy( bstrProxyServer, bEnable );
		}
		return hr;
	}

	CComPtr<IDwService> m_pDwService;
	DWORD m_dwCookie;
	IUnknown *m_pUnk;
};