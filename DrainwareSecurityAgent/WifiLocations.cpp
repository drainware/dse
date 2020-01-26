#include "stdafx.h"
#include <wlanapi.h>
#include "..\..\DrainwareLibs\json-c\json.h"
//#include <atlhttp.h>
#include "..\DwLib\DwLib.h"

#pragma comment(lib, "wlanapi.lib")

void GetWifiLocations( CStringA &strLocations, CAtlArray< CString > &aProxy, bool bProxyEnable )
{
	//Sleep( 20000 );
	HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;      //    
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;
    DWORD dwRetVal = 0;
    int iRet = 0;
	CString strURL = _T("https://maps.googleapis.com/maps/api/browserlocation/json?browser=firefox&sensor=true");

	if( ERROR_SUCCESS == WlanOpenHandle( dwMaxClient, NULL, &dwCurVersion, &hClient ) )
	{
		PWLAN_INTERFACE_INFO_LIST pIfList = NULL;

		if( ERROR_SUCCESS == WlanEnumInterfaces(hClient, NULL, &pIfList) )
		{
			CStringA strValue;
			//CString strSSID;
			CStringA strA;
			for( DWORD i = 0; i < pIfList->dwNumberOfItems; i++ )
			{
				PWLAN_INTERFACE_INFO pIfInfo = &pIfList->InterfaceInfo[ i ];
				PWLAN_BSS_LIST pBssList = NULL;
				if( ERROR_SUCCESS == WlanGetNetworkBssList( hClient, &pIfInfo->InterfaceGuid, NULL, dot11_BSS_type_any, FALSE, NULL, &pBssList ) )
				{
					for( DWORD j = 0; j < pBssList->dwNumberOfItems; j++ )
					{
						PWLAN_BSS_ENTRY pEntry = &pBssList->wlanBssEntries[ j ];
				
						strA.SetString( (const char *)pEntry->dot11Ssid.ucSSID, pEntry->dot11Ssid.uSSIDLength );
						//strSSID = strA;
						strValue.Format( "&wifi=mac:%02x-%02x-%02x-%02x-%02x-%02x|ssid:%s|ss:%d", pEntry->dot11Bssid[ 0 ], pEntry->dot11Bssid[ 1 ], pEntry->dot11Bssid[ 2 ]
							, pEntry->dot11Bssid[ 3 ], pEntry->dot11Bssid[ 4 ], pEntry->dot11Bssid[ 5 ], strA, pEntry->lRssi );
						strURL += strValue;
					}
				}
				if( pBssList )
					WlanFreeMemory( pBssList );
			}
		}
		if( pIfList )
			WlanFreeMemory( pIfList );
	}

	if( hClient )
		WlanCloseHandle( hClient , NULL );


	if( aProxy.GetCount() )
	{
		for( size_t i = 0; i < aProxy.GetCount(); i++ )
		{
			if( QueryWinHttp( strURL, strLocations, 443, NULL, NULL, aProxy[ i ], bProxyEnable ) )
				return;
		}
	}
	else
		QueryWinHttp( strURL, strLocations, 443 );

	//QueryWinHttp( strURL, strLocations, 443, NULL, NULL, strProxy, bProxyEnable );
}

void GetWifiLocationsOld( CStringA &strLocations )
{
	//Sleep( 20000 );
	json_object *pRoot = json_object_new_object();

	HANDLE hClient = NULL;
    DWORD dwMaxClient = 2;      //    
    DWORD dwCurVersion = 0;
    DWORD dwResult = 0;
    DWORD dwRetVal = 0;
    int iRet = 0;
    
	if( ERROR_SUCCESS != WlanOpenHandle( dwMaxClient, NULL, &dwCurVersion, &hClient ) )
		return;

	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;

	if( ERROR_SUCCESS != WlanEnumInterfaces(hClient, NULL, &pIfList) )
		return;

	for( DWORD i = 0; i < pIfList->dwNumberOfItems; i++ )
	{
		PWLAN_INTERFACE_INFO pIfInfo = &pIfList->InterfaceInfo[ i ];
	    PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
		if( ERROR_SUCCESS == WlanGetAvailableNetworkList( hClient, &pIfInfo->InterfaceGuid, 0,  NULL,  &pBssList ) )
		{
			for( DWORD j = 0; j < pBssList->dwNumberOfItems; j++ )
			{
				PWLAN_AVAILABLE_NETWORK pBssEntry = &pBssList->Network[ j ];
				int nQuality = 0;
				if( pBssEntry->wlanSignalQuality == 0 )
					nQuality = -100;
				else if( pBssEntry->wlanSignalQuality == 100 )
					nQuality = -50;
				else
					nQuality = -100 + pBssEntry->wlanSignalQuality / 2;

				nQuality = 0;
				//pBssEntry->dot11Ssid.ucSSID

			}

			if( pBssList )
				WlanFreeMemory( pBssList );
		}
	}

	if( pIfList )
		WlanFreeMemory( pIfList );


	json_object_put( pRoot );
}