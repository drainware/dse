#pragma once

interface IUserNotify
{
	virtual void OnUserConfig( const CStringA &strJSON ) = 0;
	virtual void OnGroupChanged( const CStringA &strGroup, const CStringA &strJSON ) = 0;
	virtual const CAtlList< CStringA > &Groups() = 0;
};

interface IDDINotify
{
	virtual void OnAtpConfig( const CStringA &strJSON ) = 0;
	virtual void OnDDICommand( const CStringA &strJSON ) = 0;
	virtual void OnDDIClose() = 0;
};

interface IDDICtl
{
	virtual void UnsubscribeUserToGroup( const char *szUser, const char *szGroup ) = 0;
};