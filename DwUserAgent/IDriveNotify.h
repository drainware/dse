#pragma once

interface IDriveNotify
{
	virtual void OnDeviceSafeRemoval( TCHAR nDrive ) = 0;
};
