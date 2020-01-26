#pragma once

class CStgMedium : public STGMEDIUM
{
public:
	CStgMedium()
	{
		ZeroMemory( this, sizeof(*this) );
	}

	~CStgMedium()
	{
		//::ReleaseStgMedium( this );
	}
};