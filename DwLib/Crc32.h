#pragma once

class Crc32
{
public:
	Crc32()
	{
		for( DWORD i = 0; i < 256; i++)
		{
			DWORD c = i;
			for (int j = 0; j < 8; j++) {
				c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
			}
			m_crcTable[i] = c;
		}
	}

	DWORD operator()( PBYTE pBuffer, size_t nLen )
	{
		DWORD c = 0xFFFFFFFF;
		for (size_t i = 0; i < nLen; i++) {
			c = m_crcTable[(c ^ pBuffer[i]) & 0xFF] ^ (c >> 8);
		}
		return c ^ 0xFFFFFFFF;
	}
private:
	DWORD m_crcTable[ 256 ];
};