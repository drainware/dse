#pragma once

class CCrypt
{
public:
	CCrypt();
	~CCrypt();

	bool ImportPrivateKey( LPCTSTR szKeyFileName);
	bool ImportPrivateKey( std::vector<char> &pemPrivKey );
	bool ImportPublicKey( LPCTSTR szKeyFileName);
	bool ImportPublicKey( std::vector<char> &pemPubKey );
	bool Decrypt( LPCTSTR sourceFileName, LPCTSTR destinationFileName );
	bool Decrypt( CStringA &strSrc, CStringA &strDst );
	bool Encrypt( LPCTSTR  sourceFileName, LPCTSTR destinationFileName );
	bool Encrypt( CStringA &strSrc, CStringA &strDst );
private:
	HCRYPTPROV m_hCryptoProvider;
	HCRYPTKEY m_hPubKey;
	HCRYPTKEY m_hPrivateKey;
	DWORD m_dwKeySize;
	DWORD m_dwPrivateKeySize;
};