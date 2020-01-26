#include "stdafx.h"
#include "Crypt.h"

CCrypt::CCrypt()
{
	m_hCryptoProvider = NULL;
	m_hPubKey = NULL;
	m_hPrivateKey = NULL;
	m_dwKeySize = 0;
	m_dwPrivateKeySize = 0;

	CryptAcquireContext( &m_hCryptoProvider, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT );
}

CCrypt::~CCrypt()
{
	if( m_hPubKey )
		CryptDestroyKey(m_hPubKey);
	if( m_hPrivateKey )
		CryptDestroyKey(m_hPrivateKey);

	CryptReleaseContext( m_hCryptoProvider, 0 );
}

bool CCrypt::ImportPrivateKey( std::vector<char> &pemPrivKey )
{
	DWORD derPrivKeyLen = 0;
	if( !CryptStringToBinaryA( &pemPrivKey.front(), 0, CRYPT_STRING_BASE64HEADER, 0, &derPrivKeyLen, NULL, NULL ) )
		return false;

	std::vector<BYTE> derPrivKey(derPrivKeyLen);
	if( !CryptStringToBinaryA(&pemPrivKey.front(), 0, CRYPT_STRING_BASE64HEADER, &derPrivKey.front(), &derPrivKeyLen, NULL, NULL ) )
		return false;

	DWORD nBlobLength = 0;
	BLOBHEADER *pBlob = NULL;
	if( CryptDecodeObjectEx( X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, &derPrivKey.front(), derPrivKeyLen, CRYPT_DECODE_ALLOC_FLAG, NULL, &pBlob, &nBlobLength ) ) 
	{
		CryptImportKey( m_hCryptoProvider, (BYTE*)pBlob, nBlobLength, NULL, 0, &m_hPrivateKey );
	}

	if( pBlob )
		LocalFree( pBlob );

	if( m_hPrivateKey )
	{
		DWORD dwSize = sizeof(DWORD);
		CryptGetKeyParam( m_hPrivateKey, KP_BLOCKLEN, (BYTE*)&m_dwPrivateKeySize, &dwSize, 0 );
		m_dwPrivateKeySize /= 8;
	}

	return true;
}

bool CCrypt::ImportPrivateKey( LPCTSTR szKeyFileName )
{
	CAtlFile fKey;
	fKey.Create( szKeyFileName, GENERIC_READ, 0, OPEN_EXISTING );

	if( !fKey )
		return false;

	ULONGLONG nLen = 0;
	fKey.GetSize( nLen );
	DWORD readLen = DWORD( nLen );

	std::vector<char> vPrivateKey(readLen);

	if( S_OK != fKey.Read( &vPrivateKey.front(), readLen ) )
		return false;

	return ImportPrivateKey( vPrivateKey );
}

bool CCrypt::ImportPublicKey( std::vector<char> &pemPubKey )
{
	DWORD derPubKeyLen = 0;
	if( !CryptStringToBinaryA( &pemPubKey.front(), 0, CRYPT_STRING_BASE64HEADER, 0, &derPubKeyLen, NULL, NULL ) )
		return false;

	std::vector<BYTE> derPubKey(derPubKeyLen);
	if( !CryptStringToBinaryA(&pemPubKey.front(), 0, CRYPT_STRING_BASE64HEADER, &derPubKey.front(), &derPubKeyLen, NULL, NULL ) )
		return false;

	CERT_PUBLIC_KEY_INFO *publicKeyInfo;
	DWORD publicKeyInfoLen;
	if( !CryptDecodeObjectEx( X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &derPubKey.front(), derPubKeyLen, CRYPT_ENCODE_ALLOC_FLAG, NULL, &publicKeyInfo, &publicKeyInfoLen ) )
		return false;
	
	BYTE* pbPKEY = 0;
	DWORD dwPKEYSize = 0;
	if( !CryptDecodeObjectEx( X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, publicKeyInfo->PublicKey.pbData, publicKeyInfo->PublicKey.cbData, CRYPT_DECODE_ALLOC_FLAG, NULL, &pbPKEY, &dwPKEYSize ) )
	{
		LocalFree(publicKeyInfo);
		return false;
	}

	if( !CryptImportKey( m_hCryptoProvider, pbPKEY, dwPKEYSize, 0, 0, &m_hPubKey ) )
	{
		LocalFree(publicKeyInfo);
		LocalFree(pbPKEY);
		return false;
	}

	LocalFree(publicKeyInfo);
	LocalFree(pbPKEY);

	if( m_hPubKey )
	{
		DWORD dwParamSize = sizeof(DWORD);
		CryptGetKeyParam( m_hPubKey, KP_KEYLEN, (BYTE*) &m_dwKeySize, &dwParamSize, 0 );
		m_dwKeySize /= 8;
	}

	return true;
}

bool CCrypt::ImportPublicKey( LPCTSTR szKeyFileName )
{
	CAtlFile fKey;
	fKey.Create( szKeyFileName, GENERIC_READ, 0, OPEN_EXISTING );

	if( !fKey )
		return false;

	ULONGLONG nLen = 0;
	fKey.GetSize( nLen );
	DWORD readLen = DWORD( nLen );

	std::vector<char> pemPubKey(readLen);

	if( S_OK != fKey.Read( &pemPubKey.front(), readLen ) )
		return false;

	return ImportPublicKey( pemPubKey );
}

bool CCrypt::Encrypt( LPCTSTR sourceFileName, LPCTSTR destinationFileName)
{
	if( !m_hPubKey || !m_dwKeySize )
		return false;

	CAtlFile fSource;
	if( S_OK != fSource.Create( sourceFileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
		return false;

	if( !fSource )
		return false;

	CAtlFile fDest;
	if( S_OK != fDest.Create( destinationFileName, GENERIC_WRITE, FILE_SHARE_READ, OPEN_ALWAYS ) )
		return false;

	bool fEOF = false;

	DWORD dwBlockLen = m_dwKeySize - 11;
	std::vector<BYTE> buffer(dwBlockLen);

    do 
    {
		DWORD dwReadCount = 0;
		if( S_OK != fSource.Read( &buffer.front(), dwBlockLen, dwReadCount ) )
			return false;

        if( dwReadCount < dwBlockLen)
        {
            fEOF = true;
        }

		DWORD dwBufferEncSize = dwReadCount;
		if( !CryptEncrypt(m_hPubKey, 0, fEOF, 0, NULL, &dwBufferEncSize, dwReadCount ) )
			return false;

		if( dwBufferEncSize > buffer.size() )
			buffer.resize( dwBufferEncSize );

		if( !CryptEncrypt( m_hPubKey, 0, fEOF, 0, &buffer.front(), &dwReadCount, dwBufferEncSize ) )
			return false;

		for( DWORD i = 0; i < (dwBufferEncSize / 2); i++ ) //Convert to big endian
		{
			BYTE c = buffer[ i ];
			buffer[ i ] = buffer[ dwBufferEncSize - 1 - i ];
			buffer[ dwBufferEncSize - 1 - i ] = c;
		}
 
		if( S_OK != fDest.Write( &buffer.front(), dwBufferEncSize ) )
			return false;
    } 
	while( !fEOF );

	return true;
}

bool CCrypt::Encrypt( CStringA &strSrc, CStringA &strDst )
{
	if( !m_hPubKey || !m_dwKeySize )
		return false;

	bool fEOF = false;

	DWORD dwBlockLen = m_dwKeySize - 11;
	std::vector<BYTE> buffer( dwBlockLen );
	DWORD nPosSrc = 0;
    do
    {
		DWORD dwReadCount = min( dwBlockLen, DWORD(strSrc.GetLength()) - nPosSrc );
		CopyMemory( &buffer.front(), strSrc.GetBuffer() + nPosSrc, dwReadCount );
		nPosSrc += dwReadCount;

        if( dwReadCount < dwBlockLen)
            fEOF = true;

		DWORD dwBufferEncSize = dwReadCount;
		if( !CryptEncrypt(m_hPubKey, 0, fEOF, 0, NULL, &dwBufferEncSize, dwReadCount ) )
			return false;

		if( dwBufferEncSize > buffer.size() )
			buffer.resize( dwBufferEncSize );

		if( !CryptEncrypt( m_hPubKey, 0, fEOF, 0, &buffer.front(), &dwReadCount, dwBufferEncSize ) )
			return false;

		for( DWORD i = 0; i < (dwBufferEncSize / 2); i++ ) //Convert to big endian
		{
			BYTE c = buffer[ i ];
			buffer[ i ] = buffer[ dwBufferEncSize - 1 - i ];
			buffer[ dwBufferEncSize - 1 - i ] = c;
		}

		DWORD nPosDst = strDst.GetLength();
		CopyMemory( strDst.GetBufferSetLength( nPosDst + dwBufferEncSize ) + nPosDst, &buffer.front(), dwBufferEncSize );
 
    }while( !fEOF );

	return true;
}


bool CCrypt::Decrypt( CStringA &strSrc, CStringA &strDst )
{
	if( !m_hPrivateKey || !m_dwPrivateKeySize )
		return false;
	bool fEOF = false;
	DWORD dwBlockLen = m_dwPrivateKeySize;// - 11;
	std::vector<BYTE> buffer(dwBlockLen);
	DWORD nPosSrc = 0;
    do 
    {
		DWORD dwReadCount = min( dwBlockLen, DWORD(strSrc.GetLength()) - nPosSrc );
		CopyMemory( &buffer.front(), strSrc.GetBuffer() + nPosSrc, dwReadCount );
		nPosSrc += dwReadCount;

        if( dwReadCount < dwBlockLen)
            fEOF = true;

		DWORD dwBufferDecSize = dwReadCount;
		for( DWORD i = 0; i < (dwBufferDecSize / 2); i++ ) //Convert to little endian
		{
			BYTE c = buffer[ i ];
			buffer[ i ] = buffer[ dwBufferDecSize - 1 - i ];
			buffer[ dwBufferDecSize - 1 - i ] = c;
		}

		if( !CryptDecrypt( m_hPrivateKey, 0, fEOF, 0, &buffer.front(), &dwBufferDecSize ) )
			return false;
 
		DWORD nPosDst = strDst.GetLength();
		CopyMemory( strDst.GetBufferSetLength( nPosDst + dwBufferDecSize ) + nPosDst, &buffer.front(), dwBufferDecSize );
    } 
	while( !fEOF );

	return true;
}

bool CCrypt::Decrypt( LPCTSTR sourceFileName, LPCTSTR destinationFileName )
{
	if( !m_hPrivateKey || !m_dwPrivateKeySize )
		return false;

	CAtlFile fSource;
	if( S_OK != fSource.Create( sourceFileName, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING ) )
		return false;

	if( !fSource )
		return false;

	CAtlFile fDest;
	if( S_OK != fDest.Create( destinationFileName, GENERIC_WRITE, FILE_SHARE_READ, OPEN_ALWAYS ) )
		return false;

	bool fEOF = false;

	DWORD dwBlockLen = m_dwPrivateKeySize;// - 11;
	std::vector<BYTE> buffer(dwBlockLen);

    do 
    {
		DWORD dwReadCount = 0;
		if( S_OK != fSource.Read( &buffer.front(), dwBlockLen, dwReadCount ) )
			return false;

        if( dwReadCount < dwBlockLen)
        {
            fEOF = true;
        }

		DWORD dwBufferDecSize = dwReadCount;
		for( DWORD i = 0; i < (dwBufferDecSize / 2); i++ ) //Convert to little endian
		{
			BYTE c = buffer[ i ];
			buffer[ i ] = buffer[ dwBufferDecSize - 1 - i ];
			buffer[ dwBufferDecSize - 1 - i ] = c;
		}

		if( !CryptDecrypt( m_hPrivateKey, 0, fEOF, 0, &buffer.front(), &dwBufferDecSize ) )
			return false;
 
		if( S_OK != fDest.Write( &buffer.front(), dwBufferDecSize ) )
			return false;
    } 
	while( !fEOF );

	return true;
}
