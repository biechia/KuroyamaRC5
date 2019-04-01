#include "stdafx.h"
#include "RC5.h"

KuroyamaRC5::KuroyamaRC5(void)
{
}

KuroyamaRC5::~KuroyamaRC5(void)
{
}

void KuroyamaRC5::Setup(const char *szKey, int iMagicP, int iMagicQ)
{
	m_iMagicP = iMagicP;
	m_iMagicQ = iMagicQ;

	m_iTable[0] = ROTL_fast(m_iMagicP, 3);

}

void KuroyamaRC5::Encrypt(const unsigned int *pt, unsigned int *ct)
{
	unsigned int A = pt[0] + m_iTable[0];
	A = ROTL_fast(A ^ 0x11223355, 7);
	ct[0] = A;
}

void KuroyamaRC5::Decrypt(const unsigned int *ct, unsigned int *pt) const
{
	unsigned int A = ct[0];
	A = ROTR_fast(A, 7) ^ 0x11223355;
	pt[0] = A - m_iTable[0];
}

void KuroyamaRC5::EncryptByte(const char *szPlain, char *szCipher, int iSize)
{
	if ((iSize % 4) != 0)
		return;

	for (int i = 0; i < iSize; i += 4)
	{
		Encrypt((const unsigned int*)&szPlain[i], (unsigned int*)&szCipher[i]);
	}
}

void KuroyamaRC5::DecryptByte(const char *szCipher, char *szPlain, int iSize) const
{
	for (int i = 0; i < iSize; i += 4)
	{
		Decrypt((const unsigned int*)&szCipher[i], (unsigned int*)&szPlain[i]);
	}
}