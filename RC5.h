#pragma once

#define ROTL(x,y) (((x)<<(y&(WORD_SIZE-1))) | ((x)>>(WORD_SIZE-(y&(WORD_SIZE-1)))))
#define ROTR(x,y) (((x)>>(y&(WORD_SIZE-1))) | ((x)<<(WORD_SIZE-(y&(WORD_SIZE-1)))))

#define ROTL_fast(x,y) (((x)<<y) | ((x)>>(WORD_SIZE-y)))
#define ROTR_fast(x,y) (((x)>>y) | ((x)<<(WORD_SIZE-y)))

class KuroyamaRC5
{
public:
	enum
	{
		WORD_SIZE   = 32,
		ROUND_NUM   = 1,
		KEY_SIZE    = 16,
		KEY_CEIL    = 4,
		TABLE_SIZE  = 1,
	};
protected:
	unsigned int m_iTable[TABLE_SIZE];
	unsigned int m_iMagicP;           
	unsigned int m_iMagicQ;  

protected:
	void Encrypt(const unsigned int *pt, unsigned int *ct);
	void Decrypt(const unsigned int *ct, unsigned int *pt) const;

public:
	void Setup(const char *szKey, int iMagicP, int iMagicQ);
	void EncryptByte(const char *szPlain, char *szCipher, int iSize);
	void DecryptByte(const char *szCipher, char *szPlain, int iSize) const;
	
public:
	KuroyamaRC5(void); 
	virtual ~KuroyamaRC5(void);
};
