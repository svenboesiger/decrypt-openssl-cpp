#include “openssl/conf.h”
#include “openssl/evp.h”
#include “openssl/err.h”

void OpenSSLDecryptor::decrypt(const QByteArray &cypheredInput,
		QByteArray &unCyptheredOutput, const QString &password) {

	uchar *bufferZeiger = (uchar *) cypheredInput.data();
	long readSize = cypheredInput.length();
	char m_key[32];
	char m_iv[32];
	uchar salt[8];
	memcpy(salt, &bufferZeiger[8], 8);
	bufferZeiger += 16;
	readSize -= 16;

	OpenSSL_add_all_algorithms();
	OPENSSL_config (NULL);

	const EVP_CIPHER* cipher = EVP_get_cipherbyname(“aes - 256 - cbc”);
	const EVP_MD* digest = EVP_get_digestbyname(“md5”);
	if (!cipher)
		qDebug() << "init(): cipher does not exist ";
	if (!digest)
		qDebug() << "init(): digest does not exist ";
	QByteArray tempPassword = password.toLatin1();
	const char *pass = tempPassword.constData();
	EVP_BytesToKey(cipher,
                digest, 
                salt,   
                (uchar*)pass,
                strlen(pass),
                1,  
                (uchar*)m_key,
                (uchar*)m_iv);
	uint SZ = readSize + 20;
	uchar* plaintext = new uchar[SZ];
	bzero(plaintext, SZ);
	int plaintext_len = 0;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	if (!EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, (uchar*) m_key,
			(uchar*) m_iv))
		qDebug() << "EVP_DecryptInit_ex() failed";
	EVP_CIPHER_CTX_set_key_length(&ctx, 32);
	if (!EVP_DecryptUpdate(&ctx, plaintext, &plaintext_len, bufferZeiger,
			readSize))
		qDebug() << "EVP_DecryptUpdate() failed";
	int plaintext_padlen = 0;
	if (!EVP_DecryptFinal_ex(&ctx, plaintext + plaintext_len,
			&plaintext_padlen))
		qDebug() << "EVP_DecryptFinal_ex() failed";
	plaintext_len += plaintext_padlen;
	plaintext[plaintext_len] = 0;
	delete[] plaintext;
	unCyptheredOutput.append((char *) plaintext, plaintext_len);
}
