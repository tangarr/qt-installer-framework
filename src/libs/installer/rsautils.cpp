#include "rsautils.h"
#include <QFile>
#include <memory>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

RsaPublicKey::RsaPublicKey() :
    mPubKey(nullptr, RSA_free)
{
    mError=QLatin1String("(NULL)");
}

RsaPublicKey::RsaPublicKey(const QByteArray &data) :
    mPubKey(nullptr, RSA_free)
{
    std::unique_ptr<BIO, void(*)(BIO*)> bio(BIO_new_mem_buf(reinterpret_cast<const void*>(data.constData()), data.size()), [](BIO* bio) {
        if (!bio)
            return;
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free(bio);
    });
    if (!bio) {
        mError = QString::fromLatin1("BIO_new_mem_buf failed");
        return;
    }

    std::unique_ptr<RSA, void(*)(RSA*)> pubKey(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr), RSA_free);
    if (!pubKey)
        mError = QString::fromLatin1("PEM_read_bio_RSAPublicKey failed: ")+QString::fromLatin1(ERR_error_string(ERR_peek_last_error(), nullptr));
    mPubKey = std::move(pubKey);
}

RsaPublicKey &RsaPublicKey::operator =(RsaPublicKey &&other)
{
    if (this == &other)
        return *this;
    mPubKey = std::move(other.mPubKey);
    mError = std::move(other.mError);
    return *this;
}

bool RsaPublicKey::isValid() const
{
    return mPubKey.get() != nullptr;
}

QString RsaPublicKey::errorString() const
{
    return mError;
}

bool RsaPublicKey::verify(const QString &file, const QString &signature)
{
    if (!isValid())
        return false;
    mError.clear();
    try {
        QFile inputFile(signature);
        auto signatureSize = inputFile.size();
        if (signatureSize==0)
            throw QString::fromLatin1("Signature file \"%1\" is empty").arg(file);
        if (signatureSize>1024*1024)
            throw QString::fromLatin1("Signature file \"%1\" is too big").arg(file);
        if (!inputFile.open(QIODevice::ReadOnly))
            throw QString::fromLatin1("Unable to open file \"%1\": %2").arg(file).arg(inputFile.errorString());
        auto sign = inputFile.readAll();
        inputFile.close();
        inputFile.setFileName(file);
        if (!inputFile.open(QIODevice::ReadOnly))
            throw QString::fromLatin1("Unable to open file \"%1\": %2").arg(file).arg(inputFile.errorString());
        std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
        if (!mdctx)
            throw QString::fromLatin1("EVP_MD_CTX_create() failed");
        std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> key(EVP_PKEY_new(), EVP_PKEY_free);
        if (!key)
            throw QString::fromLatin1("EVP_PKEY_new() failed");
        if (!EVP_PKEY_set1_RSA(key.get(), mPubKey.get()))
            throw QString::fromLatin1("EVP_PKEY_set1_RSA() failed");
        if(1 != EVP_DigestVerifyInit(mdctx.get(), NULL, EVP_sha256(), NULL, key.get()))
            throw QString::fromLatin1("EVP_DigestVerifyInit() failed");
        char buffer[1024];
        qint64 readed = 0;
        while (readed < inputFile.size()) {
            auto toRead = inputFile.size() - readed;
            if (toRead > sizeof(buffer))
                toRead = sizeof(buffer);
            qint64 br = inputFile.read(buffer, toRead);
            if (br != toRead)
                throw QString::fromLatin1("Read of file \"%1\" failed: %2").arg(file).arg(inputFile.errorString());
            readed += br;
            if(1 != EVP_DigestVerifyUpdate(mdctx.get(), buffer, static_cast<int>(toRead)))
                throw QString::fromLatin1("EVP_DigestVerifyUpdate() failed");
        }
        if (!EVP_DigestVerifyFinal(mdctx.get(), reinterpret_cast<const unsigned char*>(sign.constData()), sign.length())) {
            throw QString::fromLatin1("Signature is invalid");
        }

    }
    catch (const QString &error) {
        mError = error;
        return false;
    }
    return true;


}

RsaPrivateKey::RsaPrivateKey() :
    mPrivKey(nullptr, RSA_free)
{
    mError=QLatin1String("(NULL)");
}

RsaPrivateKey::RsaPrivateKey(const QByteArray &data) :
    mPrivKey(nullptr, RSA_free)
{
    std::unique_ptr<BIO, void(*)(BIO*)> bio(BIO_new_mem_buf(reinterpret_cast<const void*>(data.constData()), data.size()), [](BIO* bio) {
        if (!bio)
            return;
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free(bio);
    });
    if (!bio) {
        mError = QString::fromLatin1("BIO_new_mem_buf failed");
        return;
    }

    std::unique_ptr<RSA, void(*)(RSA*)> key(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr), RSA_free);
    if (!key)
        mError = QString::fromLatin1("PEM_read_bio_RSAPublicKey failed: ")+QString::fromLatin1(ERR_error_string(ERR_peek_last_error(), nullptr));
    mPrivKey = std::move(key);
}

bool RsaPrivateKey::isValid() const
{
    return mPrivKey.get() != nullptr;
}

QString RsaPrivateKey::errorString() const
{
    return mError;
}

RsaPrivateKey &RsaPrivateKey::operator =(RsaPrivateKey &&other)
{
    if (this == &other)
        return *this;
    mError = std::move(other.mError);
    mPrivKey = std::move(other.mPrivKey);
    return *this;
}

bool RsaPrivateKey::sign(const QString &file, const QString &signature)
{
    if (!isValid()) {
        return false;
    }
    mError.clear();
    try {
        QFile inputFile(file);
        if (!inputFile.open(QIODevice::ReadOnly))
            throw QString::fromLatin1("Unable to open file \"%1\": %2").arg(file).arg(inputFile.errorString());
        std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> mdctx(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
        if (!mdctx)
            throw QString::fromLatin1("EVP_MD_CTX_create() failed");
        std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> key(EVP_PKEY_new(), EVP_PKEY_free);
        if (!key)
            throw QString::fromLatin1("EVP_PKEY_new() failed");
        if (!EVP_PKEY_set1_RSA(key.get(), mPrivKey.get()))
            throw QString::fromLatin1("EVP_PKEY_set1_RSA() failed");
        if(1 != EVP_DigestSignInit(mdctx.get(), NULL, EVP_sha256(), NULL, key.get()))
            throw QString::fromLatin1("EVP_DigestSignInit() failed");
        char buffer[1024];
        qint64 readed = 0;
        while (readed < inputFile.size()) {
            auto toRead = inputFile.size() - readed;
            if (toRead > sizeof(buffer))
                toRead = sizeof(buffer);
            qint64 br = inputFile.read(buffer, toRead);
            if (br != toRead)
                throw QString::fromLatin1("Read of file \"%1\" failed: %2").arg(file).arg(inputFile.errorString());
            readed += br;
            if(1 != EVP_DigestSignUpdate(mdctx.get(), buffer, static_cast<int>(toRead)))
                throw QString::fromLatin1("EVP_DigestSignUpdate() failed");
        }
        size_t slen;
        if(1 != EVP_DigestSignFinal(mdctx.get(), NULL, &slen))
            throw QString::fromLatin1("EVP_DigestSignFinal() failed");
        std::unique_ptr<void, void(*)(void*)> sig(OPENSSL_malloc(sizeof(unsigned char)*slen), CRYPTO_free);
        if (!sig)
            throw QString::fromLatin1("OPENSSL_malloc() failed");
        if(1 != EVP_DigestSignFinal(mdctx.get(), reinterpret_cast<unsigned char*>(sig.get()), &slen))
            throw QString::fromLatin1("EVP_DigestSignFinal() failed");
        QFile outFile(signature);
        if (!outFile.open(QIODevice::WriteOnly))
            throw QString::fromLatin1("Unable to open file \"%1\": %2").arg(signature).arg(outFile.errorString());
        auto bw = outFile.write(reinterpret_cast<const char*>(sig.get()), slen);
        if (bw != slen || !outFile.flush())
            throw QString::fromLatin1("Write to file \"%1\" failed: %2").arg(signature).arg(outFile.errorString());
    }
    catch (const QString &error) {
        mError = error;
        return false;
    }
    return true;
}
