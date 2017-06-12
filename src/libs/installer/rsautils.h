#ifndef RSAUTILS_H
#define RSAUTILS_H

#include <QByteArray>
#include <memory>

typedef struct rsa_st RSA;

class RsaPublicKey {
public:
    RsaPublicKey();
    RsaPublicKey(const QByteArray &data);

    RsaPublicKey &operator = (RsaPublicKey && other);
    bool isValid() const;
    QString errorString() const;
    bool verify(const QString &file, const QString &signature);
private:
    std::unique_ptr<RSA, void(*)(RSA*)> mPubKey;
    QString mError;
};


class RsaPrivateKey {
public:
    RsaPrivateKey();
    RsaPrivateKey(const QByteArray &data);

    RsaPrivateKey &operator = (RsaPrivateKey && other);
    QString errorString() const;
    bool isValid() const;
    bool sign(const QString& file, const QString &signature);
private:
    std::unique_ptr<RSA, void(*)(RSA*)> mPrivKey;
    QString mError;
};

#endif // RSAUTILS_H
