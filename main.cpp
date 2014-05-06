#include <QCoreApplication>
#include <iostream>
#include <QString>

#define CRYPTOPP_DEFAULT_NO_DLL
#include <cryptopp/dll.h>
#ifdef CRYPTOPP_WIN32_AVAILABLE
#include <windows.h>
#endif
#include <cryptopp/md5.h>
USING_NAMESPACE(CryptoPP)
USING_NAMESPACE(std)
using namespace std;
const int MAX_PHRASE_LENGTH=250;

void Save(const string& filename, const CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void SavePublicKey(const string& filename, const CryptoPP::RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void SavePrivateKey(const string& filename, const CryptoPP::RSA::PrivateKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}



int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    string messagebuffer = "";
    //string str("C:/Qt/Tools/QtCreator/bin/QTTestingSSLEncryption/CryptoChatDER.key");
    //CryptoPP::RSA::PrivateKey prkey;
    //LoadKey(str, prkey);
    CryptoPP::AutoSeededRandomPool rnd;
    CryptoPP::RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

    CryptoPP::RSA::PublicKey rsaPublic(rsaPrivate);

    SavePrivateKey("CryptoChatRSA.key", rsaPrivate);
    SavePublicKey("CryptoChatPubRSA.key", rsaPublic);

    cout << "Please enter a message to encrypt" << endl;
    cin >> messagebuffer;
    QString PlainMessage = QString::fromStdString(messagebuffer);
    int plainTextSize = messagebuffer.length();

    string plain=messagebuffer, cipher, recovered;


    RSAES_OAEP_SHA_Encryptor e(rsaPublic);

    StringSource ss1(plain, true,
        new PK_EncryptorFilter(rnd, e,
            new StringSink(cipher)
       )
    );


    RSAES_OAEP_SHA_Decryptor d(rsaPrivate);

    StringSource ss2(cipher, true,
        new PK_DecryptorFilter(rnd, d,
            new StringSink(recovered)
       )
    );

    cout << "Recovered plain text" << endl;
    }


