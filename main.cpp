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
    cout << "Automatically generating a random number from random number pool" << endl;
    CryptoPP::AutoSeededRandomPool rnd;
    cout << "Creating a private key based on an integer length and the random number obtained" << endl;
    CryptoPP::RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rnd, 3072);

    cout << "Creating public key utilising the previously created private key" << endl;
    CryptoPP::RSA::PublicKey rsaPublic(rsaPrivate);

    cout << "Storing the private key for future use" << endl;
    SavePrivateKey("CryptoChatRSA.key", rsaPrivate);
    cout << "Storing the public key for future use" << endl;
    SavePublicKey("CryptoChatPubRSA.key", rsaPublic);

    cout << "Please enter a message to encrypt" << endl;
    cin >> messagebuffer;
    cout << "Converting QString to plaintext" << endl;
    QString PlainMessage = QString::fromStdString(messagebuffer);
    cout << "Obtaining length of string to ensure encryption of full text" << endl;
    int plainTextSize = messagebuffer.length();

    string plain=messagebuffer, cipher, recovered;

    cout << "Encrypting plaintext" << endl;
    CryptoPP::RSAES_OAEP_SHA_Encryptor e(rsaPublic);

    CryptoPP::StringSource ss1(plain, true,
        new CryptoPP::PK_EncryptorFilter(rnd, e,
            new CryptoPP::StringSink(cipher)
       )
    );

    cout << "Decrypting ciphertext" << endl;
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(rsaPrivate);

    CryptoPP::StringSource ss2(cipher, true,
        new CryptoPP::PK_DecryptorFilter(rnd, d,
            new CryptoPP::StringSink(recovered)
       )
    );

    cout << "Recovered plain text" << endl;
    }


