using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TestCSharpRSAConsole
{
    class RSAUtil
    {
        static AsymmetricKeyParameter readPrivateKey(string privateKeyFileName)
        {
            AsymmetricKeyParameter keyParam;

            PemObject pemObj;
            using (var reader = File.OpenText(privateKeyFileName))
                pemObj = new PemReader(reader).ReadPemObject();

            keyParam = PublicKeyFactory.CreateKey(pemObj.Content);

            return keyParam;
        }

        public static string RSAEncrypt(string XmlPublicKey, string PlainText)
        {
            byte[] publicInfoByte = Convert.FromBase64String(XmlPublicKey);
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(publicInfoByte);
            var decryptEngine = new OaepEncoding(new RsaEngine());
            decryptEngine.Init(true, publicKey);

            byte[] bytesToDecrypt = Encoding.Default.GetBytes(PlainText);
            var decrypted =decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length);

            return Convert.ToBase64String(decrypted);
        }


        public static string RSADecrypt(string XmlPrivateKey, string EncryptedText)
        {
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(XmlPrivateKey));
            var decryptEngine = new OaepEncoding(new RsaEngine());
            decryptEngine.Init(false, privateKey);

            byte[] bytesToDecrypt = Convert.FromBase64String(EncryptedText);
            var decrypted = Encoding.Default.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));

            return decrypted;
        }


        public static string RSAEncryptLong(string XmlPublicKey, string PlainText)
        {
            byte[] publicInfoByte = Convert.FromBase64String(XmlPublicKey);
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(publicInfoByte);
            var decryptEngine = new OaepEncoding(new RsaEngine());
            decryptEngine.Init(true, publicKey);

            byte[] bytesToDecrypt = Encoding.Default.GetBytes(PlainText);

            int MaxPlainTextLength = Common.GetOEAPFixedMaxPlainTextLength(decryptEngine.GetOutputBlockSize());

            byte[] decrypted = null;
        
            int Times = (bytesToDecrypt.Length - 1)/ MaxPlainTextLength +1;

            List<byte> encryptedCache = new List<byte>();
            int Counter = 0;
            while (Counter < Times)
            {
                int RemainLength = bytesToDecrypt.Length - MaxPlainTextLength * Counter;
                int Length = MaxPlainTextLength > RemainLength ? RemainLength : MaxPlainTextLength;
                byte[] decryptedPatch = decryptEngine.ProcessBlock(bytesToDecrypt, MaxPlainTextLength * Counter, Length);
                encryptedCache.AddRange(decryptedPatch);

                Counter++;
            }

            decrypted = encryptedCache.ToArray();

            return Convert.ToBase64String(decrypted);
        }

        // to be done
        public static string RSADecryptLong(string XmlPrivateKey, string EncryptedText)
        {
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(XmlPrivateKey));
            var decryptEngine = new OaepEncoding(new RsaEngine());
            decryptEngine.Init(false, privateKey);

            int CipherLength = decryptEngine.GetInputBlockSize();

            byte[] bytesToDecrypt = Convert.FromBase64String(EncryptedText);

            byte[] decrypted = null;

            int Times = (bytesToDecrypt.Length - 1) / CipherLength + 1;

            List<byte> decryptedCache = new List<byte>();
            int Counter = 0;
            while (Counter < Times)
            {
                byte[] decryptedPatch = decryptEngine.ProcessBlock(bytesToDecrypt, CipherLength * Counter, CipherLength);
                decryptedCache.AddRange(decryptedPatch);

                Counter++;
            }

            decrypted = decryptedCache.ToArray();

            return Encoding.Default.GetString(decrypted);
        }
    }
}
