using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TestCSharpRSAConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            String OriginWord = "test 今天dddddddddddddddssssssssssssssssswwwwwwwwwwwa很好";

            Console.WriteLine(Common.RSAPublicKey.Replace("\r", ""));
            String EncryptedWord = RSAUtil.RSAEncryptLong(Common.RSAPublicKey.Replace("\r",""),OriginWord);

            String DecryptedWord = RSAUtil.RSADecryptLong(Common.RSAPrivateKey.Replace("\r", ""), EncryptedWord);

            Console.WriteLine("OriginWord : " + OriginWord);
            Console.WriteLine("RecongizedWord : "+DecryptedWord);
        }
    }
}
