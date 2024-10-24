using BouncyCastle.Crypto.Test.SM;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyCastle.Crypto.Test {
    internal class Program {
        static void Main(string[] args) {

            CustomSM2Test();

            Console.ReadKey();
        }

        /// <summary>
        /// 依赖 BouncyCastle.Crypto ，这是旧版本，有安全漏洞，建议使用最新版本BouncyCastle.Cryptography
        /// </summary>
        static void CustomSM2Test() {
            string privateKey = string.Empty;
            string publicKey = string.Empty;
            SM2Utils.GenerateKeyPair(out publicKey, out privateKey);

            //// 国密规范正式私钥  
            //privateKey = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
            //// 国密规范正式公钥  
            //publicKey = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";

            string toEncryptData = "hello fang";

            var encryptDataStr = SM2Utils.Encrypt(publicKey, toEncryptData, Encoding.UTF8);
            Console.WriteLine($"encrypt data:{encryptDataStr}");

            var decryptData = SM2Utils.Decrypt(privateKey, encryptDataStr, Encoding.UTF8);
            Console.WriteLine($"decrypt data:{decryptData}");
        }
    }
}
