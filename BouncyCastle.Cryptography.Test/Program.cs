using BouncyCastle.Cryptography.Test.SM;
using Org.BouncyCastle.Utilities.Encoders;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;

namespace BouncyCastle.Cryptography.Test {
    internal class Program {
        static void Main(string[] args) {

            Sm2Test();

            SM2SignTest();

            SM3Test();

            SM4Test();

            Console.ReadKey();
        }

        static void Sm2Test() {

            var toEncryptData = Encoding.UTF8.GetBytes("测试hello fang");
            var (publicKey, privateKey) = SM2Utils.SM2KeyGen();

            //// 国密规范正式私钥  
            //privateKey = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
            //// 国密规范正式公钥  
            //publicKey = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";
            //publicKey = Hex.Decode("04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A");
            //privateKey = Hex.Decode("3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94");
            Console.WriteLine("\n********* SM2 ********\n");

            Console.WriteLine($"publickey = {Hex.ToHexString(publicKey)}\n");
            Console.WriteLine($"privatekey = {Hex.ToHexString(privateKey)}\n");

            Console.WriteLine("\n********* SM2 c1c3c2 ********\n");

            var encryptData = SM2Utils.SM2Encrypt(toEncryptData, publicKey);

            Console.WriteLine($"encrypt data hex : {Hex.ToHexString(encryptData)}\n");

            var decryptData = SM2Utils.SM2Decrypt(encryptData, privateKey);
            Console.WriteLine($"decrypt data : {Encoding.UTF8.GetString(decryptData)}\n");


            Console.WriteLine("\n********* SM2 c1c2c3 ********\n");

            var encryptData1 = SM2Utils.SM2Encrypt(toEncryptData, publicKey, mode: SM2Engine.Mode.C1C2C3);

            Console.WriteLine($"encrypt data hex: {Hex.ToHexString(encryptData1)}\n");

            var decryptData1 = SM2Utils.SM2Decrypt(encryptData1, privateKey, mode: SM2Engine.Mode.C1C2C3);
            Console.WriteLine($"decrypt data: {Encoding.UTF8.GetString(decryptData1)}\n");
        }

        static void SM2SignTest() {
            var userId = Encoding.UTF8.GetBytes("userid_fang");
            var toSignData = Encoding.UTF8.GetBytes("测试hello fang");

            var (publicKey, privateKey) = SM2Utils.SM2KeyGen();


            Console.WriteLine("\n********** SM2 sign data and valid sign **********\n");

            var signData = SM2Utils.SM2Sign(toSignData, privateKey, userId);
            var validSign = SM2Utils.SM2VerifySign(toSignData, publicKey, signData, userId);

            Console.WriteLine($"valid sign : {validSign}");

            Console.WriteLine("\n********** SM2withSM3 sign by hash data and valid sign **********\n");
            var signDataByHashData = SM2Utils.SM2SignByDataHash(toSignData, privateKey);
            var validSignByHashData = SM2Utils.SM2VerifySignByDataHash(toSignData, publicKey, signDataByHashData);

            Console.WriteLine($"valid sign by hash data: {validSignByHashData}");
        }

        static void SM3Test() {
            var toEncryptData = Encoding.UTF8.GetBytes("测试hello fang");

            Console.WriteLine("\n********* SM3 ********\n");

            var key = SM3Utils.SM3KeyGen();
            Console.WriteLine($"SM3 key hex = {Hex.ToHexString(key)}\n");

            var sm3Data = SM3Utils.SM3HashData(toEncryptData);
            Console.WriteLine($"encrypt data hex : {Hex.ToHexString(sm3Data)}\n");

        }

        static void SM4Test() {
            var toEncryptData = Encoding.UTF8.GetBytes("测试hello fang");

            var pwd = "fang_test";
            var (key, iv) = SM4Utils.SM4KeyGen(pwd);

            Console.WriteLine("\n********* SM4 ********\n");
            Console.WriteLine($"SM4 hex key = {Hex.ToHexString(key)}, iv = {Hex.ToHexString(iv)}\n");

            Console.WriteLine("\n********* SM4 CBC padding ********\n");

            var cbcEncryptData = SM4Utils.SM4CBCEncrypt(toEncryptData, key, iv);
            Console.WriteLine($"encrypt data = {Hex.ToHexString(cbcEncryptData)}\n");

            var cbcDecryptData = SM4Utils.SM4CBCDecrypt(cbcEncryptData, key, iv);
            Console.WriteLine($"decrypt data = {Encoding.UTF8.GetString(cbcDecryptData)}\n");

            Console.WriteLine("\n********* SM4 ECB padding ********\n");
            var ecbEncryptData = SM4Utils.SM4ECBEncrypt(toEncryptData, key);
            Console.WriteLine($"encrypt data = {Hex.ToHexString(ecbEncryptData)}\n");

            var ecbDencryptData = SM4Utils.SM4ECBDecrypt(ecbEncryptData, key);
            Console.WriteLine($"decrypt data = {Encoding.UTF8.GetString(ecbDencryptData)}\n");

        }
    }
}
