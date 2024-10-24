using BouncyCastle.Crypto.Test.SM;
using KYSharp.SM.Core.Test.Extends;
using KYSharp.SM.Core.Test.SM.SM2;
using KYSharp.SM.Core.Test.SM.SM3;
using KYSharp.SM.Core.Test.SM.SM4;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace KYSharp.SM.Core.Test {
    internal class Program {
        static void Main(string[] args) {

            KYSharpSM2Test();
            CustomSM2Test();
            CommonSM2Test();

            KYSharpSM3Test();
            CustomSM3Test();
            CommonSM3Test();

            CommonSignSM3WithSM2Test();

            KYSharpSM4Test();
            CustomSM4Test();
            CommonSM4Test();

            Console.ReadKey();
        }

        static void KYSharpSM2Test() {
            string privateKey = string.Empty;
            string publicKey = string.Empty;
            SM2Utils.GenerateKeyPair(out publicKey, out privateKey);

            //// 国密规范正式私钥  
            //privateKey = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
            //// 国密规范正式公钥  
            //publicKey = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";

            string toEncryptData = "测试hello fang";

            Console.WriteLine("\n********* KYSharpSM2 c1c2c3 ********\n");

            var encryptDataStr = SM2Utils.Encrypt_Hex(publicKey, toEncryptData, Encoding.UTF8);
            Console.WriteLine($"encrypt hex data:{encryptDataStr}\n");

            var encryptDataArray = SM2Utils.Encrypt(Hex.Decode(publicKey), Encoding.UTF8.GetBytes(toEncryptData));
            Console.WriteLine($"encrypt data:{Encoding.UTF8.GetString(Hex.Encode(encryptDataArray))}\n");


            var decryptDataStr = SM2Utils.Decrypt_Hex(privateKey, encryptDataStr, Encoding.UTF8);
            Console.WriteLine($"decrypt hex data:{decryptDataStr} \n");

            var decryptDataArray = SM2Utils.Decrypt(Hex.Decode(privateKey), encryptDataArray);
            Console.WriteLine($"decrypt data:{Encoding.UTF8.GetString(decryptDataArray)}\n");


            Console.WriteLine("\n********* KYSharpSM2 c1c3c2 ********\n");



            var encryptDataArray2 = SM2Utils.Encrypt(Hex.Decode(publicKey), Encoding.UTF8.GetBytes(toEncryptData));
            encryptDataArray2 = SMExtend.ChangeC1C2C3ToC1C3C2(encryptDataArray2);
            Console.WriteLine($"encrypt data:{Encoding.UTF8.GetString(Hex.Encode(encryptDataArray2))} \n");


            encryptDataArray2 = SMExtend.ChangeC1C3C2ToC1C2C3(encryptDataArray2);
            var decryptDataArray2 = SM2Utils.Decrypt(Hex.Decode(privateKey), encryptDataArray2);
            Console.WriteLine($"decrypt data:{Encoding.UTF8.GetString(decryptDataArray2)} \n");
        }

        static void CustomSM2Test() {
            string privateKey = string.Empty;
            string publicKey = string.Empty;
            SM.SM2.SM2Utils.GenerateKeyPair(out publicKey, out privateKey);

            //// 国密规范正式私钥  
            //privateKey = "3690655E33D5EA3D9A4AE1A1ADD766FDEA045CDEAA43A9206FB8C430CEFE0D94";
            //// 国密规范正式公钥  
            //publicKey = "04F6E0C3345AE42B51E06BF50B98834988D54EBC7460FE135A48171BC0629EAE205EEDE253A530608178A98F1E19BB737302813BA39ED3FA3C51639D7A20C7391A";

            string toEncryptData = "测试hello fang";
            Console.WriteLine("\n********* CustomSM2 c1c3c2 ********\n");
            var encryptDataStr = SM.SM2.SM2Utils.Encrypt(publicKey, toEncryptData, Encoding.UTF8);
            Console.WriteLine($"encrypt data:{encryptDataStr} \n");

            var decryptDataStr = SM.SM2.SM2Utils.Decrypt(privateKey, encryptDataStr, Encoding.UTF8);
            Console.WriteLine($"decrypt data:{decryptDataStr} \n");

            Console.WriteLine("\n********* CustomSM2 c1c2c3 ********\n");
            var encryptDataStr2 = SM.SM2.SM2Utils.Encrypt(publicKey, toEncryptData, Encoding.UTF8, SM2Model.C1C2C3);
            Console.WriteLine($"encrypt data:{encryptDataStr2} \n");

            var decryptDataArray2 = SM.SM2.SM2Utils.Decrypt(privateKey, encryptDataStr2, Encoding.UTF8, SM2Model.C1C2C3);
            Console.WriteLine($"decrypt data:{Encoding.UTF8.GetString(decryptDataArray2)} \n");
        }

        static void CommonSM2Test() {

            string toEncryptData = "测试hello fang";
            Console.WriteLine("\n*******CommonGMUtils SM2 test***********\n");


            Console.WriteLine("由d生成privatekey\n");
            var d = "097b5230ef27c7df0fa768289d13ad4e8a96266f0fcb8de40d5942af4293a54a";
            ECPrivateKeyParameters cepPrivateKey = GMCommonUtils.GetPrivatekeyFromD(d);
            Console.WriteLine($"privatekey hex={Hex.ToHexString(cepPrivateKey.D.ToByteArray())}\n");
            Console.WriteLine($"privatekey={cepPrivateKey.D.ToString(16)}\n");

            //公钥X坐标PublicKeyXHex: 59cf9940ea0809a97b1cbffbb3e9d96d0fe842c1335418280bfc51dd4e08a5d4
            //公钥Y坐标PublicKeyYHex: 9a7f77c578644050e09a9adc4245d1e6eba97554bc8ffd4fe15a78f37f891ff8
            Console.WriteLine("公钥坐标生成publickey\n");
            string x = "59cf9940ea0809a97b1cbffbb3e9d96d0fe842c1335418280bfc51dd4e08a5d4";
            string y = "9a7f77c578644050e09a9adc4245d1e6eba97554bc8ffd4fe15a78f37f891ff8";
            var ecpPublickeyParameter = GMCommonUtils.GetPublickeyFromXY(x, y);
            Console.WriteLine($"publickey={ecpPublickeyParameter.Q}\n");

            //Console.WriteLine("cer生成publickey");
            //cer生成公钥
            //AsymmetricKeyParameter publicKeyX509 = GMCommonUtils.GetPublickeyFromX509File(new FileInfo("d:/certs/69629141652.cer"));
            //Console.WriteLine($"publickey={(publicKeyX509 as ECPublicKeyParameters)?.Q}");

            //读取.SM2 证书文件
            string sm2 = "MIIDHQIBATBHBgoqgRzPVQYBBAIBBgcqgRzPVQFoBDDW5/I9kZhObxXE9Vh1CzHdZhIhxn+3byBU\nUrzmGRKbDRMgI3hJKdvpqWkM5G4LNcIwggLNBgoqgRzPVQYBBAIBBIICvTCCArkwggJdoAMCAQIC\nBRA2QSlgMAwGCCqBHM9VAYN1BQAwXDELMAkGA1UEBhMCQ04xMDAuBgNVBAoMJ0NoaW5hIEZpbmFu\nY2lhbCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEbMBkGA1UEAwwSQ0ZDQSBURVNUIFNNMiBPQ0Ex\nMB4XDTE4MTEyNjEwMTQxNVoXDTIwMTEyNjEwMTQxNVowcjELMAkGA1UEBhMCY24xEjAQBgNVBAoM\nCUNGQ0EgT0NBMTEOMAwGA1UECwwFQ1VQUkExFDASBgNVBAsMC0VudGVycHJpc2VzMSkwJwYDVQQD\nDCAwNDFAWnRlc3RAMDAwMTAwMDA6U0lHTkAwMDAwMDAwMTBZMBMGByqGSM49AgEGCCqBHM9VAYIt\nA0IABDRNKhvnjaMUShsM4MJ330WhyOwpZEHoAGfqxFGX+rcL9x069dyrmiF3+2ezwSNh1/6YqfFZ\nX9koM9zE5RG4USmjgfMwgfAwHwYDVR0jBBgwFoAUa/4Y2o9COqa4bbMuiIM6NKLBMOEwSAYDVR0g\nBEEwPzA9BghggRyG7yoBATAxMC8GCCsGAQUFBwIBFiNodHRwOi8vd3d3LmNmY2EuY29tLmNuL3Vz\nL3VzLTE0Lmh0bTA4BgNVHR8EMTAvMC2gK6AphidodHRwOi8vdWNybC5jZmNhLmNvbS5jbi9TTTIv\nY3JsNDI4NS5jcmwwCwYDVR0PBAQDAgPoMB0GA1UdDgQWBBREhx9VlDdMIdIbhAxKnGhPx8FcHDAd\nBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDAYIKoEcz1UBg3UFAANIADBFAiEAgWvQi3h6\niW4jgF4huuXfhWInJmTTYr2EIAdG8V4M8fYCIBixygdmfPL9szcK2pzCYmIb6CBzo5SMv50Odycc\nVfY6";
            var base64Str = Convert.FromBase64String(sm2);
            string pwd = "cfca1234";

            var sm2Cert = GMCommonUtils.ReadSm2File(base64Str, pwd);
            var sm2CertPublickey = (sm2Cert.PublicKey as ECPublicKeyParameters)?.Q;
            var sm2CertPrivatekey = Hex.ToHexString((sm2Cert.PrivateKey as ECPrivateKeyParameters)?.D.ToByteArray());

            Console.WriteLine("****************读取.SM2 证书文件**********************");
            Console.WriteLine($"sm2 file publickey hex = {Hex.ToHexString(sm2CertPublickey?.GetEncoded(false))}\n");//验证签名时，publickey 要去掉开关的04
            Console.WriteLine($"sm2 file publickey = {sm2CertPublickey?.ToString()}\n");
            Console.WriteLine($"sm2 file privatekey = {sm2CertPrivatekey}\n");
            Console.WriteLine($"sm2 file certid = {sm2Cert.CertId}\n");


            AsymmetricCipherKeyPair kp = GMCommonUtils.GenerateKeyPair();
            AsymmetricKeyParameter publicKey = kp.Public;
            AsymmetricKeyParameter privateKey = kp.Private;

            var encryptData = GMCommonUtils.Sm2Encrypt(Encoding.UTF8.GetBytes(toEncryptData), publicKey);

            Console.WriteLine($"encrypt data={Hex.ToHexString(encryptData)}\n");
            var decryptData = GMCommonUtils.Sm2Decrypt(encryptData, privateKey);
            Console.WriteLine($"decrypt data={Encoding.UTF8.GetString(decryptData)}\n");

        }


        static void KYSharpSM3Test() {
            var input = "测试hello fang";

            var res = new SM3().Encrypt(input);

            Console.WriteLine("\n************KYSharp SM3 ***************\n");
            Console.WriteLine($"SM3 hash={res} \n");
        }

        static void CustomSM3Test() {
            var input = "测试hello fang";
            var res = SM3Digest.DoHash(input, Encoding.UTF8);
            Console.WriteLine("\n************* Custom SM3 ************\n");
            Console.WriteLine($"SM3 hash={res}\n");
        }

        static void CommonSM3Test() {
            var input = "测试hello fang";

            var res = GMCommonUtils.Sm3(input);
            Console.WriteLine("\n************* Common SM3 ************\n");
            Console.WriteLine($"SM3 hash={res}\n");
        }

        static void CommonSignSM3WithSM2Test() {
            var input = "测试hello fang";

            var userid = "userId";
            var keyPair = GMCommonUtils.GenerateKeyPair();

            var resSign = GMCommonUtils.SignSm3WithSm2(input, userid, keyPair.Private);
            Console.WriteLine("\n************* Common SignSm3WithSm2 ************\n");
            Console.WriteLine($"SignSm3WithSm2 hash={resSign}\n");

            var validValue = GMCommonUtils.VerifySm3WithSm2(input, userid, resSign, keyPair.Public);
            Console.WriteLine($"VerifySignSm3WithSm2 result={validValue}\n");

            //java 签名结果 GeStRluidiYhbIlQA4ngbD7JP1Fvv8HxjvJjASUegF3sp0c3st+iH+pVSQGYv066fp0EaTvmrR9jD6+YMSL8bw==

            input = "签名报文字符串123456";
            userid = "123456789";
            var publicKey = "3D3AA4732B56DFCC643CF1B0ABAF75EF9EC16A756C18967090E8250E0A49915EEFDD5CBE16BB34CC93B20D3EFB4C842FFCE13887FE211DAE33DFD2AD025265D6";

            var signValue = "aBqRJHtnPJvYJNL6C+KoH0BGYmO+3tRJ/IK5TYHuxdqcD41Nr5z2/bq1zx3m2nrPxB/imLpIUQmR/EpubiS/Ig==";//true
            //java 签名结果 
            //signValue = "GeStRluidiYhbIlQA4ngbD7JP1Fvv8HxjvJjASUegF3sp0c3st+iH+pVSQGYv066fp0EaTvmrR9jD6+YMSL8bw==";//false
            //signValue = "GeStRluidiYhbIlQA4nqbD7JP1Fvv8HxjvJjASUeqF3sp0c3st+iH+pVSQGYv066fp0EaTvmrR9jD6+YMSL8bw==";//false
            //signValue = "GeStRluidiYhbIlQA4ngbD7JP1Fvv8HxjvJjASUeqF3sp0c3st+iH+pVSQGYv066fp0EaTvmrR9jD6+YMSL8bw==";//false
            //signValue = "GeStRluidiYhbIlQA4nqbD7JP1Fvv8HxjvJjASUegF3sp0c3st+iH+pVSQGYv066fp0EaTvmrR9jD6+YMSL8bw==";//false

            input = "1977年，三位数学家Rivest、Shamir 和 Adleman 设计了一种算法";
            publicKey = Hex.ToHexString(Convert.FromBase64String("agqV3MU7WaQCpAHHhVV8GDolxHqx3PfLbSEOhmtz1U271UjRN6j0I4D4Cn/MEpbMrl+SAsFHWwaXd5+SoLZq6Q=="));
            signValue = "F4261292B3BE90400DB813085A3BE0329021073FF2E792CD0C2D4F2E4443EE8C";

            var validValue2 = GMCommonUtils.VerifySm3WithSm2(input, userid, signValue, publicKey, true);

            Console.WriteLine($"VerifySignSm3WithSm2 result={validValue2}\n");

        }

        /// <summary>
        /// SM4 CBC模式代码有问题
        /// </summary>
        static void KYSharpSM4Test() {
            var input = "测试hello fang";
            var sm4 = new SM4Utils();
            sm4.secretKey = "JeF8U9wHFOMfs2Y8";//长度16
            sm4.iv = "UISwD9fW6cFh9SNS";//长度16
            sm4.hexString = false;

            Console.WriteLine("\n******** KYSharpSM4  ECB ********\n");
            var encryptEcb = sm4.Encrypt_ECB(input);
            Console.WriteLine($"encrypt ecb data = {encryptEcb}\n");

            var decryptEcb = sm4.Decrypt_ECB(encryptEcb);
            Console.WriteLine($"decrypt ecb data = {decryptEcb}\n");


            Console.WriteLine("\n******** KYSharpSM4  CBC ********\n");
            //var encryptCbc = sm4.Encrypt_CBC(input);//代码有问题，修复地址 https://www.cnblogs.com/zhoading/p/14054599.html
            //Console.WriteLine($"encrypt cbc data = {encryptCbc}\n");

            //var decryptCbc = sm4.Decrypt_CBC(encryptCbc);
            //Console.WriteLine($"decrypt cbc data = {decryptCbc}\n");
        }

        static void CustomSM4Test() {
            var input = "测试hello fang";
            var secretKey = "fang_secret_key1";//长度16
            var iv = "fang_iv_12345678";//长度16

            Console.WriteLine("\n******** CustomSM4  ECB padding ********\n");
            var encryptEcb = SM.SM4.SM4Utils.EncryptECB(input, secretKey);
            Console.WriteLine($"encrypt ecb data = {encryptEcb}\n");

            var decryptEcb = SM.SM4.SM4Utils.DecryptECB(encryptEcb, secretKey);
            Console.WriteLine($"decrypt ecb data = {decryptEcb}\n");


            Console.WriteLine("\n******** CustomSM4  CBC padding ********\n");
            var encryptCbc = SM.SM4.SM4Utils.EncryptCBC(input, secretKey, iv);
            Console.WriteLine($"encrypt cbc data = {encryptCbc}\n");

            var decryptCbc = SM.SM4.SM4Utils.DecryptCBC(encryptCbc, secretKey, iv);
            Console.WriteLine($"decrypt cbc data = {decryptCbc}\n");
        }

        static void CommonSM4Test() {

            string input = "测试hello fang";//
            string secretKey = "fang_secret_key1";//长度16
            string iv = "fang_iv_12345678";//长度16

            Console.WriteLine("\n******** CommonSM4  ECB no padding ********\n");
            var encryptEcb = GMCommonUtils.Sm4EncryptECB(secretKey, input, PaddingMode.None);
            Console.WriteLine($"encrypt ecb hex data = {encryptEcb}\n");

            var decryptEcb = GMCommonUtils.Sm4DecryptECB(secretKey, encryptEcb, PaddingMode.None);
            Console.WriteLine($"decrypt ecb data = {decryptEcb}\n");


            Console.WriteLine("\n******** CommonSM4  ECB PKCS7 padding ********\n");
            var encryptEcbPadding = GMCommonUtils.Sm4EncryptECB(secretKey, input);
            Console.WriteLine($"encrypt ecb hex data = {encryptEcbPadding}\n");

            var decryptEcbPadding = GMCommonUtils.Sm4DecryptECB(secretKey, encryptEcbPadding);
            Console.WriteLine($"decrypt ecb data = {decryptEcbPadding}\n");


            Console.WriteLine("\n******** CommonSM4  CBC no padding********\n");
            var encryptCbc = GMCommonUtils.Sm4EncryptCBC(secretKey, input, null, PaddingMode.None);
            Console.WriteLine($"encrypt cbc hex data = {encryptCbc}\n");

            var decryptCbc = GMCommonUtils.Sm4DecryptCBC(secretKey, encryptCbc, null, PaddingMode.None);
            Console.WriteLine($"decrypt cbc data = {decryptCbc}\n");


            Console.WriteLine("\n******** CommonSM4  CBC PKCS7 padding********\n");
            var encryptCbcPadding = GMCommonUtils.Sm4EncryptCBC(secretKey, input, iv);
            Console.WriteLine($"encrypt cbc hex data = {encryptCbcPadding}\n");

            var decryptCbcPadding = GMCommonUtils.Sm4DecryptCBC(secretKey, encryptCbcPadding, iv);
            Console.WriteLine($"decrypt cbc data = {decryptCbcPadding}\n");
        }
    }
}
