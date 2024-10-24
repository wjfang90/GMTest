using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.X9;

namespace BouncyCastle.Crypto.Test.SM {
    public class SM2Utils {
        public static void GenerateKeyPair() {
            SM2 sm2 = SM2.Instance;
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            BigInteger privateKey = ecpriv.D;
            ECPoint publicKey = ecpub.Q;

            System.Console.Out.WriteLine("公钥: " + Encoding.Default.GetString(Hex.Encode(publicKey.GetEncoded())).ToUpper());
            System.Console.Out.WriteLine("私钥: " + Encoding.Default.GetString(Hex.Encode(privateKey.ToByteArray())).ToUpper());
        }

        public static void GenerateKeyPair(out string publicKey, out string privateKey) {
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = SM2.Instance.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecprivateKeyParameters = (ECPrivateKeyParameters)asymmetricCipherKeyPair.Private;
            ECPublicKeyParameters ecpublicKeyParameters = (ECPublicKeyParameters)asymmetricCipherKeyPair.Public;
            BigInteger d = ecprivateKeyParameters.D;
            ECPoint q = ecpublicKeyParameters.Q;
            publicKey = Encoding.UTF8.GetString(Hex.Encode(q.GetEncoded())).ToUpper();
            privateKey = Encoding.UTF8.GetString(Hex.Encode(d.ToByteArray())).ToUpper();
        }

        /// <summary>
        /// SM2的结果为C1||C2||C3，为旧标准，新标准为C1||C3||C2
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string Encrypt(string publicKeyStr, string dataStr, Encoding encoding, SM2Model model = SM2Model.C1C3C2) {

            if (string.IsNullOrEmpty(publicKeyStr) || string.IsNullOrEmpty(dataStr)) {
                return null;
            }
            var publicKey = Hex.Decode(publicKeyStr);
            var data = encoding.GetBytes(dataStr);

            byte[] source = new byte[data.Length];
            Array.Copy(data, 0, source, 0, data.Length);

            Cipher cipher = new Cipher();
            SM2 sm2 = SM2.Instance;

            ECPoint userKey = sm2.ecc_curve.DecodePoint(publicKey);

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);

            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);

            string sc1 = encoding.GetString(Hex.Encode(c1.GetEncoded()));
            string sc2 = encoding.GetString(Hex.Encode(source));
            string sc3 = encoding.GetString(Hex.Encode(c3));

            switch (model) {
                case SM2Model.C1C2C3:
                    return (sc1 + sc2 + sc3).ToUpper();
                case SM2Model.C1C3C2:
                default:
                    return (sc1 + sc3 + sc2).ToUpper();
            }
        }

        /// <summary>
        /// SM2的结果为C1||C2||C3，为旧标准，新标准为C1||C3||C2
        /// </summary>
        /// <param name="privateKeyStr"></param>
        /// <param name="encryptedDataStr"></param>
        /// <param name="encoding"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        public static byte[] Decrypt(string privateKeyStr, string encryptedDataStr, Encoding encoding, SM2Model model = SM2Model.C1C3C2) {
            if (string.IsNullOrEmpty(privateKeyStr) || string.IsNullOrEmpty(encryptedDataStr)) {
                return null;
            }

            var privateKey = Hex.Decode(privateKeyStr);
            var encryptedData = Hex.Decode(encryptedDataStr);

            string data = encoding.GetString(Hex.Encode(encryptedData));
            byte[] c1Bytes = Hex.Decode(encoding.GetBytes(data.Substring(0, 130)));
            byte[] c2;
            byte[] c3;
            int c2Len = encryptedData.Length - 97;

            switch (model) {
                case SM2Model.C1C2C3:
                    c2 = Hex.Decode(encoding.GetBytes(data.Substring(130, 2 * c2Len)));
                    c3 = Hex.Decode(encoding.GetBytes(data.Substring(130 + 2 * c2Len, 64)));
                    break;
                case SM2Model.C1C3C2:
                default:
                    c3 = Hex.Decode(encoding.GetBytes(data.Substring(130, 64)));
                    c2 = Hex.Decode(encoding.GetBytes(data.Substring(130 + 64, 2 * c2Len)));
                    break;
            }


            SM2 sm2 = SM2.Instance;
            BigInteger userD = new BigInteger(1, privateKey);

            ECPoint c1 = sm2.ecc_curve.DecodePoint(c1Bytes);
            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            return c2;
        }
        /// <summary>
        /// SM2的结果新标准为C1||C3||C2
        /// </summary>
        /// <param name="privateKeyStr"></param>
        /// <param name="encryptedDataStr"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string Decrypt(string privateKeyStr, string encryptedDataStr, Encoding encoding) {
            var res = Decrypt(privateKeyStr, encryptedDataStr, encoding, SM2Model.C1C3C2);
            return encoding.GetString(res);
        }
    }

    /// <summary>
    /// SM2 加密结果顺序
    /// </summary>
    public enum SM2Model {
        /// <summary>
        /// 旧标准
        /// </summary>
        C1C2C3 = 1,
        /// <summary>
        /// 新标准
        /// </summary>
        C1C3C2 = 2
    }
}
