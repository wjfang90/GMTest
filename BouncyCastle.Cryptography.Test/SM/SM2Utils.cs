using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyCastle.Cryptography.Test.SM {

    public class SM2Utils {
        private static readonly X9ECParameters x9 = GMNamedCurves.GetByName("SM2P256V1");
        private const int RS_LEN = 32;

        #region ASN.1 DER编码格式转换 
        public static byte[] RsAsn1ToPlainByteArray(byte[] signDer) {
            Asn1Sequence seq = Asn1Sequence.GetInstance(signDer);
            byte[] r = BigIntToFixexLengthBytes(DerInteger.GetInstance(seq[0]).Value);
            byte[] s = BigIntToFixexLengthBytes(DerInteger.GetInstance(seq[1]).Value);
            byte[] result = new byte[RS_LEN * 2];
            Buffer.BlockCopy(r, 0, result, 0, r.Length);
            Buffer.BlockCopy(s, 0, result, RS_LEN, s.Length);
            return result;
        }

        public static byte[] RsAsn1FromPlainByteArray(byte[] sign) {
            if (sign.Length != RS_LEN * 2) throw new ArgumentException("err rs. ");
            BigInteger r = new(1, Arrays.CopyOfRange(sign, 0, RS_LEN));
            BigInteger s = new(1, Arrays.CopyOfRange(sign, RS_LEN, RS_LEN * 2));
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(new DerInteger(r));
            v.Add(new DerInteger(s));
            try {
                return new DerSequence(v).GetEncoded("DER");
            }
            catch (IOException e) {
                return new byte[0];
            }
        }
        private static byte[] BigIntToFixexLengthBytes(BigInteger rOrS) {
            byte[] rs = rOrS.ToByteArray();
            if (rs.Length == RS_LEN) return rs;
            else if (rs.Length == RS_LEN + 1 && rs[0] == 0) return Arrays.CopyOfRange(rs, 1, RS_LEN + 1);
            else if (rs.Length < RS_LEN) {
                byte[] result = new byte[RS_LEN];
                Arrays.Fill(result, (byte)0);
                Buffer.BlockCopy(rs, 0, result, RS_LEN - rs.Length, rs.Length);
                return result;
            }
            else {
                throw new ArgumentException("err rs: " + Hex.ToHexString(rs));
            }
        }
        #endregion

        #region 密钥生成
        public static (byte[] PublicKey, byte[] PrivateKey) SM2KeyGen() {
            ECKeyPairGenerator eCKeyPairGenerator = new();
            eCKeyPairGenerator.Init(new ECKeyGenerationParameters(new ECDomainParameters(x9), new SecureRandom()));
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = eCKeyPairGenerator.GenerateKeyPair();
            var publicKey = ((ECPublicKeyParameters)asymmetricCipherKeyPair.Public).Q.GetEncoded(compressed: false);
            var privateKey = ((ECPrivateKeyParameters)asymmetricCipherKeyPair.Private).D.ToByteArray();
            return (publicKey, privateKey);
        }
        #endregion

        #region 签名和验证
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data">待签名的数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="userId">userId</param>
        /// <returns></returns>
        public static byte[] SM2Sign(byte[] data, byte[] privateKey, byte[]? userId = null) {
            SM2Signer sM2Signer = new(new SM3Digest());
            ICipherParameters parameters = new ParametersWithRandom(new ECPrivateKeyParameters(new BigInteger(1, privateKey), new ECDomainParameters(x9)));
            if (userId != null) {
                parameters = new ParametersWithID(parameters, userId);
            }

            sM2Signer.Init(forSigning: true, parameters);
            sM2Signer.BlockUpdate(data, 0, data.Length);

            var dataSignedDer = sM2Signer.GenerateSignature();
            var dataSigned = RsAsn1ToPlainByteArray(dataSignedDer);
            return dataSigned;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data">待签名的数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="dataSigned">待签名数据的签名</param>
        /// <param name="userId">userId</param>
        /// <returns></returns>
        public static bool SM2VerifySign(byte[] data, byte[] publicKey, byte[] dataSigned, byte[]? userId = null) {
            var dataSignedDer = RsAsn1FromPlainByteArray(dataSigned);

            SM2Signer sM2Signer = new(new SM3Digest());
            ICipherParameters parameters = new ECPublicKeyParameters(x9.Curve.DecodePoint(publicKey), new ECDomainParameters(x9));
            if (userId != null) {
                parameters = new ParametersWithID(parameters, userId);
            }

            sM2Signer.Init(forSigning: false, parameters);
            sM2Signer.BlockUpdate(data, 0, data.Length);
            return sM2Signer.VerifySignature(dataSignedDer);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data">待签名的数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="userId">userId</param>
        /// <returns></returns>
        public static byte[] SM2SignByDataHash(byte[] data, byte[] privateKey, byte[]? userId = null) {
            var dataHash = SM3Utils.SM3HashData(data);

            SM2Signer sM2Signer = new(new SM3Digest());
            ICipherParameters parameters = new ParametersWithRandom(new ECPrivateKeyParameters(new BigInteger(1, privateKey), new ECDomainParameters(x9)));
            if (userId != null) {
                parameters = new ParametersWithID(parameters, userId);
            }

            sM2Signer.Init(forSigning: true, parameters);
            sM2Signer.BlockUpdate(dataHash, 0, dataHash.Length);

            var dataSignedDer = sM2Signer.GenerateSignature();
            var dataSigned = RsAsn1ToPlainByteArray(dataSignedDer);
            return dataSigned;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data">待签名的数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="dataSigned">待签名数据的签名</param>
        /// <param name="userId">userId</param>
        /// <returns></returns>
        public static bool SM2VerifySignByDataHash(byte[] data, byte[] publicKey, byte[] dataSigned, byte[]? userId = null) {
            var dataSignedDer = RsAsn1FromPlainByteArray(dataSigned);

            var dataHash = SM3Utils.SM3HashData(data);

            SM2Signer sM2Signer = new(new SM3Digest());
            ICipherParameters parameters = new ECPublicKeyParameters(x9.Curve.DecodePoint(publicKey), new ECDomainParameters(x9));
            if (userId != null) {
                parameters = new ParametersWithID(parameters, userId);
            }

            sM2Signer.Init(forSigning: false, parameters);
            sM2Signer.BlockUpdate(dataHash, 0, dataHash.Length);
            return sM2Signer.VerifySignature(dataSignedDer);
        }
        #endregion

        #region 加密和解密
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data">待加密的数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="userId">userId</param>
        /// <param name="mode">SM2加密解密结果连接模式:C1C2C3或C1C3C2</param>
        /// <returns></returns>
        public static byte[] SM2Encrypt(byte[] data, byte[] publicKey, byte[]? userId = null, SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2) {
            SM2Engine sM2Engine = new(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            ICipherParameters cipherParameters = new ParametersWithRandom(new ECPublicKeyParameters(x9.Curve.DecodePoint(publicKey), new ECDomainParameters(x9)));
            if (userId != null) {
                cipherParameters = new ParametersWithID(cipherParameters, userId);
            }

            sM2Engine.Init(forEncryption: true, cipherParameters);
            data = sM2Engine.ProcessBlock(data, 0, data.Length);
            if (mode == SM2Engine.Mode.C1C2C3) {
                data = C132ToC123(data);
            }

            return data;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="dataEncrypted">待解决的数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="userId">userId</param>
        /// <param name="mode">SM2加密解密结果连接模式:C1C2C3或C1C3C2</param>
        /// <returns></returns>
        public static byte[] SM2Decrypt(byte[] dataEncrypted, byte[] privateKey, byte[]? userId = null, SM2Engine.Mode mode = SM2Engine.Mode.C1C3C2) {
            if (mode == SM2Engine.Mode.C1C2C3) {
                dataEncrypted = C123ToC132(dataEncrypted);
            }

            SM2Engine sM2Engine = new(new SM3Digest(), SM2Engine.Mode.C1C3C2);
            ICipherParameters cipherParameters = new ECPrivateKeyParameters(new BigInteger(1, privateKey), new ECDomainParameters(x9));
            if (userId != null) {
                cipherParameters = new ParametersWithID(cipherParameters, userId);
            }

            sM2Engine.Init(forEncryption: false, cipherParameters);
            return sM2Engine.ProcessBlock(dataEncrypted, 0, dataEncrypted.Length);
        }

        private static byte[] C123ToC132(byte[] c1c2c3) {
            int num = (x9.Curve.FieldSize + 7 >> 3 << 1) + 1;
            byte[] array = new byte[c1c2c3.Length];
            Array.Copy(c1c2c3, 0, array, 0, num);
            Array.Copy(c1c2c3, c1c2c3.Length - 32, array, num, 32);
            Array.Copy(c1c2c3, num, array, num + 32, c1c2c3.Length - num - 32);
            return array;
        }
        private static byte[] C132ToC123(byte[] c1c3c2) {
            int num = (x9.Curve.FieldSize + 7 >> 3 << 1) + 1;
            byte[] array = new byte[c1c3c2.Length];
            Array.Copy(c1c3c2, 0, array, 0, num);
            Array.Copy(c1c3c2, num + 32, array, num, c1c3c2.Length - num - 32);
            Array.Copy(c1c3c2, num, array, c1c3c2.Length - 32, 32);
            return array;
        }
        #endregion
    }
}
