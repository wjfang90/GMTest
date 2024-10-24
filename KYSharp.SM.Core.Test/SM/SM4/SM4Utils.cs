using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KYSharp.SM.Core.Test.SM.SM4 {
    public class SM4Utils {


        /// <summary>
        /// 
        /// </summary>
        /// <param name="plainText">要加密的数据</param>
        /// <param name="secretKey">key</param>
        /// <param name="isHexString">secretKey 是否是16进制字符串</param>
        /// <returns>加密的数据，16进制字符串</returns>
        public static string EncryptECB(string plainText, string secretKey, bool isHexString = false) {
            SM4Context ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            if (isHexString) {
                keyBytes = Hex.Decode(secretKey);
            }
            else {
                keyBytes = Encoding.UTF8.GetBytes(secretKey);
            }

            SM4 sm4 = new SM4();
            sm4.Sm4SetKeyEnc(ctx, keyBytes);
            byte[] encrypted = sm4.Sm4CryptEcb(ctx, Encoding.UTF8.GetBytes(plainText));

            string cipherText = Hex.ToHexString(encrypted);
            //string cipherText = Encoding.UTF8.GetString(Hex.Encode(encrypted));//等效方法Hex.ToHexString()
            return cipherText;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherText">待解密的数据，16进制字符串</param>
        /// <param name="secretKey">key</param>
        /// <param name="isHexString">secretKey 是否是16进制字符串</param>
        /// <returns></returns>
        public static string DecryptECB(string cipherText, string secretKey, bool isHexString = false) {
            SM4Context ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            if (isHexString) {
                keyBytes = Hex.Decode(secretKey);
            }
            else {
                keyBytes = Encoding.UTF8.GetBytes(secretKey);
            }

            SM4 sm4 = new SM4();
            sm4.Sm4SetKeyDec(ctx, keyBytes);
            byte[] decrypted = sm4.Sm4CryptEcb(ctx, Hex.Decode(cipherText));
            return Encoding.UTF8.GetString(decrypted);
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="plainText">要加密的数据</param>
        /// <param name="secretKey">key</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexString">secretKey和iv 是否是16进制字符串</param>
        /// <returns>加密的数据，16进制字符串</returns>
        public static string EncryptCBC(string plainText, string secretKey, string iv, bool isHexString = false) {
            SM4Context ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (isHexString) {
                keyBytes = Hex.Decode(secretKey);
                ivBytes = Hex.Decode(iv);
            }
            else {
                keyBytes = Encoding.UTF8.GetBytes(secretKey);
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }

            SM4 sm4 = new SM4();
            sm4.Sm4SetKeyEnc(ctx, keyBytes);
            byte[] encrypted = sm4.Sm4CryptCbc(ctx, ivBytes, Encoding.UTF8.GetBytes(plainText));

            string cipherText = Hex.ToHexString(encrypted);
            return cipherText;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherText">待解密的数据，16进制字符串</param>
        /// <param name="secretKey">key</param>
        /// <param name="iv">iv</param>
        /// <param name="isHexString">secretKey和iv 是否是16进制字符串</param>
        /// <returns></returns>
        public static string DecryptCBC(string cipherText, string secretKey, string iv, bool isHexString = false) {
            SM4Context ctx = new SM4Context();
            ctx.IsPadding = true;
            ctx.Mode = SM4.SM4_DECRYPT;

            byte[] keyBytes;
            byte[] ivBytes;
            if (isHexString) {
                keyBytes = Hex.Decode(secretKey);
                ivBytes = Hex.Decode(iv);
            }
            else {
                keyBytes = Encoding.UTF8.GetBytes(secretKey);
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }

            SM4 sm4 = new SM4();
            sm4.Sm4SetKeyDec(ctx, keyBytes);
            byte[] decrypted = sm4.Sm4CryptCbc(ctx, ivBytes, Hex.Decode(cipherText));
            return Encoding.UTF8.GetString(decrypted);
        }
    }
}
