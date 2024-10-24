using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BouncyCastle.Cryptography.Test.SM {
    public class SM4Utils {
        public static (byte[] Key, byte[] IV) SM4KeyGen(string password, int keySizeBit = 128, byte[]? salts = null) {
            byte[] salt = salts ?? new byte[] { 0x31, 0x33, 0x35, 0x37, 0x32, 0x34, 0x36, 0x38 };
            if (salt.Length % 8 == 0 && salt.Length >= 8) { }
            else { throw new ArgumentException("加盐数组的长度必须为8的倍数", nameof(salts)); }

            int myIterations = 1000;
            Rfc2898DeriveBytes keyBytesGen = new(password, salt, myIterations, HashAlgorithmName.SHA256);

            int keyLen = keySizeBit / 8;
            byte[] key = new byte[keyLen];
            byte[] iv = new byte[16];
            key = keyBytesGen.GetBytes(key.Length);
            iv = keyBytesGen.GetBytes(iv.Length);
            return (Key: key, IV: iv);
        }

        public static byte[] SM4CBCEncrypt(byte[] data, byte[] key, byte[] iv, PaddingMode padding = PaddingMode.PKCS7) {
            var engine = new SM4Engine();
            var blockCipher = new CbcBlockCipher(engine);
            
            IBlockCipherPadding blockPadding = null;
            switch (padding) {
                case PaddingMode.None:
                    break;
                case PaddingMode.Zeros:
                    blockPadding = new ZeroBytePadding();
                    break;
                case PaddingMode.PKCS7:
                default:
                    blockPadding = new Pkcs7Padding();
                    break;
                case PaddingMode.ANSIX923:
                    blockPadding = new X923Padding();
                    break;
                case PaddingMode.ISO10126:
                    blockPadding = new ISO10126d2Padding();
                    break;
            }
            CipherUtilities.GetCipher
            var cipher = blockPadding is null ? new PaddedBufferedBlockCipher(blockCipher) : new PaddedBufferedBlockCipher(blockCipher, blockPadding);
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));
            return cipher.DoFinal(data);
        }

        public static byte[] SM4CBCDecrypt(byte[] dataEncrypted, byte[] key, byte[] iv, PaddingMode padding = PaddingMode.PKCS7) {
            var engine = new SM4Engine();
            var blockCipher = new CbcBlockCipher(engine);
            IBlockCipherPadding blockPadding = null;
            switch (padding) {
                case PaddingMode.None:
                    break;
                case PaddingMode.Zeros:
                    blockPadding = new ZeroBytePadding();
                    break;
                case PaddingMode.PKCS7:
                default:
                    blockPadding = new Pkcs7Padding();
                    break;
                case PaddingMode.ANSIX923:
                    blockPadding = new X923Padding();
                    break;
                case PaddingMode.ISO10126:
                    blockPadding = new ISO10126d2Padding();
                    break;
            }

            var cipher = blockPadding is null ? new PaddedBufferedBlockCipher(blockCipher) : new PaddedBufferedBlockCipher(blockCipher, blockPadding);
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
            return cipher.DoFinal(dataEncrypted);
        }

        public static byte[] SM4ECBEncrypt(byte[] data, byte[] key, PaddingMode padding = PaddingMode.PKCS7) {
            var engine = new SM4Engine();
            var blockCipher = new EcbBlockCipher(engine);
            IBlockCipherPadding blockPadding = null;
            switch (padding) {
                case PaddingMode.None:
                    break;
                case PaddingMode.Zeros:
                    blockPadding = new ZeroBytePadding();
                    break;
                case PaddingMode.PKCS7:
                default:
                    blockPadding = new Pkcs7Padding();
                    break;
                case PaddingMode.ANSIX923:
                    blockPadding = new X923Padding();
                    break;
                case PaddingMode.ISO10126:
                    blockPadding = new ISO10126d2Padding();
                    break;
            }

            var cipher = blockPadding is null ? new PaddedBufferedBlockCipher(blockCipher) : new PaddedBufferedBlockCipher(blockCipher, blockPadding);
            cipher.Init(true, new ParametersWithRandom(new KeyParameter(key)));
            return cipher.DoFinal(data);
        }

        public static byte[] SM4ECBDecrypt(byte[] data, byte[] key, PaddingMode padding = PaddingMode.PKCS7) {
            var engine = new SM4Engine();
            var blockCipher = new EcbBlockCipher(engine);
            IBlockCipherPadding blockPadding = null;
            switch (padding) {
                case PaddingMode.None:
                    break;
                case PaddingMode.Zeros:
                    blockPadding = new ZeroBytePadding();
                    break;
                case PaddingMode.PKCS7:
                default:
                    blockPadding = new Pkcs7Padding();
                    break;
                case PaddingMode.ANSIX923:
                    blockPadding = new X923Padding();
                    break;
                case PaddingMode.ISO10126:
                    blockPadding = new ISO10126d2Padding();
                    break;
            }

            var cipher = blockPadding is null ? new PaddedBufferedBlockCipher(blockCipher) : new PaddedBufferedBlockCipher(blockCipher, blockPadding);
            cipher.Init(false, new ParametersWithRandom(new KeyParameter(key)));
            return cipher.DoFinal(data);
        }
    }
}
