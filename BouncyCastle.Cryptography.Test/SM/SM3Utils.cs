﻿using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BouncyCastle.Cryptography.Test.SM {
    public class SM3Utils {
        public static byte[] SM3KeyGen(int keySizeBit = 512) {
            int keySize = keySizeBit / 8;
            //var keyRandom =  RandomNumberGenerator.GetBytes(keySize);
            var keyRandom = SecureRandom.GetNextBytes(new SecureRandom(), keySize);
            return keyRandom;
        }

        public static byte[] SM3HashData(byte[] data) {
            SM3Digest sm3 = new();
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] md = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(md, 0);
            return md;
        }

        public static byte[] SM3HashData(byte[] data, byte[] key) {
            SM3Digest sm3 = new();
            HMac mac = new(sm3);
            KeyParameter keyParameter = new(key);
            mac.Init(keyParameter);
            mac.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[mac.GetMacSize()];
            mac.DoFinal(result, 0);
            return result;
        }
    }
}
