﻿using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math;

namespace BouncyCastle.Crypto.Test.SM {
    public class Cipher {
        private int ct = 1;


        private ECPoint p2;
        private SM3Digest sm3keybase;
        private SM3Digest sm3c3;


        private byte[] key = new byte[32];
        private byte keyOff = 0;


        public Cipher() {
        }


        private void Reset() {
            sm3keybase = new SM3Digest();
            sm3c3 = new SM3Digest();


            byte[] p;


            //p = p2.AffineXCoord.ToBigInteger().ToByteArray();
            p = p2.X.ToBigInteger().ToByteArray();
            sm3keybase.BlockUpdate(p, 0, p.Length);
            sm3c3.BlockUpdate(p, 0, p.Length);


            //p = p2.AffineYCoord.ToBigInteger().ToByteArray();
            p = p2.Y.ToBigInteger().ToByteArray();
            sm3keybase.BlockUpdate(p, 0, p.Length);


            ct = 1;
            NextKey();
        }


        private void NextKey() {
            SM3Digest sm3keycur = new SM3Digest(sm3keybase);
            sm3keycur.Update((byte)(ct >> 24 & 0x00ff));
            sm3keycur.Update((byte)(ct >> 16 & 0x00ff));
            sm3keycur.Update((byte)(ct >> 8 & 0x00ff));
            sm3keycur.Update((byte)(ct & 0x00ff));
            sm3keycur.DoFinal(key, 0);
            keyOff = 0;
            ct++;
        }


        public virtual ECPoint Init_enc(SM2 sm2, ECPoint userKey) {
            BigInteger k = null;
            ECPoint c1 = null;


            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.GenerateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)key.Private;
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters)key.Public;
            k = ecpriv.D;
            c1 = ecpub.Q;


            p2 = userKey.Multiply(k);
            Reset();


            return c1;
        }


        public virtual void Encrypt(byte[] data) {
            sm3c3.BlockUpdate(data, 0, data.Length);
            for (int i = 0; i < data.Length; i++) {
                if (keyOff == key.Length)
                    NextKey();


                data[i] ^= key[keyOff++];
            }
        }


        public virtual void Init_dec(BigInteger userD, ECPoint c1) {
            p2 = c1.Multiply(userD);
            Reset();
        }


        public virtual void Decrypt(byte[] data) {
            for (int i = 0; i < data.Length; i++) {
                if (keyOff == key.Length)
                    NextKey();


                data[i] ^= key[keyOff++];
            }
            sm3c3.BlockUpdate(data, 0, data.Length);
        }


        public virtual void Dofinal(byte[] c3) {
            //byte[] p = p2.AffineYCoord.ToBigInteger().ToByteArray();
            byte[] p = p2.Y.ToBigInteger().ToByteArray();
            sm3c3.BlockUpdate(p, 0, p.Length);
            sm3c3.DoFinal(c3, 0);
            Reset();
        }
    }
}
