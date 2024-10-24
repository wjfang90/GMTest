using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KYSharp.SM.Core.Test.SM.SM2
{
    public class SM2
    {
        public static SM2 Instance
        {
            get
            {
                return new SM2();
            }

        }
        public static SM2 InstanceTest
        {
            get
            {
                return new SM2();
            }

        }

        public static readonly string[] Sm2Param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// gx,4
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" // gy,5
        };

        public string[] EccParam = Sm2Param;

        public readonly BigInteger EccP;
        public readonly BigInteger EccA;
        public readonly BigInteger EccB;
        public readonly BigInteger EccN;
        public readonly BigInteger EccGx;
        public readonly BigInteger EccGy;

        public readonly ECCurve EccCurve;
        public readonly ECPoint EccPointG;

        public readonly ECDomainParameters EccBcSpec;

        public readonly ECKeyPairGenerator EccKeyPairGenerator;

        private SM2()
        {
            EccParam = Sm2Param;

            ECFieldElement ecc_gx_fieldelement;
            ECFieldElement ecc_gy_fieldelement;

            EccP = new BigInteger(EccParam[0], 16);
            EccA = new BigInteger(EccParam[1], 16);
            EccB = new BigInteger(EccParam[2], 16);
            EccN = new BigInteger(EccParam[3], 16);
            EccGx = new BigInteger(EccParam[4], 16);
            EccGy = new BigInteger(EccParam[5], 16);

            
            ecc_gx_fieldelement = new FpFieldElement(EccP, EccGx);

            ecc_gy_fieldelement = new FpFieldElement(EccP, EccGy);

            EccCurve = new FpCurve(EccP, EccA, EccB);
            EccPointG = new FpPoint(EccCurve, ecc_gx_fieldelement, ecc_gy_fieldelement);            

            EccBcSpec = new ECDomainParameters(EccCurve, EccPointG, EccN);

            ECKeyGenerationParameters ecc_ecgenparam;
            ecc_ecgenparam = new ECKeyGenerationParameters(EccBcSpec, new SecureRandom());

            EccKeyPairGenerator = new ECKeyPairGenerator();
            EccKeyPairGenerator.Init(ecc_ecgenparam);
        }

        public virtual byte[] Sm2GetZ(byte[] userId, ECPoint userKey)
        {
            SM3Digest sm3 = new SM3Digest();
            byte[] p;
            // userId length
            int len = userId.Length * 8;
            sm3.Update((byte)(len >> 8 & 0x00ff));
            sm3.Update((byte)(len & 0x00ff));

            // userId
            sm3.BlockUpdate(userId, 0, userId.Length);

            // a,b
            p = EccA.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = EccB.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            // gx,gy
            p = EccGx.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = EccGy.ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // x,y
            p = userKey.get_X().ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);
            p = userKey.get_Y().ToBigInteger().ToByteArray();
            sm3.BlockUpdate(p, 0, p.Length);

            // Z
            byte[] md = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(md, 0);

            return md;
        }

    }
}
