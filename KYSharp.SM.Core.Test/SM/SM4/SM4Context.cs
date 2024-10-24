using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace KYSharp.SM.Core.Test.SM.SM4 {
    public class SM4Context {
        /// <summary>
        /// 算法模式：1为加密，0为解密
        /// </summary>
        public int Mode { get; set; }

        public long[] Sk { get; set; }

        /// <summary>
        /// 是否使用PKCS7填充模式
        /// </summary>
        public bool IsPadding { get; set; }

        public SM4Context() {
            this.Mode = 1;
            this.IsPadding = true;
            this.Sk = new long[32];
        }
    }
}
