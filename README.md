# 国密算法

## BouncyCastle 类库实现

## BouncyCastle.Crypto 、BouncyCastle.Cryptography 、 Portable.BouncyCastle 三个库的区别和联系

- BouncyCastle.Crypto 是旧版本，有安全漏洞，只适用NET framework 平台

- BouncyCastle.Cryptography 是最新版本，适用于 .NET Framework 和 .NET Standard

- Portable.BouncyCastle 跨平台，支持 .NET Framework、.NET Core 和 Xamarin 等多个平台

## KYSharp.SM.Core 库说明

- 依赖于Portable.BouncyCastle

- SM4类的Encrypt_CBC和Decrypt_CBC方法有问题，不能使用，可用 KYSharp.SM.Core.Test.SM.SM4.SM4Utils 类或 BouncyCastle.Crypto.Test.SM.GMCommonUtils 类

## BouncyCastle.Crypto.Test项目

- 只实现了SM2一个算法   