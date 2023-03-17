using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace WayfJwtConnector.Helpers
{
    internal sealed class RsaHelper
    {
        public static RsaSecurityKey IssuerSigningKey(string publicKey)
        {
            var keyBytes = Convert.FromBase64String(publicKey);
            var x509Certificate = new X509CertificateParser().ReadCertificate(keyBytes);
            var asymmetricKeyParameter = x509Certificate.GetPublicKey();
            var rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            var rsaParameters = new RSAParameters
            {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            
            return new RsaSecurityKey(rsaParameters);
        }

    }
}
