using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
            var x509Certificate = new X509Certificate2(keyBytes);
            return new RsaSecurityKey(x509Certificate.GetRSAPublicKey());
        }

    }
}
