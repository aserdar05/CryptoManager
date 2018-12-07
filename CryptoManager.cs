public sealed class RemCryptoManager
    {
        private string CertificateName { get; set; }
        private StoreName CertStoreName { get; set; }

        private X509Certificate2 Certificate { get; set; }

        public RemCryptoManager(string certName, StoreName certStoreName)
        {

            CertificateName = certName;
            CertStoreName = certStoreName;

            X509Store store = new X509Store(CertStoreName, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection certificates = store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
            certificates = certificates.Find(X509FindType.FindBySubjectDistinguishedName, "CN=" + CertificateName, false);

            if (certificates.Count != 0)
            {
                Certificate = certificates[0];
                if (!Certificate.HasPrivateKey && certStoreName.Equals(StoreName.My))
                {
                    store.Close();
                    throw new Exception("Sertifikanın private key i bulunamadı");
                }
            }
            else
            {
                store.Close();
                throw new Exception("Sertifika bulunamadı");
            }

            store.Close();

        }

        public string Encrypt(string plainData)
        {
            RSACryptoServiceProvider rsaEncryptor = (RSACryptoServiceProvider)Certificate.PublicKey.Key;
            rsaEncryptor.PersistKeyInCsp = true;
            byte[] encryptData = Encoding.UTF8.GetBytes(plainData);
            byte[] signatureData = rsaEncryptor.Encrypt(encryptData, false);
            return Convert.ToBase64String(signatureData);
        }

        public string Decrypt(string encryptedData)
        {
            RSACryptoServiceProvider rsaEncryptor = (RSACryptoServiceProvider)Certificate.PrivateKey;
            byte[] encrypted = Convert.FromBase64String(encryptedData);
            byte[] plainData = rsaEncryptor.Decrypt(encrypted, false);
            return Encoding.UTF8.GetString(plainData);
        }



        public byte[] Sign(byte[] message)
        {
            RSACryptoServiceProvider rsaEncryptor = (RSACryptoServiceProvider)Certificate.PrivateKey;
            byte[] signature = rsaEncryptor.SignData(message, new SHA1CryptoServiceProvider());
            return signature;
        }

        public bool Validate(byte[] message, byte[] signature)
        {
            RSACryptoServiceProvider rsaEncryptor = (RSACryptoServiceProvider)Certificate.PublicKey.Key;
            return rsaEncryptor.VerifyData(message, new SHA1CryptoServiceProvider(), signature);
        }


    }

