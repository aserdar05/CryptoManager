public class CertificateManager
    {
        public static void AddCertificateToStore(StoreName StoreName, StoreLocation StoreLocation, byte[] CertificateArray)
        {
            X509Store store = new X509Store(StoreName, StoreLocation);
            X509Certificate2 certificate = new X509Certificate2(CertificateArray);

            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate); //cert is the X509Certificate2 cert that I have created 
            store.Close();
        }

        public static void RemoveCertificateFromStore(StoreName StoreName, StoreLocation StoreLocation, String CertificateName)
        {
            // Use other store locations if your certificate is not in the current user store.
            X509Store store = new X509Store(StoreName, StoreLocation);
            store.Open(OpenFlags.ReadWrite | OpenFlags.IncludeArchived);

            // You could also use a more specific find type such as X509FindType.FindByThumbprint
            X509Certificate2Collection col = store.Certificates.Find(X509FindType.FindBySubjectName, CertificateName, false);

            foreach (var cert in col)
            {
                store.Remove(cert);
            }
            store.Close();
        }
    }
