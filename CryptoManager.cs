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




public ServiceHandler(BindingType bindingType) {
            this.Token = InterContext.Current.ServiceAuthToken;
            Client = new RemServiceApiClient(bindingType == BindingType.BasicHttp ? "basicHttpBinding" : "basicHttpsBinding");
            OperationContextScope = new OperationContextScope(Client.InnerChannel);
            OperationContext.Current.OutgoingMessageHeaders.Add(MessageHeader.CreateHeader("Bearer", "http://kep.com.tr/v1", this.Token));
            this.ValidateToken();
        }


<serviceBehaviors>
        <behavior name="ApiServiceBehaviour">
          <serviceMetadata httpGetEnabled="false" httpsGetEnabled="true" />
          <serviceDebug includeExceptionDetailInFaults="true" />
          <serviceAuthorization serviceAuthorizationManagerType="Intertech.Rem.Portal.UI.User.Api.WebApi.KepServiceAuthorizationManager, Intertech.Rem.Portal.UI.User" />
        </behavior>
        <behavior name="ExternalClientServiceBehaviour">
          <serviceMetadata httpGetEnabled="false" httpsGetEnabled="true" />
          <serviceDebug includeExceptionDetailInFaults="true" />
          <serviceAuthorization serviceAuthorizationManagerType="Intertech.Rem.Portal.UI.User.Api.WebApi.KepExternalClientServiceAuthorizationManager, Intertech.Rem.Portal.UI.User" />
        </behavior>
      </serviceBehaviors>





public class KepExternalClientServiceAuthorizationManager : ServiceAuthorizationManager
    {
        protected override bool CheckAccessCore(OperationContext operationContext)
        {
            var action = operationContext.RequestContext.RequestMessage.Headers.Action;
            DispatchOperation operation = operationContext.EndpointDispatcher.DispatchRuntime.Operations.FirstOrDefault(o => o.Action == action);
            Type hostType = operationContext.Host.Description.ServiceType;
            MethodInfo method = hostType.GetMethod(operation.Name);
            bool isAnonymous = method.GetCustomAttributes(true).Any(a => a.GetType() == typeof(AllowAnonymousAttribute));

            if (!isAnonymous)
            {
                var accessToken = OperationContext.Current.IncomingMessageHeaders.GetHeader<string>("Bearer", "http://tempuri.org/");
                RemoteEndpointMessageProperty endpoint = OperationContext.Current.IncomingMessageProperties[RemoteEndpointMessageProperty.Name] as RemoteEndpointMessageProperty;
                string clientIp = endpoint.Address;
                InterContext.Logger.Info("Web Servis external client api metodu çağırıldı. Client ip : " + clientIp);

                Result tokenResult = ApiUtils.ValidateServiceToken(accessToken);
                InterContext.Logger.Info("Web Servis external client api metodu token validation: Doğrulama sonucu : " + tokenResult.Passed + ", Sonuç mesajı : " + tokenResult.Message  + "}");
                if (tokenResult.Passed)
                {
                    UserAuthModel model = tokenResult.Data as UserAuthModel;
                    var claims = new List<Claim>();
                    claims.Add(new Claim(ClaimTypes.Name, model.RemUserId.ToString()));
                    ClaimsIdentity identity = new ClaimsIdentity(claims);
                    ClaimsPrincipal.ClaimsPrincipalSelector = () =>
                    {
                        return new ClaimsPrincipal(identity);
                    };
                }
                return tokenResult.Passed;
            }
            else return true;
        }

        private AuthenticationTicket GetTicket(string accessToken)
        {
            var dataFormat = KepTicketFactory.KepDataFormat();
            try
            {
                return dataFormat.Unprotect(accessToken);
            }
            catch (Exception exc)
            {
                InterContext.Logger.Info("GetTicket DataFormatı hata aldı." + exc.Message + "." + exc.StackTrace);
                throw;
            }
        }
    }
