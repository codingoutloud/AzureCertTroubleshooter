using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace AzureCertThumbScan
{
    public class CertStoreScanner
    {
        private bool Verbose { get; set; }

        public CertStoreScanner(bool verbose = false)
        {
            Verbose = verbose;
        }

        public bool FindCertificatesByThumbprint(string thumbprint)
        {
            Console.WriteLine("\n--- Certificate Store ---");

            var howManyFound = 0;

            foreach (var sl in Enum.GetValues(typeof(StoreLocation)))
            {
                if (Verbose) Console.WriteLine(String.Format("Store Location: {0}", sl));
                foreach (var sn in Enum.GetValues(typeof(StoreName)))
                {
                    var store = new X509Store((StoreName)sn, (StoreLocation)sl);
                    store.Open(OpenFlags.ReadOnly);

                    if (Verbose) Console.WriteLine(String.Format(" Store Location/Store Name: {0}/{1}",
                                                    store.Location, store.Name));
                    var certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                    foreach (var cert in certs)
                    {
                        if (Verbose) DumpCertDetails(store, cert);
                        howManyFound++;
                    }
                }
            }

            return howManyFound > 0;
        }

        public void DumpCertDetails(X509Store store, X509Certificate2 cert)
        {
            Console.WriteLine(String.Format("{0} {1}/{2} {0}",
                                            new string('-', 15), store.Location, store.Name));
            Console.WriteLine("Thumbprint = {0}", cert.Thumbprint);
            Console.WriteLine("{0}" +
                              "\tCertificate Subject Name: {1}" +
                              "\n\t Has private key? {2} Is archived? {3}" +
                              "\n\t X.509 version: {4}" +
                              "\n\t Key algorithm: {5} Signature algorithm: {6} ({7})" +
                              "\n\t Issuer: {8}" +
                              "\n\t Invalid before: {9}" +
                              "\n\t Invalid after: {10}" +
                              "\n\t {11} extensions",
                              String.IsNullOrEmpty(cert.FriendlyName)
                                  ? ""
                                  : String.Format("\t[Store Friendly Name: {0}]\n",
                                                  cert.FriendlyName),
                              cert.SubjectName.Name,
                // FriendlyName is a store concept, not cert?
                              cert.HasPrivateKey, cert.Archived,
                              cert.Version,
                              cert.GetKeyAlgorithm(), cert.SignatureAlgorithm.FriendlyName,
                              cert.SignatureAlgorithm.Value,
                              cert.IssuerName.Name,
                              cert.NotBefore, cert.NotAfter,
                              cert.Extensions.Count);
            foreach (var ext in cert.Extensions)
            {
                Console.WriteLine("\t OID = {0} {1}", ext.Oid.FriendlyName,
                                  ext.Critical ? "[Critical]" : "");
            }
        }

    }
}


#if false
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Collections.Generic;

namespace PublishSettingsDiff
{
    internal class Program
    {
        //        private static string _managementCertificate = "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";
        private static string _managementCertificate =
            "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";

        private static string subscriptionId = "1d29d4d6-b128-44bb-b644-a3204eb444be";
        private static string subscriptionName = "MVP MSND Account";
        private static string certificateThumbprint = "";
        private static StoreLocation certificateStoreLocation = StoreLocation.CurrentUser;
        private static StoreName certificateStoreName = StoreName.My;
        private static string publishFileFormat = @"<?xml version=""1.0"" encoding=""utf-8""?>
<PublishData>
  <PublishProfile
    PublishMethod=""AzureServiceManagementAPI""
    Url=""https://management.core.windows.net/""
    ManagementCertificate=""{0}"">
    <Subscription
      Id=""{1}""
      Name=""{2}"" />
  </PublishProfile>
</PublishData>";

        private static void Main(string[] args)
        {
            // one Arra sent: ‎3f 61 90 06 e1 ee 83 3c cb 52 50 08 76 96 d6 0c ad 26 97 b9
            // real one: ‎4b 59 ed 19 28 6c 15 30 20 fc e3 14 7e 56 8f e9 0c 0f e6 ef
            string cloudConstructThumb = "‎4b 59 ed 19 28 6c 15 30 20 fc e3 14 7e 56 8f e9 0c 0f e6 ef";
            cloudConstructThumb = "‎3f 61 90 06 e1 ee 83 3c cb 52 50 08 76 96 d6 0c ad 26 97 b9";
            cloudConstructThumb = "575926B22D4425235C75C15BFC42E6677F6D1B28";
            cloudConstructThumb = "F3667BF51215D71B283DA92B2FC1DF38B98AD5AE"; // this is on portal - is it local too?
            string ccThumb = cloudConstructThumb.Replace(" ", "");
            var foo = FindCertificatesByThumbprint(ccThumb);

            DumpWindowsAzureConnectionsXml();

            return;

            DumpExpiredCerts();

            return;

            var certificateStore = new X509Store(certificateStoreName, certificateStoreLocation);
            certificateStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certificates = certificateStore.Certificates;
            var matchingCertificates = certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false);
            if (matchingCertificates.Count == 0)
            {
                Console.WriteLine(
                    "No matching certificate found. Please ensure that proper values are specified for Certificate Store Name, Location and Thumbprint");
            }
            else
            {
                var certificate = matchingCertificates[0];
                var certificateData = Convert.ToBase64String(certificate.Export(X509ContentType.Pkcs12, string.Empty));
                if (string.IsNullOrWhiteSpace(subscriptionName))
                {
                    subscriptionName = subscriptionId;
                }
                string publishSettingsFileData = string.Format(publishFileFormat, certificateData, subscriptionId,
                                                               subscriptionName);
                string fileName = Path.GetTempPath() + subscriptionId + ".publishsettings";
                File.WriteAllBytes(fileName, Encoding.UTF8.GetBytes(publishSettingsFileData));
                Console.WriteLine("Publish settings file written successfully at: " + fileName);
            }
            Console.WriteLine("Press any key to terminate the program.");
            Console.ReadLine();
        }


        public static void DumpExpiredCerts()
        {
            // Iterates through all of the X.509 digital certificates installed in the certificate store
            // on a Windows operating system, dumping out some metadata about each. Each certificate, in
            // each Certificate Store, from each Certificate Location is included.
            //
            // Bill Wilder | @codingoutloud | Oct 2012
            // Original: https://gist.github.com/4005661

            var totalCerts = 0;
            var totalExpiredCerts = 0;
            var totalNotYetValidCerts = 0;

            foreach (var sl in Enum.GetValues(typeof (StoreLocation)))
            {
                Console.WriteLine(String.Format("Store Location: {0}", sl));
                foreach (var sn in Enum.GetValues(typeof (StoreName)))
                {
                    var store = new X509Store((StoreName) sn, (StoreLocation) sl);
                    store.Open(OpenFlags.ReadOnly);

                    Console.WriteLine(String.Format(" Store Location/Store Name: {0}/{1}",
                                                    store.Location, store.Name));
                    foreach (X509Certificate2 c in store.Certificates)
                    {
                        try
                        {
                            if (c.Thumbprint.ToLower().Substring(0, 4) == "1D61".ToLower())
                            {
                                // 1D61ADDF9C67030F91CA1EDB7CD86E30168F9603
                                Console.WriteLine("\n**\n**\n** THUMBED **\n**\n**");
                                DumpCertDetails(store, c);
                            }
                            if (c.GetEffectiveDateString().Contains("2013"))
                            {
                                // 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
                                Console.WriteLine("2013! - " + c.GetEffectiveDateString());
                            }


                            string target = _managementCertificate;
                            string candidate = Convert.ToBase64String(c.Export(X509ContentType.Pkcs12, String.Empty));
                            int tlen = target.Length;
                            int clen = candidate.Length;

                            if (target.ToLower().Substring(0, 4) == candidate.ToLower().Substring(0, 4))
                            {
                                Console.WriteLine("SAME BEGINNING");
                                DumpCertDetails(store, c);
                            }

                            if (tlen == clen)
                            {
                                Console.WriteLine("LENGTH IS CORRECT: {0} - Issued by {1} - Key = {2}", c.FriendlyName,
                                                  c.IssuerName.Name, c.PublicKey);
                            }
                            else
                            {
                                // Console.WriteLine("LENDIFF = " + Math.Abs(tlen - clen));
                            }

                            if (target == candidate)
                            {
                                Console.WriteLine("FOUND IT: {0} - Issued by {1} - Key = {2}", c.FriendlyName,
                                                  c.IssuerName.Name, c.PublicKey);
                            }
                            else
                            {
                                // Console.WriteLine("SKIPPING: {0} by {1}", c.FriendlyName, c.IssuerName.Name);
                            }
                        }
                        catch (Exception ex)
                        {
                            // Console.WriteLine("Cound not handle this one... " + c.IssuerName.Name);
                        }

#if false

                        totalCerts++;

                        var now = DateTime.UtcNow;
                        if (c.NotAfter < now || c.NotBefore > now)
                        {
                            // Certificate c has expired or not yet become valid

                            if (c.NotAfter < now) totalExpiredCerts++;
                            if (c.NotBefore > now) totalNotYetValidCerts++;

                            Console.WriteLine(String.Format("{0} {1}/{2} {0}",
                                                            new string('-', 15), store.Location, store.Name));
                            Console.WriteLine("{0}" +
                                              "\tCertificate Subject Name: {1}" +
                                              "\n\t Has private key? {2} Is archived? {3}" +
                                              "\n\t X.509 version: {4}" +
                                              "\n\t Key algorithm: {5} Signature algorithm: {6}" +
                                              "\n\t Issuer: {7}" +
                                              "\n\t Invalid before: {8}" +
                                              "\n\t Invalid after: {9}" +
                                              "\n\t {10} extensions",
                                              String.IsNullOrEmpty(c.FriendlyName)
                                                  ? ""
                                                  : String.Format("\t[Store Friendly Name: {0}]\n",
                                                                  c.FriendlyName),
                                              c.SubjectName.Name,
                                              // FriendlyName is a store concept, not cert?
                                              c.HasPrivateKey, c.Archived,
                                              c.Version,
                                              c.GetKeyAlgorithm(), c.SignatureAlgorithm,
                                              c.IssuerName.Name,
                                              c.NotBefore, c.NotAfter,
                                              c.Extensions.Count);
                            foreach (var ext in c.Extensions)
                            {
                                Console.WriteLine("\t OID = {0} {1}", ext.Oid.FriendlyName,
                                                  ext.Critical ? "[Critical]" : "");
                            }
                        }
#endif
                    }
                    store.Close();
                }
            }

            Console.WriteLine("\nFor Operating System {0}...\n", Environment.OSVersion);
            Console.WriteLine("Of {0} total certificates, {1} are not YET valid, {2} have EXPIRED.",
                              totalCerts, totalNotYetValidCerts, totalExpiredCerts);
            Console.ReadLine();
        }


    }
}
#endif