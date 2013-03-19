using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace AzureCertThumbScan
{
    public class AzureVisualStudioConfigScanner
    {
        private bool Verbose { get; set; }

        public AzureVisualStudioConfigScanner(bool verbose = false)
        {
            Verbose = verbose;   
        }

        /// <summary>
        /// XML STRUCTURED LIKE THIS:
        /// <NamedCredentials xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        ///   <Items>
        ///     <NamedCredential>
        ///       <SubscriptionId>GUID HERE</SubscriptionId>
        ///       <IsImported>true</IsImported>
        ///       <ServiceEndpoint>https://management.core.windows.net/</ServiceEndpoint>
        ///       <CertificateThumbprint>CERT THUMB HERE</CertificateThumbprint>
        ///       <Name>NAME OF ACCOUNT IN AZURE HERE</Name>
        ///     </NamedCredential>
        ///   ...
        /// </summary>
        public bool FindCertificatesByThumbprint(string thumbprint) // DumpWindowsAzurePowerShellConnectionsXml()
        {
            Console.WriteLine("\n--- Visual Studio ---");

            var count = 0;

            var xdocPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), @"Visual Studio 2012\Settings", "Windows Azure Connections.xml");
            Console.WriteLine("Searching Azure Visual Studio settings here: {0}", xdocPath);

            if (File.Exists(xdocPath))
            {
                var xdoc = XDocument.Load(xdocPath);
                var credentials = from c in xdoc.Descendants("NamedCredential")
                                  select new
                                             {
                                                 SubscriptionId = c.Element("SubscriptionId").Value,
                                                 CertificateThumbprint = c.Element("CertificateThumbprint").Value,
                                                 SubscriptionName = c.Element("Name").Value
                                             };
                var matchingCredentials = from c in credentials
                                          where c.CertificateThumbprint.ToUpper() == thumbprint.ToUpper()
                                          select c;
                foreach (var c in matchingCredentials)
                {
                    Console.WriteLine("VS: Subscription {0} ({1}) uses Thumbprint {2}", c.SubscriptionName,
                                      c.SubscriptionId, c.CertificateThumbprint);
                    count++;
                }

                if (count == 0)
                    Console.WriteLine("Thumbprint {0} NOT found in your local Azure Visual Studio CONFIG", thumbprint);
                else
                    Console.WriteLine(
                        "Certificate {0} found {1} times in your local Azure Visual Studio config store.", thumbprint,
                        count);
            }
            else
            {
                Console.WriteLine("VS: file {0} does not exist. Have you configured Visual Studio for Azure deployment on this machine?", xdocPath);
            }

            return count > 0;
        }
    }
}





