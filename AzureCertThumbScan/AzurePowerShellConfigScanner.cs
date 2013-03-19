using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace AzureCertThumbScan
{
    public class AzurePowerShellConfigScanner
    {
        private bool Verbose { get; set; }

        public AzurePowerShellConfigScanner(bool verbose = false)
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
            Console.WriteLine("\n--- PowerShell ---");

            var count = 0;

            // http://blogs.msdn.com/b/avkashchauhan/archive/2012/11/20/how-does-windows-azure-powershell-import-publishsettings-using-import-azurepublishsettingsfile-command.aspx
            var currConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Windows Azure Powershell", "config.json");
            if (File.Exists(currConfigPath))
            {
                Console.WriteLine("Current Azure Subscription setting for PowerShell (from {0}): \n\t{1}",
                                  currConfigPath, File.ReadAllText(currConfigPath));
            }
            else
            {
                Console.WriteLine("PS: file {0} does not exist. Have you configured PowerShell for Azure on this machine?", currConfigPath);
            }

            {
                var xdocPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                            @"Windows Azure Powershell", "DefaultSubscriptionData.xml");

                Console.WriteLine("PS (config file 1 of 2): Searching Azure PowerShell settings here: {0}", xdocPath);

                if (File.Exists(currConfigPath))
                {
                    var xdoc = XDocument.Load(xdocPath);
                    XNamespace ns = "urn:Microsoft.WindowsAzure.Management:WaPSCmdlets";
                    var credentials = from c in xdoc.Descendants(ns + "Subscription")
                                      select new
                                                 {
                                                     SubscriptionId = c.Element(ns + "SubscriptionId").Value,
                                                     CertificateThumbprint = c.Element(ns + "Thumbprint").Value,
                                                     ServiceEndpoint = c.Element(ns + "ServiceEndpoint").Value,
                                                     SubscriptionName = c.Attribute("name").Value
                                                 };

                    var matchingCredentials = from c in credentials
                                              where c.CertificateThumbprint.ToUpper() == thumbprint.ToUpper()
                                              select c;

                    foreach (var c in matchingCredentials)
                    {
                        Console.WriteLine("PS: Subscription {0} ({1}) uses Thumbprint {2}", c.SubscriptionName,
                                          c.SubscriptionId, c.CertificateThumbprint);
                        count++;
                    }

                    if (count == 0)
                        Console.WriteLine("Thumbprint {0} NOT found in your local Azure POWERSHELL CONFIG", thumbprint);
                    else
                        Console.WriteLine(
                            "Certificate {0} found {1} times in your local Azure PowerShell config store.",
                            thumbprint, count);
                }
                else
                {
                    Console.WriteLine("PS: file {0} does not exist. Have you configured PowerShell for Azure on this machine?", xdocPath);
                }
            }


            // === PART 2 === 
            {
                var xdocPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                            @"Windows Azure Powershell", "publishSettings.xml");

                Console.WriteLine("PS (config file 2 of 2): Searching Azure PowerShell settings here: {0}", xdocPath);

                if (File.Exists(xdocPath))
                {

                    var xdoc = XDocument.Load(xdocPath);
                    var matchingPublishProfiles = from pp in xdoc.Descendants("PublishProfile")
                                                  where pp.Attribute("ManagementCertificate").Value.ToUpper() == thumbprint.ToUpper()
                                                  select new
                                                             {
                                                                 PublishMethod = pp.Attribute("PublishMethod"),
                                                                 Url = pp.Attribute("Url"),
                                                                 ManagementCertificate =
                                                      pp.Attribute("ManagementCertificate")
                                                             };

                    var matchingCredentials = from c in xdoc.Descendants("Subscription")
                                              select new
                                                         {
                                                             CertificateThumbprint = thumbprint,
                                                             SubscriptionId = c.Attribute("Id").Value,
                                                             SubscriptionName = c.Attribute("Name")
                                                         };

                    foreach (var c in matchingCredentials)
                    {
                        Console.WriteLine("PS: Subscription {0} ({1}) uses Thumbprint {2}", c.SubscriptionName,
                                          c.SubscriptionId, c.CertificateThumbprint);
                        count++;
                    }

                    if (count == 0)
                        Console.WriteLine("Thumbprint {0} NOT found in your local Azure POWERSHELL CONFIG", thumbprint);
                    else
                        Console.WriteLine(
                            "Certificate {0} found {1} times (grand total across both config files) in your local Azure PowerShell config store.",
                            thumbprint, count);
                }
                else
                {
                    Console.WriteLine("PS: file {0} does not exist. Have you configured PowerShell for Azure on this machine?", xdocPath);                    
                }
            }

            return count > 0;
        }
    }
}
