using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertificadoDigital
{
    class Program
    {
        static void Main(string[] args)
        {
            Guid guid = Guid.NewGuid();
            Console.WriteLine(guid);

            var bytes = guid.ToByteArray();

            ContentInfo content = new ContentInfo(bytes);
            SignedCms signedCms = new SignedCms(content, false);
            bool verifica_conexao = false;

            if (VerifySign(bytes))
            {
                signedCms.Decode(bytes);
            }




            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            //my.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            my.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection collection = (X509Certificate2Collection)my.Certificates;
            X509Certificate2Collection collection1 = (X509Certificate2Collection)collection.Find(X509FindType.FindBySubjectName, "BRUNA REVERIEGO", false);

            // Find the certificate we'll use to sign            
            //RSACryptoServiceProvider csp = null;

            if (collection1.Count != 0)
            {
                foreach (X509Certificate2 cert in collection1)
                {
                    try
                    {
                        var x509 = cert;
                        byte[] rawData = x509.RawData;



                        Console.WriteLine("Content Type: {0}", X509Certificate2.GetCertContentType(rawData));

                        Console.WriteLine("Serial Number: {0}", x509.SerialNumber);
                        Console.WriteLine("Friendly Name: {0}", x509.FriendlyName);


                        verifica_conexao = true;
                        CmsSigner signer = new CmsSigner(x509);
                        signer.IncludeOption = X509IncludeOption.WholeChain;
                        signedCms.ComputeSignature(signer, false);
                        Console.WriteLine(signedCms);


                        Console.ReadKey();

                
                    }
                    catch (CryptographicException)
                    {
                        Console.WriteLine("Information could not be written out for this certificate.");
                    }
                }
            }


            if (my.Certificates.Count == 0 || verifica_conexao == false)
            {
                Console.WriteLine("Nenhum certificado localizado");
            }



        }

        public static bool VerifySign(byte[] data)
        {
            try
            {
                SignedCms signed = new SignedCms();
                signed.Decode(data);
            }
            catch
            {
                return false; // Arquivo não assinado
            }
            return true;
        }
    }
}
