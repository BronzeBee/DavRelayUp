using System;
using System.Runtime.InteropServices;
using static DavRelayUp.Relay.Natives;

namespace DavRelayUp.Relay
{
    public class Ldap
    {
        public IntPtr ld;

        public bool Connect()
        {
            var timeout = new LDAP_TIMEVAL
            {
                tv_sec = (int) (new TimeSpan(0, 0, 60).Ticks / TimeSpan.TicksPerSecond)
            };
            ld = ldap_init(Options.domainController, (uint) Options.ldapPort);
            uint LDAP_OPT_ON = 1;
            uint version = 3;
            var ldapStatus = ldap_set_option(ld, 0x11, ref version);

            if (Options.useSSL)
            {
                ldap_get_option(ld, 0x0a, out int lv); //LDAP_OPT_SSL
                if (lv == 0)
                    ldap_set_option(ld, 0x0a, ref LDAP_OPT_ON);

                ldap_get_option(ld, 0x0095, out lv); //LDAP_OPT_SIGN
                if (lv == 0)
                    ldap_set_option(ld, 0x0095, ref LDAP_OPT_ON);

                ldap_get_option(ld, 0x0096, out lv); //LDAP_OPT_ENCRYPT
                if (lv == 0)
                    ldap_set_option(ld, 0x0096, ref LDAP_OPT_ON);

                ldap_set_option(ld, 0x81,
                    Marshal.GetFunctionPointerForDelegate(new VERIFYSERVERCERT((connection, serverCert) => true)));
            }

            ldapStatus = ldap_connect(ld, timeout);
            if (ldapStatus != 0)
            {
                Console.WriteLine("[-] Could not connect to {0}. ldap_connect failed with error code 0x{1}",
                    Options.domainController, ldapStatus.ToString("x2"));
                return false;
            }

            return true;
        }

        public byte[] Bind(byte[] authMsg, out int status)
        {
            var bufSize = authMsg.Length;
            var bufferPtr = Marshal.AllocHGlobal(bufSize);
            Marshal.Copy(authMsg, 0, bufferPtr, bufSize);
            var berval = new berval
            {
                bv_len = bufSize,
                bv_val = bufferPtr
            };
            var bervalPtr = Marshal.AllocHGlobal(Marshal.SizeOf(berval));
            Marshal.StructureToPtr(berval, bervalPtr, false);

            var bind = ldap_sasl_bind(ld, "", "GSSAPI", bervalPtr, IntPtr.Zero, IntPtr.Zero, out IntPtr servResp);

            ldap_get_option(ld, 0x0031, out status);

            byte[] result = null;
            if (servResp != IntPtr.Zero)
            {
                Marshal.PtrToStructure(servResp, berval);
                result = new byte[berval.bv_len];
                Marshal.Copy(berval.bv_val, result, 0, berval.bv_len);
            }

            Marshal.FreeHGlobal(bervalPtr);
            Marshal.FreeHGlobal(bufferPtr);

            return result;
        }

        public void Unbind()
        {
            ldap_unbind(ld);
        }

    }
}