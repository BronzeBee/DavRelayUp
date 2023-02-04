using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DavRelayUp.Relay
{
    internal class Natives
    {
        [StructLayout(LayoutKind.Sequential)]
        public sealed class LDAPMod
        {
            /// <summary>
            /// Values that you want to add, delete, or replace.
            /// </summary>
            [StructLayout(LayoutKind.Explicit)]
            public struct mod_vals
            {
                /// <summary>
                /// Pointer to a NULL terminated array of string values for the attribute.
                /// </summary>
                [FieldOffset(0)] public IntPtr modv_strvals;

                /// <summary>
                /// Pointer to a NULL-terminated array of berval structures for the attribute.
                /// </summary>
                [FieldOffset(0)] public IntPtr modv_bvals;
            }

            /// <summary>
            /// The operation to be performed on the attribute and the type of data specified as the attribute values.
            /// </summary>
            public int mod_op;

            /// <summary>
            /// Pointer to the attribute type that you want to add, delete, or replace.
            /// </summary>
            public IntPtr mod_type;

            /// <summary>
            /// A NULL-terminated array of string values for the attribute.
            /// </summary>
            public mod_vals mod_vals_u;

            public IntPtr mod_next;
        }

        public enum LdapModOperation
        {
            LDAP_MOD_ADD = 0x00,
            LDAP_MOD_DELETE = 0x01,
            LDAP_MOD_REPLACE = 0x02,
            LDAP_MOD_BVALUES = 0x80
        }

        public enum LdapSearchScope
        {
            LDAP_SCOPE_BASE = 0x0000,
            LDAP_SCOPE_BASEOBJECT = LDAP_SCOPE_BASE,
            LDAP_SCOPE_ONELEVEL = 0x0001,
            LDAP_SCOPE_ONE = LDAP_SCOPE_ONELEVEL,
            LDAP_SCOPE_SUBTREE = 0x0002,
            LDAP_SCOPE_SUB = LDAP_SCOPE_SUBTREE,
            LDAP_SCOPE_SUBORDINATE = 0x0003, /* OpenLDAP extension */
            LDAP_SCOPE_CHILDREN = LDAP_SCOPE_SUBORDINATE,
            LDAP_SCOPE_DEFAULT = -1 /* OpenLDAP extension */
        }

        public enum LdapResultType
        {
            LDAP_ERROR = -1,
            LDAP_TIMEOUT = 0,
            LDAP_RES_BIND = 0x61,
            LDAP_RES_SEARCH_ENTRY = 0x64,
            LDAP_RES_SEARCH_REFERENCE = 0x73,
            LDAP_RES_SEARCH_RESULT = 0x65,
            LDAP_RES_MODIFY = 0x67,
            LDAP_RES_ADD = 0x69,
            LDAP_RES_DELETE = 0x6b,
            LDAP_RES_MODDN = 0x6d,
            LDAP_RES_COMPARE = 0x6f,
            LDAP_RES_EXTENDED = 0x78,
            LDAP_RES_INTERMEDIATE = 0x79
        }

        public enum LdapStatus
        {
            LDAP_SUCCESS = 0,
            LDAP_OPERATIONS_ERROR = 1,

            //LDAP_PROTOCOL_ERROR = 2,
            LDAP_TIMELIMIT_EXCEEDED = 3,

            LDAP_SIZELIMIT_EXCEEDED = 4,

            //LDAP_COMPARE_FALSE = 5,
            //LDAP_COMPARE_TRUE = 6,
            LDAP_AUTH_METHOD_NOT_SUPPORTED = 7,

            //LDAP_STRONG_AUTH_REQUIRED = 8,
            //LDAP_REFERRAL = 9,
            //LDAP_ADMIN_LIMIT_EXCEEDED = 11,
            //LDAP_UNAVAILABLE_CRITICAL_EXTENSION = 12,
            //LDAP_CONFIDENTIALITY_REQUIRED = 13,
            LDAP_SASL_BIND_IN_PROGRESS = 14,

            LDAP_NO_SUCH_ATTRIBUTE = 16,
            LDAP_UNDEFINED_TYPE = 17,

            //LDAP_INAPPROPRIATE_MATCHING = 18,
            LDAP_CONSTRAINT_VIOLATION = 19,

            LDAP_TYPE_OR_VALUE_EXISTS = 20,
            LDAP_INVALID_SYNTAX = 21,

            LDAP_NO_SUCH_OBJECT = 32,

            //LDAP_ALIAS_PROBLEM = 33,
            LDAP_INVALID_DN_SYNTAX = 34,

            //LDAP_IS_LEAF = 35,
            //LDAP_ALIAS_DEREF_PROBLEM = 36,

            //LDAP_INAPPROPRIATE_AUTH = 48,
            LDAP_INVALID_CREDENTIALS = 49,

            LDAP_INSUFFICIENT_ACCESS = 50,
            LDAP_BUSY = 51,
            LDAP_UNAVAILABLE = 52,
            LDAP_UNWILLING_TO_PERFORM = 53,
            //LDAP_LOOP_DETECT = 54,

            //LDAP_NAMING_VIOLATION = 64,
            LDAP_OBJECT_CLASS_VIOLATION = 65,

            LDAP_NOT_ALLOWED_ON_NONLEAF = 66,

            //LDAP_NOT_ALLOWED_ON_RDN = 67,
            LDAP_ALREADY_EXISTS = 68,

            //LDAP_NO_OBJECT_CLASS_MODS = 69,
            //LDAP_RESULTS_TOO_LARGE = 70,
            //LDAP_AFFECTS_MULTIPLE_DSAS = 71,
            //LDAP_OTHER = 80,

            LDAP_SERVER_DOWN = -1,
            //LDAP_LOCAL_ERROR = -2,
            //LDAP_ENCODING_ERROR = -3,
            //LDAP_DECODING_ERROR = -4,
            //LDAP_TIMEOUT = -5,
            //LDAP_AUTH_UNKNOWN = -6,
            //LDAP_FILTER_ERROR = -7,
            //LDAP_USER_CANCELLED = -8,
            //LDAP_PARAM_ERROR = -9,
            //LDAP_NO_MEMORY = -10,
            //LDAP_CONNECT_ERROR = -11,
            //LDAP_NOT_SUPPORTED = -12,
            //LDAP_CONTROL_NOT_FOUND = -13,
            //LDAP_NO_RESULTS_RETURNED = -14,
            //LDAP_MORE_RESULTS_TO_RETURN = -15,

            //LDAP_CLIENT_LOOP = -16,
            //LDAP_REFERRAL_LIMIT_EXCEEDED = -17,
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate bool VERIFYSERVERCERT(
            IntPtr connection,
            IntPtr pServerCert);

        [DllImport("wldap32", EntryPoint = "ldap_set_option", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ldap_set_option(IntPtr ld, uint option, ref uint invalue);

        [DllImport("wldap32", EntryPoint = "ldap_set_option", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ldap_set_option(IntPtr ld, uint option, IntPtr pointer);

        [DllImport("wldap32", EntryPoint = "ldap_connect", CharSet = CharSet.Ansi, SetLastError = true,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern uint ldap_connect(IntPtr ld, LDAP_TIMEVAL timeout);

        [DllImport("wldap32", EntryPoint = "ldap_initA", CharSet = CharSet.Ansi, SetLastError = true,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr ldap_init(string hostname, uint port);

        [DllImport("wldap32", EntryPoint = "ldap_sasl_bind_sA", CharSet = CharSet.Ansi,
            CallingConvention = CallingConvention.Cdecl)]
        public static extern int ldap_sasl_bind(
            [In] IntPtr ld,
            string dn, string mechanism,
            IntPtr cred,
            IntPtr serverctrls,
            IntPtr clientctrls,
            out IntPtr serverData);

        [StructLayout(LayoutKind.Sequential)]
        internal sealed class berval
        {
            public int bv_len;
            public IntPtr bv_val = IntPtr.Zero;

            public berval()
            {
            }
        }

        [DllImport("wldap32", EntryPoint = "ldap_get_optionW", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_get_option(IntPtr ld, int option, out int value);

        [DllImport("wldap32", EntryPoint = "ldap_searchW", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_search(
            IntPtr ld,
            string @base,
            int scope,
            string filter,
            IntPtr attrs,
            int attrsonly);

        [StructLayout(LayoutKind.Sequential)]
        public sealed class LDAP_TIMEVAL
        {
            public int tv_sec;
            public int tv_usec;
        }

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_result(
            IntPtr ld,
            int msgid,
            int all,
            LDAP_TIMEVAL timeout,
            ref IntPtr pMessage);

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_first_entry(
            IntPtr ld,
            IntPtr pMessage);

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_entry(
            IntPtr ld,
            IntPtr pMessage);

        [DllImport("wldap32", EntryPoint = "ldap_get_dnW", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_get_dn(IntPtr ld, IntPtr message);

        [DllImport("wldap32", EntryPoint = "ldap_first_attributeW", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_first_attribute(IntPtr ld, IntPtr entry, ref IntPtr ppBer);

        [DllImport("wldap32", EntryPoint = "ldap_next_attributeW", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_attribute(IntPtr ld, IntPtr entry, ref IntPtr ppBer);

        [DllImport("wldap32", EntryPoint = "ldap_next_attributeW", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_next_attribute(IntPtr ld, IntPtr entry, IntPtr ppBer);

        [DllImport("wldap32", EntryPoint = "ldap_get_values_lenW", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr ldap_get_values_len(IntPtr ld, IntPtr entry, IntPtr pBer);

        [DllImport("wldap32", EntryPoint = "ldap_modify_s", CharSet = CharSet.Unicode,
            CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_modify_s(IntPtr ld, string dn, IntPtr mods);

        [DllImport("wldap32", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ldap_unbind(IntPtr ld);

        [DllImport("wldap32", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void ldap_value_free_len(IntPtr vals);

        public const int OS_ANYSERVER = 29;

        [DllImport("shlwapi.dll", SetLastError = true, EntryPoint = "#437")]
        public static extern bool IsOS(int os);
    }
}