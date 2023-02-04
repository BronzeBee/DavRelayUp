# DavRelayUp

This tool is basically [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) (90% of code shamelessly copy-pasted) with the whole RELAY phase replaced by good ol' HTTP-to-LDAP NTLM relay using `LockScreen.SetImageFileAsync()` trigger discovered by  [@elad_shamir](https://twitter.com/elad_shamir) back in August 2019. All the other attack phases (LDAP updates, TGT/TGS requests, service creation) remain unchanged.

The attack will only work on **domain-joined Windows 10 workstations**. It should also work on Windows Server 2016/2019 if WebDAV-Redirector feature is installed (by default it isn't).

Note that **it's not a new vulnerability/exploit** but just a handy wrapper around [@elad_shamir](https://twitter.com/elad_shamir)'s old coercion primitive compiled into a single binary. All of this can be achieved using impacket as the original research suggests.

Tested on Windows 10 22H2 Build 19045.2486 and Windows Server 2019 1809 Build 17763.3232.

Command-line arguments are almost identical to those of KrbRelayUp except for ADCS attack type which is not implemented since I was only targeting LDAP. Also, my WebDAV server implementation uses HttpListener class that can only listen on URL prefixes allowed by URL ACLs. By default it will bind to `http://*:5357/` (should be available to any user), but in case if you need another listen address, you can specify it using `-l/--Listen`; just make sure you have access to one (`netsh http show urlacl`).

## Acknowledgements

- [@elad_shamir](https://twitter.com/elad_shamir) for the [original research](https://shenaniganslabs.io/2019/08/08/Lock-Screen-LPE.html)
- [@saim1z](https://twitter.com/saim1z) and [attl4s](https://github.com/attl4s) for [Change-Lockscreen](https://github.com/nccgroup/Change-Lockscreen)
- [@Dec0ne](https://twitter.com/dec0ne) for [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp), make sure to visit Acknowledgements section there as well
