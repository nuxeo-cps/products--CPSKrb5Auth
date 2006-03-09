
CPSKrb5Auth replaces Zope's CookieCrumbler. It can be used with CPS3.4
out-of-the-box. Since no modifications of the user folder are performed, all
CPSUserFolder features are available by default (group management, role
blocking, directory backends, ...)

CPSKrb5Auth authenticates users against krb5 (or against any service that can
match a username against a password) and stores the authentication information
in the request just before it gets published.

The password is transmitted only during the authentication phase. A client
certificate (CLCert) is then used afterwards to know that the user has been
authenticated.

The certificate is stored on the server in RAM. It contains information about:

- the browser id (a.k.a ZopeId)
- the name of the remote host.

the user's session expires when the RAM cache is cleaned up (see the RAM cache
manager's 'Cleanup interval' option)
