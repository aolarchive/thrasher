thrashd  is a service which provides centralized rate-limiting services
to one or many clients.  While  it  does  not  have  the  authority  to
actively  block  connections, it determines whether a connection SHOULD
be blocked.

At the base, thrashd uses a simplistic ratio based model for  determin
ing  what  is  and what is not malicious, though more advanced features
can be enabled.

This was originally developed to facilitate a very large farm  of  web
servers, so many of the keywords and features may be HTTP sounding.

It is relased under the BSD license.
