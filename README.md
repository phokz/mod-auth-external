# mod-authnz-external
### Apache External Authentication Module
Previous Maintainers: Jan Wolter (http://www.unixpapa.com), Tyler Allison (allison@nas.nasa.gov)
  
Original Author: Nathan Neulinger (nneul@umr.edu)

**Mod_authnz_external is a flexible tool for building custom basic authentication systems for the [Apache HTTP Server](http://httpd.apache.org)**. "Basic Authentication" is a type of authentication built into the HTTP protocol, in which the browser automatically pops up a login box when the user requests a protected resource, and the login ids and passwords entered are checked by Apache. Mod_auth*_external allows the password checking normally done inside Apache to be done by an separate external program running outside of Apache.


### Security Considerations

Older versions of mod_auth_external would by default pass logins and passwords into the authentication module using environment variables. This is insecure on some versions of Unix where the contents of environment variables are visible on a 'ps -e' command. In more recent versions, the default is to use a pipe to pass sensitive data. This is secure on all versions of Unix, and is recommended in all installations.

People using mod_auth*_external with pwauth to authenticate from system password databases should be aware of the [innate security risks](http://code.google.com/p/pwauth/wiki/Risks) involved in doing this.
