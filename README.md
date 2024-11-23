# mod-authnz-external [![Build Status](https://github.com/phokz/mod-auth-external/actions/workflows/build.yml/badge.svg)](https://github.com/phokz/mod-auth-external/actions/workflows/build.yml)
### External Authentication Module for Apache HTTP Server - [Apache License 1.0](https://www.apache.org/licenses/LICENSE-1.0)
Previous Maintainers: Jan Wolter (http://www.unixpapa.com), Tyler Allison (allison@nas.nasa.gov)
  
Original Author: Nathan Neulinger (nneul@umr.edu)

**Mod_authnz_external is a flexible tool for building custom basic authentication systems for the [Apache HTTP Server](http://httpd.apache.org)**. "Basic Authentication" is a type of authentication built into the HTTP protocol, in which the browser automatically pops up a login box when the user requests a protected resource, and the login ids and passwords entered are checked by Apache. Mod_auth*_external allows the password checking normally done inside Apache to be done by an separate external program running outside of Apache.

![high-level overview diagram of mod_authnz_external](/documentation/mod_authnz_external%20overview.png)

### Support Matrix

<table><thead><th>Apache Version</th><th>mod_authnz_external Version</th><th>mod_authz_unixgroup Version</th><th>Supported?</th></thead><tbody>
<tr><td rowspan='2'> Apache 2.4 </td><td> <b>mod_authnz_external 3.3.x</b> </td><td> <b>mod_authz_unixgroup 1.2.x</b> </td><td> Yes </td></tr>
<tr><td></td><td> mod_authz_unixgroup 1.1.x </td><td> - </td></tr>
<tr><td> Apache 2.2 </td><td> mod_authnz_external 3.1.x or 3.2.x </td><td> mod_authz_unixgroup 1.0.x </td><td> - </td></tr>
<tr><td> Apache 2.0 </td><td> mod_auth_external 2.2.x </td><td> - </td><td> - </td></tr>
<tr><td> Apache 1.3 </td><td> mod_auth_external 2.1.x </td><td> - </td><td> - </td></tr>
</tbody></table>

Older versions are provided on an as-is basis in this repo's [branch list](https://github.com/phokz/mod-auth-external/branches/all).

### Security Considerations

Older versions of mod_auth_external would by default pass logins and passwords into the authentication module using environment variables. This is insecure on some versions of Unix where the contents of environment variables are visible on a 'ps -e' command. In more recent versions, the default is to use a pipe to pass sensitive data. This is secure on all versions of Unix, and is recommended in all installations.

People using mod_auth*_external with pwauth to authenticate from system password databases should be aware of the [innate security risks](http://code.google.com/p/pwauth/wiki/Risks) involved in doing this.

### mod_authz_unixgroup

This repo is also the home of mod_authz_unixgroup, a unix group access control module for the [Apache HTTP Server](http://httpd.apache.org).

Source is available in the [mod_authz_unixgroup subfolder](https://github.com/phokz/mod-auth-external/tree/master/mod_authz_unixgroup), and releases can be found tagged with the "mod_authz_unixgroup-" prefix [here](https://github.com/phokz/mod-auth-external/tags).
