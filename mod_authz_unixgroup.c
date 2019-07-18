/* Copyright 2008 Jan Wolter - See LICENSE and NOTICE */

#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"	/* for ap_hook_(check_user_id | auth_checker)*/
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/*
 * Structure for the module itself.  The actual definition of this structure
 * is at the end of the file.
 */
module AP_MODULE_DECLARE_DATA authz_unixgroup_module;

/* A handle for retrieving the requested file's group from mod_authnz_owner */
APR_DECLARE_OPTIONAL_FN(char*, authz_owner_get_file_group, (request_rec *r));


/* Check if the named user is in the given list of groups.  The list of
 * groups is a string with groups separated by white space.  Group ids
 * can either be unix group names or numeric group id numbers.  There must
 * be a unix login corresponding to the named user.
 */

static int check_unix_group(request_rec *r, const char *grouplist)
{
    char **p;
    struct group *grp;
    char *user= r->user;
    char *w, *at;

    /* Strip @ sign and anything following it from the username.  Some
     * authentication modules, like mod_auth_kerb like appending such
     * stuff to user names, but an @ sign is never legal in a unix login
     * name, so it should be safe to always discard such stuff.
     */
    if ((at= strchr(user, '@')) != NULL) *at= '\0';

    /* Get info about login */
    struct passwd *pwd= getpwnam(user);
    if (pwd == NULL)
    {
	/* No such user - forget it */
	if (at != NULL) *at= '@';
    	return 0;
    }

    /* Loop through list of groups passed in */
    while (*grouplist != '\0')
    {
	w= ap_getword_conf(r->pool, &grouplist);
	if (apr_isdigit(w[0]))
	{
	    /* Numeric group id */
	    int gid= atoi(w);

	    /* Check if it matches the user's primary group */
	    if (gid == pwd->pw_gid)
	    {
		if (at != NULL) *at= '@';
		return 1;
	    }

	    /* Get list of group members for numeric group id */
	    grp= getgrgid(gid);
	}
	else
	{
	    /* Get gid and list of group members for group name */
	    grp= getgrnam(w);
	    /* Check if gid of this group matches user's primary gid */
	    if (grp != NULL && grp->gr_gid == pwd->pw_gid)
	    {
		if (at != NULL) *at= '@';
		return 1;
	    }
	}

	/* Walk through list of members, seeing if any match user login */
	if (grp != NULL)
	    for (p= grp->gr_mem; *p != NULL; p++)
	    {
		if (!strcmp(user, *p))
		{
		    if (at != NULL) *at= '@';
		    return 1;
		}
	    }
    }

    /* Didn't find any matches, flunk him */
    if (at != NULL) *at= '@';
    return 0;
}

static authz_status unixgroup_check_authorization(request_rec *r,
        const char *require_args, const void *parsed_require_args)
{
    /* If no authenticated user, pass */
    if ( !r->user ) return AUTHZ_DENIED_NO_USER;

    if (check_unix_group(r,require_args))
	return AUTHZ_GRANTED;

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
        "Authorization of user %s to access %s failed. "
        "User not in Required unix groups (%s).",
        r->user, r->uri, require_args);

    return AUTHZ_DENIED;
}

APR_OPTIONAL_FN_TYPE(authz_owner_get_file_group) *authz_owner_get_file_group;

static authz_status unixfilegroup_check_authorization(request_rec *r,
        const char *require_args, const void *parsed_require_args)
{
    const char *filegroup= NULL;

    /* If no authenticated user, pass */
    if ( !r->user ) return AUTHZ_DENIED_NO_USER;

    /* Get group name for requested file from mod_authz_owner */
    filegroup= authz_owner_get_file_group(r);

    if (!filegroup)
        /* No errog log entry, because mod_authz_owner already made one */
        return AUTHZ_DENIED;

    if (check_unix_group(r,filegroup))
	return AUTHZ_GRANTED;
    
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
        "Authorization of user %s to access %s failed. "
        "User not in Required unix file group (%s).",
        r->user, r->uri, filegroup);

    return AUTHZ_DENIED;
}

static const authz_provider authz_unixgroup_provider =
{
    &unixgroup_check_authorization,
    NULL,
};

static const authz_provider authz_unixfilegroup_provider =
{
    &unixfilegroup_check_authorization,
    NULL,
};

static void authz_unixgroup_register_hooks(apr_pool_t *p)
{
    /* Get a handle on mod_authz_owner */
    authz_owner_get_file_group = APR_RETRIEVE_OPTIONAL_FN(authz_owner_get_file_group);

    /* Register authz providers */
    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "unix-group",
            AUTHZ_PROVIDER_VERSION,
            &authz_unixgroup_provider, AP_AUTH_INTERNAL_PER_CONF);

    ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "unix-file-group",
            AUTHZ_PROVIDER_VERSION,
            &authz_unixfilegroup_provider, AP_AUTH_INTERNAL_PER_CONF);
}
    
module AP_MODULE_DECLARE_DATA authz_unixgroup_module = {
    STANDARD20_MODULE_STUFF,
    NULL,				  /* create per-dir config */
    NULL,			          /* merge per-dir config */
    NULL,			          /* create per-server config */
    NULL,			          /* merge per-server config */
    NULL,		         	  /* command apr_table_t */
    authz_unixgroup_register_hooks        /* register hooks */
};
