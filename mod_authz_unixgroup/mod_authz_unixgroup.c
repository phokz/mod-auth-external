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

/*
 *  Data type for per-directory configuration
 */

typedef struct
{
    int  enabled;
    int  authoritative;

} authz_unixgroup_dir_config_rec;


/*
 * Creator for per-dir configurations.  This is called via the hook in the
 * module declaration to allocate and initialize the per-directory
 * configuration data structures declared above.
 */

static void *create_authz_unixgroup_dir_config(apr_pool_t *p, char *d)
{
    authz_unixgroup_dir_config_rec *dir= (authz_unixgroup_dir_config_rec *)
	apr_palloc(p, sizeof(authz_unixgroup_dir_config_rec));

    dir->enabled= 0;
    dir->authoritative= 1;	/* strong by default */

    return dir;
}


/*
 * Config file commands that this module can handle
 */

static const command_rec authz_unixgroup_cmds[] =
{
    AP_INIT_FLAG("AuthzUnixgroup",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authz_unixgroup_dir_config_rec, enabled),
	OR_AUTHCFG,
	"Set to 'on' to enable unix group checking"),

    AP_INIT_FLAG("AuthzUnixgroupAuthoritative",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authz_unixgroup_dir_config_rec, authoritative),
	OR_AUTHCFG,
	"Set to 'off' to allow access control to be passed along to lower "
	    "modules if this module can't confirm access rights" ),

    { NULL }
};


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
	w= ap_getword_white(r->pool, &grouplist);
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


static int authz_unixgroup_check_user_access(request_rec *r) 
{
    authz_unixgroup_dir_config_rec *dir= (authz_unixgroup_dir_config_rec *)
	ap_get_module_config(r->per_dir_config, &authz_unixgroup_module);

    int m= r->method_number;
    int required_group= 0;
    register int x;
    const char *t, *w;
    const apr_array_header_t *reqs_arr= ap_requires(r);
    const char *filegroup= NULL;
    require_line *reqs;

    /* If not enabled, pass */
    if ( !dir->enabled ) return DECLINED;

    /* If there are no Require arguments, pass */
    if (!reqs_arr) return DECLINED;
    reqs=  (require_line *)reqs_arr->elts;

    /* Loop through the "Require" argument list */
    for(x= 0; x < reqs_arr->nelts; x++)
    {
	if (!(reqs[x].method_mask & (AP_METHOD_BIT << m))) continue;

	t= reqs[x].requirement;
	w= ap_getword_white(r->pool, &t);

	/* The 'file-group' directive causes mod_authz_owner to store the
	 * group name of the file we are trying to access in a note attached
	 * to the request.  It's our job to decide if the user actually is
	 * in that group.  If the note is missing, we just ignore it.
	 * Probably mod_authz_owner is not installed.
	 */
	if ( !strcasecmp(w, "file-group"))
	{
	    filegroup= apr_table_get(r->notes, AUTHZ_GROUP_NOTE);
	    if (filegroup == NULL) continue;
	}

	if ( !strcmp(w,"group") || filegroup != NULL)
	{
	    required_group= 1;

	    if (filegroup)
	    {
		/* Check if user is in the group that owns the file */
		if (check_unix_group(r,filegroup))
		    return OK;
	    }
	    else if (t[0])
	    {
		/* Pass rest of require line to authenticator */
		if (check_unix_group(r,t))
		    return OK;
	    }
	}
    }
    
    /* If we didn't see a 'require group' or aren't authoritive, decline */
    if (!required_group || !dir->authoritative)
	return DECLINED;

    /* Authentication failed and we are authoritive, declare unauthorized */
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
    	"access to %s failed, reason: user %s not allowed access",
    	r->uri, r->user);

    ap_note_basic_auth_failure(r);
    return HTTP_UNAUTHORIZED;
}

static void authz_unixgroup_register_hooks(apr_pool_t *p)
{
    ap_hook_auth_checker(authz_unixgroup_check_user_access, NULL, NULL,
	    APR_HOOK_MIDDLE);
}
    

module AP_MODULE_DECLARE_DATA authz_unixgroup_module = {
    STANDARD20_MODULE_STUFF,
    create_authz_unixgroup_dir_config,	  /* create per-dir config */
    NULL,			          /* merge per-dir config */
    NULL,			          /* create per-server config */
    NULL,			          /* merge per-server config */
    authz_unixgroup_cmds,	          /* command apr_table_t */
    authz_unixgroup_register_hooks        /* register hooks */
};
