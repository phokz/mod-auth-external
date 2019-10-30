/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
 * Copyright (c) Nathan Neulinger, Tyler Allison, Jan Wolter and
 *               other contributors. Please see CONTRIBUTORS.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/* Uncomment if you want to use a HARDCODE'd check (default off) */
/* #define _HARDCODE_ */

#ifdef _HARDCODE_
  /* Uncomment if you want to use your own Hardcode (default off) */
  /*             MUST HAVE _HARDCODE_ defined above!              */
  /* #include "your_function_here.c" */
#endif


#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"
#include "apr_signal.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_sha1.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef STANDARD20_MODULE_STUFF
#error This module requires Apache 2.2.0 or later.
#endif

/* Names of environment variables used to pass data to authenticator */
#define ENV_USER	"USER"
#define ENV_PASS	"PASS"
#define ENV_GROUP	"GROUP"
#define ENV_URI		"URI"
#define ENV_IP		"IP"
#define ENV_HOST	"HOST"			/* Remote Host */
#define ENV_HTTP_HOST	"HTTP_HOST"	/* Local Host */
#define ENV_CONTEXT	"CONTEXT"		/* Arbitrary Data from Config */
#define ENV_METHOD	"METHOD"		/* Request method (eg. GET, HEAD, POST, OPTIONS, etc.) */
/* Undefine this if you do not want cookies passed to the script */
#define ENV_COOKIE	"COOKIE"

/* Maximum number of arguments passed to an authenticator */
#define MAX_ARG 32

/* Default authentication method - "pipe", "environment" or "checkpass" */
#define DEFAULT_METHOD "pipe"

/*
 * Structure for the module itself.  The actual definition of this structure
 * is at the end of the file.
 */
module AP_MODULE_DECLARE_DATA authnz_external_module;

/*
 *  Data types for per-directory and per-server configuration
 */

typedef struct
{
	apr_array_header_t *auth_name;	/* Auth keyword for current dir */
	char *group_name;				/* Group keyword for current dir */
	char *context;					/* Context string from AuthExternalContext */
	int  groupsatonce;				/* Check all groups in one call? */
	int  providecache;				/* Provide auth data to mod_authn_socache? */
	int  authncheck;				/* Check for previous authentication? */

} authnz_external_dir_config_rec;


typedef struct
{
	apr_table_t *auth_path;			/* Hash mapping auth keywords to paths */
	apr_table_t *auth_method;		/* Hash mapping auth keywords to methods */

	apr_table_t *group_path;		/* Hash mapping group keywords to paths */
	apr_table_t *group_method;		/* Hash mapping group keywords to methods */

} authnz_external_svr_config_rec;


/* mod_authz_owner's function for retrieving the requested file's group */
APR_DECLARE_OPTIONAL_FN(char*, authz_owner_get_file_group, (request_rec *r));
APR_OPTIONAL_FN_TYPE(authz_owner_get_file_group) *authz_owner_get_file_group;

/* mod_authn_socache's function for adding credentials to its cache */
static APR_OPTIONAL_FN_TYPE(ap_authn_cache_store) *authn_cache_store = NULL;


/* Creators for per-dir and server configurations.  These are called
 * via the hooks in the module declaration to allocate and initialize
 * the per-directory and per-server configuration data structures declared
 * above. */

static void *create_authnz_external_dir_config(apr_pool_t *p, char *d)
{
	authnz_external_dir_config_rec *dir = (authnz_external_dir_config_rec *)
		apr_palloc(p, sizeof(authnz_external_dir_config_rec));

	dir->auth_name = apr_array_make(p, 2, sizeof(const char *)); /* no default */
	dir->group_name = NULL;		/* no default */
	dir->context = NULL;		/* no default */
	dir->groupsatonce = 1;		/* default to on */
	dir->providecache = 0;		/* default to off */
	dir->authncheck = 1;		/* default to on */
	return dir;
}

static void *create_authnz_external_svr_config(apr_pool_t *p, server_rec *s)
{
	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		apr_palloc(p, sizeof(authnz_external_svr_config_rec));

	svr->auth_method = apr_table_make(p, 4);
	svr->auth_path = apr_table_make(p, 4);
	svr->group_method = apr_table_make(p, 4);
	svr->group_path = apr_table_make(p, 4);
	/* Note: 4 is only initial hash size - they can grow bigger) */

	return (void *)svr;
}

/* Handler for a DefineExternalAuth server config line */
static const char *def_extauth(cmd_parms *cmd, void *dummy, const char *keyword,
	const char *method, const char *path)
{
	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(cmd->server->module_config,
			&authnz_external_module);

	apr_table_set(svr->auth_path, keyword, path);
	apr_table_set(svr->auth_method, keyword, method);

	return NULL;
}


/* Handler for a DefineExternalGroup server config line */
static const char *def_extgroup(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *method, const char *path)
{
	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(cmd->server->module_config,
			&authnz_external_module);

	apr_table_set(svr->group_path, keyword, path);
	apr_table_set(svr->group_method, keyword, method);

	return NULL;
}



/* Handler for a AddExternalAuth server config line - add a external auth
 * type to the server configuration */
static const char *add_extauth(cmd_parms *cmd, void *dummy, const char *keyword,
	const char *path)
{
	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(cmd->server->module_config,
			&authnz_external_module);

	apr_table_set(svr->auth_path, keyword, path);
	apr_table_set(svr->auth_method, keyword, DEFAULT_METHOD);

	return NULL;
}


/* Handler for a AddExternalGroup server config line - add a external group
 * type to the server configuration */
static const char *add_extgroup(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *path)
{
	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(cmd->server->module_config,
			&authnz_external_module);

	apr_table_set(svr->group_path, keyword, path);
	apr_table_set(svr->group_method, keyword, DEFAULT_METHOD);

	return NULL;
}

/* Handler for a SetExternalAuthMethod server config line - change an external
 * auth method in the server configuration */
static const char *set_authnz_external_method(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *method)
{
	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(cmd->server->module_config,
			&authnz_external_module);

	apr_table_set(svr->auth_method, keyword, method);

	return NULL;
}


/* Handler for a SetExternalGroupMethod server config line - change an external
 * group method in the server configuration */
static const char *set_extgroup_method(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *method)
{
	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(cmd->server->module_config,
			&authnz_external_module);

	apr_table_set(svr->group_method, keyword, method);

	return NULL;
}

/* Handler for an AuthExternal directive:
 * appends an argument to an array defined by the offset */
static const char *append_array_slot(cmd_parms *cmd, void *struct_ptr,
	const char *arg)
{
	int offset = (int)(size_t)cmd->info;
	apr_array_header_t *array =
		*(apr_array_header_t **)((char *)struct_ptr + offset);

	*(const char **)apr_array_push(array) = apr_pstrdup(array->pool, arg);

	return NULL;
}


/* Config file directives for this module */
static const command_rec authnz_external_cmds[] =
{
	AP_INIT_ITERATE("AuthExternal",
	append_array_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec,auth_name),
	OR_AUTHCFG,
	"one (or more) keywords indicating which authenticators to use"),

	AP_INIT_TAKE3("DefineExternalAuth",
	def_extauth,
	NULL,
	RSRC_CONF,
	"a keyword followed by auth method and path to authenticator"),

	AP_INIT_TAKE2("AddExternalAuth",
	add_extauth,
	NULL,
	RSRC_CONF,
	"a keyword followed by a path to the authenticator program"),

	AP_INIT_TAKE2("SetExternalAuthMethod",
	set_authnz_external_method,
	NULL,
	RSRC_CONF,
	"a keyword followed by the method by which the data is passed"),

	AP_INIT_TAKE1("GroupExternal",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, group_name),
	OR_AUTHCFG,
	"a keyword indicating which group checker to use"),

	AP_INIT_TAKE3("DefineExternalGroup",
	def_extgroup,
	NULL,
	RSRC_CONF,
	"a keyword followed by auth method type and path to group checker"),

	AP_INIT_TAKE2("AddExternalGroup",
	add_extgroup,
	NULL,
	RSRC_CONF,
	"a keyword followed by a path to the group check program"),

	AP_INIT_TAKE2("SetExternalGroupMethod",
	set_extgroup_method,
	NULL,
	RSRC_CONF,
	"a keyword followed by the method by which the data is passed"),

	AP_INIT_TAKE1("AuthExternalContext",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, context),
	OR_AUTHCFG,
	"An arbitrary context string to pass to the authenticator in the "
	ENV_CONTEXT " environment variable"),

	AP_INIT_FLAG("AuthExternalProvideCache",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, providecache),
	OR_AUTHCFG,
	"Should we forge authentication credentials for mod_authn_socache?"),

	AP_INIT_FLAG("GroupExternalManyAtOnce",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, groupsatonce),
	OR_AUTHCFG,
	"Set to 'off' if group authenticator cannot handle multiple group "
		"names in one invocation"),

	AP_INIT_FLAG("AuthExternalGroupsAtOnce",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, groupsatonce),
	OR_AUTHCFG,
	"Old version of 'GroupExternalManyAtOnce'"),

	AP_INIT_FLAG("GroupExternalAuthNCheck",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, authncheck),
	OR_AUTHCFG,
	"Set to 'off' if group authenticator should skip checking whether "
		"user is validly authenticated"),

	{ NULL }
};

/* array handling helper functions */

/* Appends a C string to the end of the APR array */
static void apr_array_push_wrapper(apr_array_header_t *arr, const char *element) {
	*(const char**)apr_array_push(arr) = element;
}


/* Called from apr_proc_create() if there are errors during launch of child
 * process.  Mostly just lifted from mod_cgi. */
static void extchilderr(apr_pool_t *p, apr_status_t err, const char *desc)
{
	apr_file_t *stderr_log;
	char errbuf[200];
	apr_file_open_stderr(&stderr_log, p);
	apr_file_printf(stderr_log, "%s: (%d) %s\n", ap_escape_logitem(p, desc),
		err, apr_strerror(err, errbuf, sizeof(errbuf)));
}

/* Called from exec_external(). Retrieves any AUTHORIZE_ headers set by
 * other modules. */
int extgetauthheaders(void *destarray, const char *key, const char *value) {
	if (strstr(key, "AUTHORIZE")) {
		apr_array_header_t *child_env = (apr_array_header_t *)destarray;
		apr_array_push_wrapper(child_env, apr_pstrcat(child_env->pool, key, "=", value, NULL));
	}
	return 1; //continue
}


/* Run an external authentication program using the given method for passing
 * in the data.  The login name is always passed in.   Dataname is "GROUP" or
 * "PASS" and data is the group list or password being checked.  To launch
 * a detached daemon, run this with extmethod=NULL.
 *
 * If the authenticator was run, we return the numeric code from the
 * authenticator, normally 0 if the login was valid, some small positive
 * number if not.  If we were not able to run the authenticator, we log
 * an error message and return a numeric error code:
 *
 *   -1   Could not execute authenticator, usually a path or permission problem
 *   -2   The external authenticator crashed or was killed.
 *   -3   Could not create process attribute structure
 *   -4   apr_proc_wait() did not return a status code.  Should never happen.
 *   -5   apr_proc_wait() returned before child finished.  Should never happen.
 */
static int exec_external(const char *extpath, const char *extmethod,
	const request_rec *r, const char *dataname, const char *data)
{
	conn_rec *c = r->connection;
	apr_pool_t *p = r->pool;
	int isdaemon, usecheck = 0, usepipeout = 0, usepipein = 0;
	apr_procattr_t *procattr;
	apr_proc_t proc;
	apr_status_t rc = APR_SUCCESS;
	apr_array_header_t *child_env = apr_array_make(p, 16, sizeof(char *));
	char *child_arg[MAX_ARG + 2];
	const char *t;
	int i, status = -4;
	apr_exit_why_e why = APR_PROC_EXIT;
#ifndef _WINDOWS
	apr_sigfunc_t *sigchld;
#endif

	/* Set various flags based on the execution method */

	isdaemon = (extmethod == NULL);
	if (!isdaemon)
	{
		usecheck = extmethod && !strcasecmp(extmethod, "checkpassword");
		usepipeout = usecheck || (extmethod && !strcasecmp(extmethod, "pipes"));
		usepipein = usepipeout || (extmethod && !strcasecmp(extmethod, "pipe"));
	}

	/* Create the environment for the child.  Daemons don't get these, they
	 * just inherit apache's environment variables.
	 */

	if (!isdaemon)
	{
		const char *cookie, *host, *remote_host;
		authnz_external_dir_config_rec *dir = (authnz_external_dir_config_rec *)
			ap_get_module_config(r->per_dir_config, &authnz_external_module);
		i = 0;

		if (!usepipein)
		{
			/* Put user name and password/group into environment */
			apr_array_push_wrapper(child_env, apr_pstrcat(p, ENV_USER"=", r->user, NULL));
			apr_array_push_wrapper(child_env, apr_pstrcat(p, dataname, "=", data, NULL));
		}

		apr_array_push_wrapper(child_env, apr_pstrcat(p, "PATH=", getenv("PATH"), NULL));

		apr_array_push_wrapper(child_env, apr_pstrcat(p, "AUTHTYPE=", dataname, NULL));

		remote_host = ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST, NULL);
		if (remote_host != NULL)
			apr_array_push_wrapper(child_env, apr_pstrcat(p, ENV_HOST"=", remote_host, NULL));

		if (r->useragent_ip)
			apr_array_push_wrapper(child_env, apr_pstrcat(p, ENV_IP"=", r->useragent_ip, NULL));

		if (r->uri)
			apr_array_push_wrapper(child_env, apr_pstrcat(p, ENV_URI"=", r->uri, NULL));

		if (r->method)
			apr_array_push_wrapper(child_env, apr_pstrcat(p, ENV_METHOD"=", r->method, NULL));

		if ((host = apr_table_get(r->headers_in, "Host")) != NULL)
			apr_array_push_wrapper(child_env, apr_pstrcat(p, ENV_HTTP_HOST"=", host, NULL));

		if (dir->context)
			apr_array_push_wrapper(child_env, apr_pstrcat(r->pool, ENV_CONTEXT"=", dir->context, NULL));

#ifdef ENV_COOKIE
		if ((cookie = apr_table_get(r->headers_in, "Cookie")) != NULL)
			apr_array_push_wrapper(child_env, apr_pstrcat(p, ENV_COOKIE"=", cookie, NULL));
#endif

#ifdef _WINDOWS
		apr_array_push_wrapper(child_env, apr_pstrcat(r->pool, "SystemRoot=", getenv("SystemRoot"), NULL));
#endif

		/* Retrieve any AUTHORIZE_ headers set by other modules */
		apr_table_do(extgetauthheaders, (void *)child_env, r->subprocess_env, NULL);

		/* End of environment */
		apr_array_push_wrapper(child_env, NULL);
	}

	/* Construct argument array */
	for (t = extpath, i = 0;
		*t != '\0' && (i <= MAX_ARG + 1);
		child_arg[i++] = ap_getword_white(p, &t))
	{
	}
	child_arg[i] = NULL;

	/* Create the process attribute structure describing the script we
	 * want to run using the Thread/Process functions from the Apache
	 * portable runtime library. */

	if (((rc = apr_procattr_create(&procattr, p)) != APR_SUCCESS) ||

		/* should we create pipes to stdin, stdout and stderr? */
		((rc = apr_procattr_io_set(procattr,
		(usepipein && !usecheck) ? APR_FULL_BLOCK : APR_NO_PIPE,
			usepipeout ? APR_FULL_BLOCK : APR_NO_PIPE,
			(usepipein && usecheck) ? APR_FULL_BLOCK : APR_NO_PIPE))
			!= APR_SUCCESS) ||

		/* will give full path of program and make a new environment */
			((rc = apr_procattr_cmdtype_set(procattr,
				isdaemon ? APR_PROGRAM_ENV : APR_PROGRAM)) != APR_SUCCESS) ||

		/* detach the child only if it is a daemon */
				((rc = apr_procattr_detach_set(procattr, isdaemon)) != APR_SUCCESS) ||

		/* function to call if child has error after fork, before exec */
		((rc = apr_procattr_child_errfn_set(procattr, extchilderr))
			!= APR_SUCCESS))
	{
		/* Failed.  Probably never happens. */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
			"could not set child process attributes");
		return -3;
	}

	/* Sometimes other modules wil mess up sigchild.  Need to fix it for
	 * the wait call to work correctly. (However, there's no need to fix
	 * the handler on Windows, since there are no signals on Windows.) */
#ifndef _WINDOWS
	sigchld = apr_signal(SIGCHLD, SIG_DFL);
#endif

	/* Start the child process */
	rc = apr_proc_create(&proc, child_arg[0],
		(const char * const *)child_arg,
		(const char * const *)child_env->elts, procattr, p);
	if (rc != APR_SUCCESS)
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
			"Could not run external authenticator: %d: %s", rc,
			child_arg[0]);
		return -1;
	}

	if (isdaemon) return 0;

	apr_pool_note_subprocess(p, &proc, APR_KILL_AFTER_TIMEOUT);

	if (usepipein)
	{
		/* Select appropriate pipe to write to */
		apr_file_t *pipe = (usecheck ? proc.err : proc.in);

		/* Send the user */
		apr_file_write_full(pipe, r->user, strlen(r->user), NULL);
		apr_file_putc(usecheck ? '\0' : '\n', pipe);

		/* Send the password */
		apr_file_write_full(pipe, data, strlen(data), NULL);
		apr_file_putc(usecheck ? '\0' : '\n', pipe);

		/* Send dummy timestamp for checkpassword */
		if (usecheck) apr_file_write_full(pipe, "0", 2, NULL);

		/* Close the file */
		apr_file_close(pipe);
	}

	/* Wait for the child process to terminate, and get status */
	rc = apr_proc_wait(&proc, &status, &why, APR_WAIT);

	/* Restore sigchild to whatever it was before we reset it */
#ifndef _WINDOWS
	apr_signal(SIGCHLD, sigchld);
#endif

	if (!APR_STATUS_IS_CHILD_DONE(rc))
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
			"Could not get status from child process");
		return -5;
	}
	if (!APR_PROC_CHECK_EXIT(why))
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"External authenticator died on signal %d", status);
		return -2;
	}

	return status;
}


/* Call the hardcoded function specified by the external path.  Of course,
 * you'll have to write the hardcoded functions yourself and insert them
 * into this source file, as well as inserting a call to them into this
 * routine.
 */
static int exec_hardcode(const request_rec *r, const char *extpath,
	const char *password)
{
#ifdef _HARDCODE_
	char *check_type;		/* Pointer to HARDCODE type check  */
	char *config_file;		/* Pointer to HARDCODE config file */
	int standard_auth = 0;

	/* Parse a copy of extpath into type and filename */
	check_type = apr_pstrdup(r->pool, extpath);
	config_file = strchr(check_type, ':');
	if (config_file != NULL)
	{
		*config_file = '\0';	/* Mark end of type */
		config_file++;			/* Start of filename */
	}

	/* This is where you make your function call.  Here is an example of
	 * what one looks like:
	 *
	 *   if (strcmp(check_type,"RADIUS")==0)
	 *      code= radcheck(r->user,password,config_file);
	 *
	 * Replace 'radcheck' with whatever the name of your function is.
	 * Replace 'RADIUS' with whatever you are using as the <type> in:
	 *     AddExternalAuth <keyword> <type>:<config file>
	 */

	if (strcmp(check_type, "EXAMPLE") == 0)		/* change this! */
		code = example(r->user, password, config_file);	/* change this! */
	else
		code = -5;
	return code;
#else
	return -4;		/* If _HARDCODE_ is not defined, always fail */
#endif /* _HARDCODE_ */
}


/* Handle a group check triggered by a 'Require external-group foo bar baz'
 * directive. */
static authz_status externalgroup_check_authorization(request_rec *r,
	const char *require_args, const void *parsed_require_args)
{
	authnz_external_dir_config_rec *dir = (authnz_external_dir_config_rec *)
		ap_get_module_config(r->per_dir_config, &authnz_external_module);

	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(r->server->module_config, &authnz_external_module);

	char *user = r->user;
	char *extname = dir->group_name;
	const char *extpath, *extmethod;
	const char *t, *w;
	int code = 0;

	if (dir->authncheck) {
		/* If no authenticated user, pass */
		if (!user) return AUTHZ_DENIED_NO_USER;
	}
	else {
		/* Prevent crash due to missing user */
		if (!user) r->user = "";
	}

	/* If no external authenticator has been configured, pass */
	if (!extname) return AUTHZ_DENIED;

	/* Get the path and method associated with that external */
	if (!(extpath = apr_table_get(svr->group_path, extname)) ||
		!(extmethod = apr_table_get(svr->group_method, extname)))
	{
		errno = 0;
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"invalid GroupExternal keyword (%s)", extname);
		return AUTHZ_DENIED;
	}

	if (dir->groupsatonce)
	{
		/* Pass rest of require line to authenticator */
		code = exec_external(extpath, extmethod, r, ENV_GROUP, require_args);
		if (code == 0) return AUTHZ_GRANTED;
	}
	else
	{
		/* Call authenticator once for each group name on line */
		t = require_args;
		while ((w = ap_getword_conf(r->pool, &t)) && w[0])
		{
			code = exec_external(extpath, extmethod, r, ENV_GROUP, w);
			if (code == 0) return AUTHZ_GRANTED;
		}
	}

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"Authorization of user %s to access %s failed. "
		"User not in Required group. Last result code: %i",
		r->user, r->uri, code);

	return AUTHZ_DENIED;
}


/* Handle a group check triggered by a 'Require external-file-group'
 * directive. */
static authz_status externalfilegroup_check_authorization(request_rec *r,
	const char *require_args, const void *parsed_require_args)
{
	authnz_external_dir_config_rec *dir = (authnz_external_dir_config_rec *)
		ap_get_module_config(r->per_dir_config, &authnz_external_module);

	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(r->server->module_config, &authnz_external_module);

	char *user = r->user;
	char *extname = dir->group_name;
	const char *extpath, *extmethod;
	const char *filegroup = NULL;
	int code;

	if (dir->authncheck) {
		/* If no authenticated user, pass */
		if (!user) return AUTHZ_DENIED_NO_USER;
	}
	else {
		/* Prevent crash due to missing user */
		if (!user) r->user = "";
	}

	/* If no external authenticator has been configured, pass */
	if (!extname) return AUTHZ_DENIED;

	/* Get the path and method associated with that external */
	if (!(extpath = apr_table_get(svr->group_path, extname)) ||
		!(extmethod = apr_table_get(svr->group_method, extname)))
	{
		errno = 0;
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"invalid GroupExternal keyword (%s)", extname);
		return AUTHZ_DENIED;
	}

	/* Get group name for requested file from mod_authz_owner */
	filegroup = authz_owner_get_file_group(r);

	if (!filegroup)
		/* No errog log entry, because mod_authz_owner already made one */
		return AUTHZ_DENIED;

	/* Pass the group to the external authenticator */
	code = exec_external(extpath, extmethod, r, ENV_GROUP, filegroup);
	if (code == 0) return AUTHZ_GRANTED;

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"Authorization of user %s to access %s failed. "
		"User not in Required file group (%s).",
		r->user, r->uri, filegroup);

	return AUTHZ_DENIED;
}


/* Mod_authn_socache wants us to pass it the username and the encrypted
 * password from the user database to cache. But we have no access to the
 * actual user database - only the external authenticator can see that -
 * and chances are, the passwords there aren't encrypted in any way that
 * mod_authn_socache would understand anyway. So instead, after successful
 * authentications only, we take the user's plain text password, encrypt
 * that using an algorithm mod_authn_socache will understand, and cache that
 * as if we'd actually gotten it from a password database.
 */
void mock_turtle_cache(request_rec *r, const char *plainpw)
{
	char cryptpw[120];

	/* Authn_cache_store will be null if mod_authn_socache does not exist.
	 * If it does exist, but is not set up to cache us, then
	 * authn_cache_store() will do nothing, which is why we turn this off
	 * with "AuthExternalProvideCache Off" to avoid doing the encryption
	 * for no reason. */
	if (authn_cache_store != NULL)
	{
		apr_sha1_base64(plainpw, strlen(plainpw), cryptpw);
		authn_cache_store(r, "external", r->user, NULL, cryptpw);
	}
}


/* Password checker for basic authentication - given a login/password,
 * check if it is valid.  Returns one of AUTH_DENIED, AUTH_GRANTED,
 * or AUTH_GENERAL_ERROR. */

static authn_status authn_external_check_password(request_rec *r,
	const char *user, const char *password)
{
	const char *extname, *extpath, *extmethod;
	int i;
	authnz_external_dir_config_rec *dir = (authnz_external_dir_config_rec *)
		ap_get_module_config(r->per_dir_config, &authnz_external_module);

	authnz_external_svr_config_rec *svr = (authnz_external_svr_config_rec *)
		ap_get_module_config(r->server->module_config,
			&authnz_external_module);
	int code = 1;

	/* Check if we are supposed to handle this authentication */
	if (dir->auth_name->nelts == 0)
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"No AuthExternal name has been set");
		return AUTH_GENERAL_ERROR;
	}

	for (i = 0; i < dir->auth_name->nelts; i++)
	{
		extname = ((const char **)dir->auth_name->elts)[i];

		/* Get the path associated with that external */
		if (!(extpath = apr_table_get(svr->auth_path, extname)))
		{
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Invalid AuthExternal keyword (%s)", extname);
			return AUTH_GENERAL_ERROR;
		}

		/* Do the authentication, by the requested method */
		extmethod = apr_table_get(svr->auth_method, extname);
		if (extmethod && !strcasecmp(extmethod, "function"))
			code = exec_hardcode(r, extpath, password);
		else
			code = exec_external(extpath, extmethod, r, ENV_PASS, password);

		/* If return code was zero, authentication succeeded */
		if (code == 0)
		{
			if (dir->providecache) mock_turtle_cache(r, password);
			return AUTH_GRANTED;
		}

		/* Log a failed authentication */
		errno = 0;
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"AuthExtern %s [%s]: Failed (%d) for user %s",
			extname, extpath, code, r->user);
	}
	/* If no authenticators succeed, refuse authentication */
	return AUTH_DENIED;
}


#if 0
/* Password checker for digest authentication - given a login/password,
 * check if it is valid.  Returns one of AUTH_USER_FOUND, AUTH_USER_NOT_FOUND,
 * or AUTH_GENERAL_ERROR.   Not implemented at this time and probably not ever.
 */

auth_status *authn_external_get_realm_hash(request_rec *r, const char *user,
	const char *realm, char **rethash);
{
}
#endif

/* This is called after all modules have been initialized to acquire pointers
 * to some functions from other modules that we would like to use if they are
 * available. */
static void opt_retr(void)
{
	/* Get authn_cache_store from mod_authn_socache */
	authn_cache_store =
		APR_RETRIEVE_OPTIONAL_FN(ap_authn_cache_store);

	/* Get authz_owner_get_file_group from mod_authz_owner */
	authz_owner_get_file_group =
		APR_RETRIEVE_OPTIONAL_FN(authz_owner_get_file_group);
}

/* This tells mod_auth_basic and mod_auth_digest what to call for
 * authentication. */
static const authn_provider authn_external_provider =
{
	&authn_external_check_password,
#if 0
	& authn_external_get_realm_hash
#else
	NULL	/* No support for digest authentication */
#endif
};

/* This tells mod_auth_basic and mod_auth_digest what to call for
 * access control with 'Require external-group' directives. */
static const authz_provider authz_externalgroup_provider =
{
	&externalgroup_check_authorization,
	NULL,
};

/* This tells mod_auth_basic and mod_auth_digest what to call for
 * access control with 'Require external-file-group' directives. */
static const authz_provider authz_externalfilegroup_provider =
{
	&externalfilegroup_check_authorization,
	NULL,
};

/* Register this module with Apache */
static void register_hooks(apr_pool_t *p)
{
	/* Register authn provider */
	ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "external",
		AUTHN_PROVIDER_VERSION,
		&authn_external_provider, AP_AUTH_INTERNAL_PER_CONF);

	/* Register authz providers */
	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "external-group",
		AUTHZ_PROVIDER_VERSION,
		&authz_externalgroup_provider, AP_AUTH_INTERNAL_PER_CONF);

	ap_register_auth_provider(p, AUTHZ_PROVIDER_GROUP, "external-file-group",
		AUTHZ_PROVIDER_VERSION,
		&authz_externalfilegroup_provider, AP_AUTH_INTERNAL_PER_CONF);

	/* Ask for opt_retr() to be called after all modules have registered */
	ap_hook_optional_fn_retrieve(opt_retr, NULL, NULL, APR_HOOK_MIDDLE);
}


AP_DECLARE_MODULE(authnz_external) = {
	STANDARD20_MODULE_STUFF,
	create_authnz_external_dir_config,	/* create per-dir config */
	NULL,								/* merge per-dir config - dflt is override */
	create_authnz_external_svr_config,	/* create per-server config */
	NULL,								/* merge per-server config */
	authnz_external_cmds,				/* command apr_table_t */
	register_hooks						/* register hooks */
};
