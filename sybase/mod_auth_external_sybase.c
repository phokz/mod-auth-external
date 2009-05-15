/* ====================================================================
 * Copyright (c) 1997 Societe Generale.  All rights reserved.
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
 *    "This product includes software developed by Societe Generale"
 *
 * 4. The name "Societe Generale" must not be used to endorse or
 *		promote products derived from this software without prior written
 *		permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Societe Generale"
 *
 * THIS SOFTWARE IS PROVIDED BY SOCIETE GENERALE ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL SOCIETE GENERALE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


/* mod_auth_external_sybase.c 1.2 - apache authentication using
 *                                  mod_auth_external HARCODE extension.
 *
 * To edit this file, use 3-characters tabs.
 *
 * REVISIONS:
 *		1.0: br, may 15 1997
 *		1.1: br, may 21 1997
 *				added some log facilities, due to PASS variable problem...
 *		1.2: br, june 5 1997
 *				updated code to use mod_auth_external HARDCODE extension
 *				changed log usage
 *
 * TO DO:
 *		- check for sybase failures, and eventually try new connexions
 *		- add config file facility
 *		- permit multiple config files
 *
 */

#undef STATUS							/* to permit correct apache compilation */

#include <stdio.h>			      /* for those who like comments */
#include <string.h>
#include <stdlib.h>
#include	<errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include	<sybfront.h>
#include	<sybdb.h>
#include	<syberror.h>

/* sybase constants: ugly, but they will *NEVER* change...
 */
#define	DBUSER	"cleopatra"	  /* user */
#define	DBPASS	"noufnouf"	  /* passwd */
#define	DBNAME	"ISIS"		  /* basename */

#define	LOGFILE	"/var/log/www/checkpass" /* to log USER/PASS info */

/* openbase() - open database...
 *
 * return value:
 *		NULL: cannot access database
 *		other: DBPROCESS id.
 *
 */
DBPROCESS *openbase()
{
	LOGINREC *login = NULL;

	if (dbinit() == FAIL)		  /* get login */
		return NULL;
	login = dblogin();

	DBSETLUSER(login, DBUSER);	  /* set user & passwd database access */
 	DBSETLPWD(login, DBPASS);

	return dbopen(login, DBNAME); /* open connexion */
}

/* sybasecheck(user, passwd, conf)
 *		char *passwd, *passwd, *conf;
 *
 */
sybasecheck(user, pass, conf)
	char *user, *pass, *conf;
{
	static DBPROCESS *dbproc = NULL;
	char gotpass[256];
	int debug = 1;					  /* change this and recompile to have some
											* debugging
											*/
	int status;
	FILE *debugfile = NULL;

	if (debug) {					  /* open log file */
		debugfile = fopen(LOGFILE, "a+");
	}
	if (debugfile) {
		fprintf(debugfile, "sybasecheck: USER = <%s> ",
				  user? user: "<NULL>");
		fprintf(debugfile, "PASS = <%s> ", pass? pass: "<NULL>");
	}

	if (user && pass) {			  /* got something? */
		if (!dbproc) {
			dbproc = openbase();	  /* open database */
			if (debugfile) {
				fprintf(debugfile, " [%d]: opened base [%#x] ",
						  (int) getpid(), dbproc);
			}
		}
		else {
			if (debugfile) {
				fprintf(debugfile, " [%d]: base [%#x] ",
						  (int) getpid(), dbproc);
			}
		}

		if (dbproc) {
			/* we generate sql request. It looks like:
			 *  select passwd from users where login=$USER
			 */
			dbfcmd(dbproc, "select passwd from users where login = \"%s\"", user);

			if (dbsqlexec(dbproc) == SUCCEED) {

				if (dbresults(dbproc) == SUCCEED) {

					/* we bind the results to gotpasss string & check if we
					 * got something...
					 */
					if ((dbbind(dbproc, 1, NTBSTRINGBIND,
									sizeof(gotpass), gotpass) == SUCCEED) &&
						 ((status = dbnextrow(dbproc)) != FAIL) &&
						 (status != NO_MORE_ROWS)) {

						if (debugfile) {
							fprintf(debugfile, "GOTPASS = <%s>\n",
									  gotpass? gotpass: "<NULL>");
							fclose(debugfile);
						}

						/* ok: compare result to PASS variable, and exit
						 */
						return(strcmp(gotpass, pass)? 1: 0);
					}

					/* all rest are sybase errors...
					 */
					else
						if (debugfile)
							fprintf(debugfile, "error accessing database.\n");
				}
				else
					if (debugfile)
						fprintf(debugfile, "error dbresults.\n");
			}
			else {
				if (debugfile)
					fprintf(debugfile, "error in dbsqlexec.\n");
			}
		}
		else
			if (debugfile)
				fprintf(debugfile, "error in dbopen.\n");
	}
	if (debugfile)
		fclose(debugfile);

	return (1);

}

