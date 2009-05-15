/*
 *
 *      RADIUS -- Remote Authentication Dial In User Service
 *
 * COPYRIGHT  (c)  1992, 1993, 1994, 1995, 1996
 * THE REGENTS OF THE UNIVERSITY OF MICHIGAN AND MERIT NETWORK, INCORPORATED
 * ALL RIGHTS RESERVED
 * 
 * PERMISSION IS GRANTED TO USE, COPY, CREATE DERIVATIVE WORKS AND REDISTRIBUTE
 * THIS SOFTWARE AND SUCH DERIVATIVE WORKS IN BINARY FORM ONLY FOR ANY PURPOSE,
 * SO LONG AS NO FEE IS CHARGED, AND SO LONG AS THE COPYRIGHT NOTICE ABOVE, THIS 
 * GRANT OF PERMISSION, AND THE DISCLAIMER BELOW APPEAR IN ALL COPIES MADE; AND
 * SO LONG AS THE NAME OF THE UNIVERSITY OF MICHIGAN IS NOT USED IN ANY
 * ADVERTISING OR PUBLICITY PERTAINING TO THE USE OR DISTRIBUTION OF THIS
 * SOFTWARE WITHOUT SPECIFIC, WRITTEN PRIOR AUTHORIZATION.
 * 
 * THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION FROM THE UNIVERSITY
 * OF MICHIGAN AS TO ITS FITNESS FOR ANY PURPOSE, AND WITHOUT WARRANTY BY THE
 * UNIVERSITY OF MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
 * WITHOUT LIMITATION THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE.  THE REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE 
 * LIABLE FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OF THE SOFTWARE, EVEN IF IT HAS BEEN OR IS HEREAFTER
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * 
 * For a License to distribute source code or to charge a fee for the program
 * or a product containing the program, contact MERIT at the University of
 * Michigan:
 * 
 * aaa-license@merit.edu
 * 
 * [This version puts NO LIMITS on the use.  It grants the right to create
 * DERIVATIVE WORKS.  The user may copy and distribute the code in the form
 * received AND DERIVATIVE WORKS, so long as no fee is charged.  If copies are
 * made, our copyright notice and the disclaimer must be included on them.  USE
 * THIS VERSION WITH CARE.  THIS VERSION VERY LIKELY WILL KILL ANY POTENTIAL
 * FOR LATER COMMERCIALIZATION OF THE SOFTWARE.]
 *****************************************************************************
 *
 * The code below is a derivative work based on the Merit Radius code found in 
 * radpwtst.c  v1.38 1996/05/18
 *
 * This code has ONLY been tested, compiled, and used on IRIX 6.2
 *
 * Your config file should look like this:
 * <server>:<port>
 * <server>:<port>
 * (eg: radius1.merit.edu:1645 )
 *
 * If you place more than one server in the config file the code will query
 * each server until the user has been authenticated or the last server has
 * been asked.
 *
 * - Tyler Allison
 *   allison@nas.nasa.gov
 */

/* You should only need to change the next couple defines */
/* If your config file is setup correctly DEFAULT_* are never used */
#define DEFAULT_RADIUS_SERVER          "radius1.merit.edu"
#define DEFAULT_RADIUS_PORT            1645
#define RADIUS_DIR                     "/usr/local/etc/raddb"
#define CONFIG_FILE                    "/usr/local/etc/raddb/rad_config"
#define MAX_CONFIG_LINE 256
#define RESPONSE_TIMEOUT        3
#define MAX_RETRIES	        0
#define MAX_PASSWORD_LENGTH     8   /* Radius has a problem with users who  */
         /* "think" they have passwords longer than is supported by the     */
         /* system. So we need to truncate the password before sending.     */
         /* For example: user thinks his password is 'foobarblaz' but we    */
         /* all know that passwords can only be 8 characters (on standard)  */
         /* so the system stores 'foobarbl' as his password. Now the system */
         /* knows that if the user types in 'foobarblaz' just to truncate   */
         /* at the 8th character and move on...but Radius doesnt!           */


#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/param.h>
#include	<netinet/in.h>
#include	<sys/time.h>
#include	<sys/signal.h>
#include	<sys/termios.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<time.h>
#include	<unistd.h>
#include        <strings.h>
#include        <malloc.h>
#include        <pwd.h>
#include        <sys/fcntl.h>
#include        <sys/wait.h>
#include        <net/if.h>
#include        <arpa/inet.h>
#include        <netdb.h>
#include        <ctype.h>
#include        <errno.h>
#include        <dirent.h>
#include        <syslog.h>
#include        <varargs.h>

#include        "md5-radius.c" /* Has some md5 functions we need */
#include	"mod-radius.h" 


#define FIND_MODE_REPLY         1
#define FIND_MODE_NAME          0
#define MAX_HOSTNAME_BUFFERS    20
#define PARSE_MODE_EQUAL        1
#define PARSE_MODE_NAME         0
#define PARSE_MODE_VALUE        2
#define MAX_AVPAIR_VTOA         20
#define LIST_COPY_LIMIT         256
#define LOG_ERR                 1
#define LOG_DEBUG               4
#define null ((void*)0) /* NULL is already defined but It wont catch everything */


extern FILE     *ddt;
extern FILE     *msgfd;
extern char     *radius_dir;
extern AATVPTR   rad_authen_aatv;
extern time_t    birthdate;
extern char      recv_buffer[4096];
extern char      send_buffer[4096];
extern char      ourhostname[MAXHOSTNAMELEN];


static FILE_LIST    *file_list = (FILE_LIST *) NULL;
static UINT4         self_ip[11];       /* Used with multi-homed servers */
static CLIENT_ENTRY *client_list = (CLIENT_ENTRY *) NULL;
static CLIENT_ENTRY *old_clients;
static DICT_ATTR    *dictionary_attributes;
static DICT_VALUE   *dictionary_values;
int                  dnspid = 0;   /* PID of current DNS resolver process */
int                  rad_ipc_port = 0;
static char * months[] =
                {
                        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                };

/* Put radcheck decleration here so we can put the code later in the file */

int radcheck (char *user_name,char *user_passwd,char *config_path);

int             radsock = 0;  /* fd for radius socket, if non-blocking mode */

char            recv_buffer[4096];
char            send_buffer[4096];
char            ourhostname[MAXHOSTNAMELEN];
char           *progname;
char           *radius_dir;
int             dumpcore = 0;
int             authfile_cnt = 0;
int             clients_cnt = 0;
int             users_cnt = 0;
time_t          birthdate;
AATVPTR		rad_authen_aatv = (AATV *) NULL;
AATVPTR         rad_ipc_aatv = (AATV *) NULL;
AATV           *authtype_tv[PW_AUTH_MAX + 1];
FILE           *ddt = NULL;
FILE           *msgfd = stderr;

typedef struct string_list_struct
{
	struct string_list_struct *next;
	char                      *str;
}string_list;

#include "mod-radfuncs.c" /* These are the funcs we dont need to know about */



int
radcheck2 (char *user_name,char *user_passwd, char *host, int port)

{
	int             final_result;
	int             retries;
	int             new_old;
	int             zero = 0;
	char           *client_name = (char *) NULL;
	char            msg[4096]; /* big enough to hold several messages */
	char            passwd[AUTH_PASS_LEN + 1];

	SEND_DATA       data;
	int             send_server ();
	

	data.user_name=user_name;
	data.password=user_passwd;

	/* Set up some defaults */

	data.code = PW_ACCESS_REQUEST;

	data.svc_port = port;
	data.server = host;

	radius_dir = RADIUS_DIR;  /* SendServer picks directory, if need be */
	data.timeout = RESPONSE_TIMEOUT;
	data.user_file = null;
	data.group = null;
	data.send_pairs = null;

	retries = MAX_RETRIES;	/* Try for response this many times */
	new_old = 0;		/* Assume old style */
	data.ustype = 0;
	data.fptype = 0;	/* by default */
	data.port_num = 1;	/* just default to port number one here */


	/* Plain authentication request ==> PW_AUTHENTICATE_ONLY */
	if (data.ustype == 0)
	{
		if (new_old == 1) /* new style */
		{
			data.ustype = PW_AUTHENTICATE_ONLY;
		}
		else /* old style */
		{
			data.ustype = PW_OUTBOUND_USER;
		}
	}

	srand (time (0));	/* Use random sequence number in request */
	data.seq_nbr = (u_char) rand ();

	if (gethostname (ourhostname, sizeof (ourhostname)) < 0)
	{
		perror ("gethostname");
		return (-2);
	}


	if (client_name == null)
	{
		if ((data.client_id = get_ipaddr (ourhostname)) == 0)
		{
			data.client_id = 0;
			return (-3);
		}
	}


	if ((data.user_file != null) && (data.group == null))
	{
		data.group = "DEFAULT";
	}


	if (send_server(&data, &retries, msg) == OK_RC)
	{
	  final_result = 1;
	}
	else
	{
	  final_result = 0;
	}
	return (final_result);
} /* end of radcheck2 () */


/****************************************************************************/
/*  This is the meat of the RADIUS authentication.  It is called from       */
/*  mod_auth_external.c                                                     */
/*  Pass it a username and password and returns:                            */
/*       0 = Authenticated                                                  */
/*       1 = Not Authenticated                                              */
/****************************************************************************/

int
radcheck (char *user_name,char *user_passwd,char *config_path)

{
	int             auth;
        char            config_line[MAX_CONFIG_LINE];
	char           *host; /* Pointer to the host we want to query */
	char           *port; /* Pointer to the port we want to query */
	char           *ptrunc; /* Pointer for truncating user_passwd */

	long            rad_port;

	/* Okay lets get the config file */

	FILE   *rad_config;
	auth = 1; /* Authentication assumed to be NO unless told otherwise */

	/* lets check the length of user_passwd and truncate as needed */
	if (strlen(user_passwd) > MAX_PASSWORD_LENGTH ) {
	  /* argh! more pointers! */
	  ptrunc = &user_passwd[MAX_PASSWORD_LENGTH+ 1];
	  *ptrunc = '\0';
	}
		
	rad_config = fopen(config_path, "r"); /* open the file */

	if (rad_config == null) {
	  /* Aww damn it! No config file let's use default!*/
	  auth = radcheck2(user_name,user_passwd,DEFAULT_RADIUS_SERVER,DEFAULT_RADIUS_PORT);
	} 
	else {
	  /* Loop inside the config file testing each host */
	  while(fgets(config_line,MAX_CONFIG_LINE,rad_config) != null)  {
	    config_line[strlen(config_line)-1] = '\0'; /* remove newline at end*/
	    host = config_line; /* host is at the beginning of line */
	    port = strchr(config_line, ':');  /* Find the colon seperator */
	    
	    /* Check for errors */
	    if (port == null) {

	      printf("Radius Error: Unable to parse Radius server file: %s\n",config_path);
	      return(-9);
	    }
	    *port = '\0'; /* Put newline where the colon is */
	    port++;       /* Point to next character */
	    rad_port = strtol(port,null,10); /* Port has to be an int so convert! */
	    auth = radcheck2(user_name,user_passwd,host,rad_port);
	    if (auth == 1) {
	      return(0); /*This needs to change to 'auth' when new */
			 /* mod_auth_external.c comes out*/
	    }
	  }
	}
	return(1);       /* This needs to change to 'auth' when new */
	                 /* mod_auth_external.c comes out */ 
}



