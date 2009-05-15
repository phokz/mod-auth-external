#ifndef RADIUS_H
#define RADIUS_H

/*
 *	RADIUS   Remote Authentication Dial In User Service
 *
 *	Livingston Enterprises, Inc.
 *	6920 Koll Center Parkway
 *	Pleasanton, CA   94566
 *
 *	Copyright 1992 Livingston Enterprises, Inc.
 *
 *	Permission to use, copy, modify, and distribute this software for any
 *	purpose and without fee is hereby granted, provided that this
 *	copyright and permission notice appear on all copies and supporting
 *	documentation, the name of Livingston Enterprises, Inc. not be used
 *	in advertising or publicity pertaining to distribution of the
 *	program without specific prior permission, and notice be given
 *	in supporting documentation that copying and distribution is by
 *	permission of Livingston Enterprises, Inc.
 *
 *	Livingston Enterprises, Inc. makes no representations about
 *	the suitability of this software for any purpose.  It is
 *	provided "as is" without express or implied warranty.
 *
 * [C] The Regents of the University of Michigan and Merit Network, Inc. 1992,
 * 1993, 1994, 1995, 1996 All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear in all
 * copies of the software and derivative works or modified versions thereof,
 * and that both the copyright notice and this permission and disclaimer
 * notice appear in supporting documentation.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE REGENTS OF THE
 * UNIVERSITY OF MICHIGAN AND MERIT NETWORK, INC. DO NOT WARRANT THAT THE
 * FUNCTIONS CONTAINED IN THE SOFTWARE WILL MEET LICENSEE'S REQUIREMENTS OR
 * THAT OPERATION WILL BE UNINTERRUPTED OR ERROR FREE.  The Regents of the
 * University of Michigan and Merit Network, Inc. shall not be liable for any
 * special, indirect, incidental or consequential damages with respect to any
 * claim by Licensee or any third party arising from use of the software.
 *
 *	@(#)radius.h	1.3 1/20/93
 *
 *	$Id: radius.h,v 2.64 1996/06/19 18:16:23 web Exp $
 */


#define	COMMENT			'#'	/* comment char for config files */

#define AUTH_VECTOR_LEN		16
#define AUTH_PASS_LEN		16
#define AUTH_ID_LEN		64
#define AUTH_STRING_LEN		128	/* maximum of 253 */

#define FILTER_LEN		16
#define NAME_LENGTH		32
#define	MAX_FSMID_LEN		20	/* Maximum length of %FSMID string */

typedef struct pw_auth_hdr
{
	u_char          code;
	u_char          id;
	u_short         length;
	u_char          vector[AUTH_VECTOR_LEN];
	u_char          data[2];
} AUTH_HDR;

#define AUTH_HDR_LEN			20
#define MAX_SECRET_LENGTH		16
#define CHAP_VALUE_LENGTH		16

#if !defined(PW_AUTH_UDP_PORT)
#define PW_AUTH_UDP_PORT		1647
#endif

#if !defined(PW_ACCT_UDP_PORT)
#define PW_ACCT_UDP_PORT		1648
#endif

#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3
#define PW_TYPE_OCTETS			4
#define PW_TYPE_VENDOR			5

/* standard RADIUS codes */

#define	PW_ACCESS_REQUEST		1
#define	PW_ACCESS_ACCEPT		2
#define	PW_ACCESS_REJECT		3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6
#define	PW_PASSWORD_REQUEST		7
#define	PW_PASSWORD_ACK			8
#define	PW_PASSWORD_REJECT		9
#define	PW_ACCOUNTING_MESSAGE		10
#define	PW_ACCESS_CHALLENGE		11
#define	PW_STATUS_SERVER		12
#define	PW_STATUS_CLIENT		13
#define	PW_FORWARDING			216


/* standard RADIUS attribute-value pairs */

#define	PW_USER_NAME			1	/* string */
#define	PW_USER_PASSWORD		2	/* string */
#define	PW_CHAP_PASSWORD		3	/* string */
#define	PW_NAS_IP_ADDRESS		4	/* ipaddr */
#define	PW_NAS_PORT			5	/* integer */
#define	PW_SERVICE_TYPE			6	/* integer */
#define	PW_FRAMED_PROTOCOL		7	/* integer */
#define	PW_FRAMED_IP_ADDRESS		8	/* ipaddr */
#define	PW_FRAMED_IP_NETMASK		9	/* ipaddr */
#define	PW_FRAMED_ROUTING		10	/* integer */
#define	PW_FILTER_ID		        11	/* string */
#define	PW_FRAMED_MTU			12	/* integer */
#define	PW_FRAMED_COMPRESSION		13	/* integer */
#define	PW_LOGIN_IP_HOST		14	/* ipaddr */
#define	PW_LOGIN_SERVICE		15	/* integer */
#define	PW_LOGIN_PORT			16	/* integer */
#define	PW_OLD_PASSWORD			17	/* string */ /* deprecated */
#define	PW_REPLY_MESSAGE		18	/* string */
#define	PW_LOGIN_CALLBACK_NUMBER	19	/* string */
#define	PW_FRAMED_CALLBACK_ID		20	/* string */
#define	PW_EXPIRATION			21	/* date */ /* deprecated */
#define	PW_FRAMED_ROUTE			22	/* string */
#define	PW_FRAMED_IPX_NETWORK		23	/* integer */
#define	PW_STATE			24	/* string */
#define	PW_CLASS			25	/* string */
#define	PW_VENDOR_SPECIFIC		26	/* string */
#define	PW_SESSION_TIMEOUT		27	/* integer */
#define	PW_IDLE_TIMEOUT			28	/* integer */
#define	PW_TERMINATION_ACTION		29	/* integer */
#define	PW_CALLED_STATION_ID		30	/* string */
#define	PW_CALLING_STATION_ID		31	/* string */
#define	PW_NAS_IDENTIFIER		32	/* string */
#define	PW_PROXY_STATE			33	/* string */
#define	PW_LOGIN_LAT_SERVICE		34	/* string */
#define	PW_LOGIN_LAT_NODE		35	/* string */
#define	PW_LOGIN_LAT_GROUP		36	/* string */
#define	PW_FRAMED_APPLETALK_LINK	37	/* integer */
#define	PW_FRAMED_APPLETALK_NETWORK	38	/* integer */
#define	PW_FRAMED_APPLETALK_ZONE	39	/* string */
#define	PW_CHAP_CHALLENGE		60	/* string */
#define	PW_NAS_PORT_TYPE		61	/* integer */
#define	PW_PORT_LIMIT			62	/* integer */
#define	PW_LOGIN_LAT_PORT		63	/* string */

/*	Accounting */

#define	PW_ACCT_STATUS_TYPE		40	/* integer */
#define	PW_ACCT_DELAY_TIME		41	/* integer */
#define	PW_ACCT_INPUT_OCTETS		42	/* integer */
#define	PW_ACCT_OUTPUT_OCTETS		43	/* integer */
#define	PW_ACCT_SESSION_ID		44	/* string */
#define	PW_ACCT_AUTHENTIC		45	/* integer */
#define	PW_ACCT_SESSION_TIME		46	/* integer */
#define	PW_ACCT_INPUT_PACKETS		47	/* integer */
#define	PW_ACCT_OUTPUT_PACKETS		48	/* integer */
#define	PW_ACCT_TERMINATE_CAUSE		49	/* integer */
#define	PW_ACCT_MULTI_SESSION_ID	50	/* string */

/*	Merit Experimental Extensions */

/*	Temporary assignment for LOG AATV session logging */

#define PW_LAS_START_TIME		145	/* integer */
#define PW_LAS_CODE			146	/* integer */
#define PW_LAS_DURATION			147	/* integer */
#define PW_LOCAL_DURATION		148	/* integer */

#define	PW_SERVICE_CLASS		149	/* string */
#define	PW_PORT_ENTRY			150	/* string */
#define	PW_PROXY_ACTION			211	/* string */
#define	PW_TOKEN			213	/* string */
#define	PW_HUNTGROUP_NAME		221	/* string */
#define	PW_USER_ID			222	/* string */
#define	PW_USER_REALM			223	/* string */

/*	Configuration Only Attributes (for check-items) */

#define	CI_COMMENT			1024	/* string */
#define	CI_XVALUE			1025	/* integer */
#define	CI_XSTRING			1026	/* string */
#define	CI_AUTHENTICATION_TYPE		1027	/* integer */
#define	CI_PROHIBIT			1028	/* integer */
#define	CI_USER_CATEGORY		1029	/* string */
#define	CI_GROUP_NAME			1030	/* string */
#define	CI_ENCRYPTED_PASSWORD		1031	/* string */
#define	CI_EXPIRATION			1032	/* date */
#define	CI_USER_PASSWORD		1033	/* string */
#define	CI_SIMULTANEOUS_USE		1034	/* integer */
#define	CI_SERVER_NAME			1035	/* string */

/*	Integer Translations */

/*	SERVICE TYPES	*/

#define	PW_LOGIN			1
#define	PW_FRAMED			2
#define	PW_CALLBACK_LOGIN		3
#define	PW_CALLBACK_FRAMED		4
#define	PW_OUTBOUND_USER		5
#define	PW_ADMINISTRATIVE_USER		6
#define	PW_SHELL_USER			7
#define PW_AUTHENTICATE_ONLY		8
#define PW_CALLBACK_ADMIN_USER		9

/*	FRAMED PROTOCOLS	*/

#define	PW_PPP				1
#define	PW_SLIP				2
#define	PW_ARA				3
#define	PW_GANDALF			4

/*	FRAMED ROUTING VALUES	*/

#define	PW_NONE				0
#define	PW_BROADCAST			1
#define	PW_LISTEN			2
#define	PW_BROADCAST_LISTEN		3

/*	FRAMED COMPRESSION TYPES	*/

#define	PW_VAN_JACOBSON_TCP_IP		1
#define	PW_IPX_HEADER_COMPRESSION	2

/*	LOGIN SERVICES	*/

#define	PW_TELNET			0
#define	PW_RLOGIN			1
#define	PW_TCP_CLEAR			2
#define	PW_PORTMASTER			3
#define	PW_LAT				4

/*	TERMINATION ACTIONS	*/

#define	PW_DEFAULT			0
#define	PW_RADIUS_REQUEST		1

/*	AUTHENTICATION TYPES */

#define AA_NONE		0	/* This is not a valid user id entry */
#define AA_UNIX		1	/* Use local Unix password file */
#define AA_AKRB		2	/* AFS Kerberos type authentication */
#define AA_MKRB		3	/* MIT Kerberos type authentication */
#define AA_RAD		4	/* Pass to remote RADIUS server */
#define AA_MNET		5	/* Do Merit specific authentication */
#define AA_KCHAP	6	/* Kerberos CHAP authentication */
#define AA_TACACS	7	/* Encrypted TACACS authentication */
#define AA_REALM	8	/* Find given realm in authfile */
#define AA_LOCAL	9
#define AA_FILE		10	/* ID/PW list in a file */

#define PW_AUTH_MAX	10	/* Highest authentication type */

/*	PROHIBIT PROTOCOL  */

#define PW_DUMB		0	/* 1 and 2 are defined in FRAMED PROTOCOLS */
#define PW_AUTH_ONLY	3
#define PW_ALL		255

/*	ACCOUNTING STATUS TYPES    */

#define PW_STATUS_START		1
#define PW_STATUS_STOP		2
#define PW_STATUS_ALIVE		3
#define PW_STATUS_MODEM_START	4
#define PW_STATUS_MODEM_STOP	5
#define PW_STATUS_CANCEL	6
#define PW_ACCOUNTING_ON	7
#define PW_ACCOUNTING_OFF	8

/*	ACCOUNTING TERMINATION CAUSES    */

#define PW_USER_REQUEST		1
#define PW_LOST_CARRIER		2
#define PW_LOST_SERVICE		3
#define PW_ACCT_IDLE_TIMEOUT	4
#define PW_ACCT_SESSION_TIMEOUT	5
#define PW_ADMIN_RESET		6
#define PW_ADMIN_REBOOT		7
#define PW_PORT_ERROR		8
#define PW_NAS_ERROR		9
#define PW_NAS_REQUEST		10
#define PW_NAS_REBOOT		11
#define PW_PORT_UNNEEDED	12
#define PW_PORT_PREEMPTED	13
#define PW_PORT_SUSPENDED	14
#define PW_SERVICE_UNAVAILABLE	15
#define PW_CALLBACK		16
#define PW_USER_ERROR		17
#define PW_HOST_REQUEST		18

/*	NAS PORT TYPES    */

#define PW_ASYNC		0
#define PW_SYNC			1
#define PW_ISDN_SYNC		2
#define PW_ISDN_SYNC_V120	3
#define PW_ISDN_SYNC_V110	4

/* Default Database File Names */

#ifndef RADIUS_DIR
#define RADIUS_DIR		"/usr/private/etc/raddb"
#endif

#ifndef RADACCT_DIR
#define RADACCT_DIR		"/usr/private/etc/radacct"
#endif

/*
 *	Note:	To change where these files go, do not change the #defines
 *		below, instead change the RADIUS_DIR #define above.
 */

#define RADIUS_DICTIONARY	"dictionary"
#define RADIUS_CLIENTS		"clients"
#define RADIUS_USERS		"users"
#define RADIUS_HOLD		"holdusers"
#define RADIUS_LOG		"logfile"
#define RADIUS_AUTH		"authfile"
#define RADIUS_PID		"radiusd.pid"
#define RADIUS_FSM		"radius.fsm"
#define RADIUS_DEBUG		"radius.debug"

#ifndef RADIUS_COMPRESS
#define RADIUS_COMPRESS		"/usr/ucb/compress"  /* might be gzip, etc. */
#endif

#ifndef RADIUS_LOCALSERVER
#define RADIUS_LOCALSERVER	"nimic.nas.nasa.gov"
#endif

#ifndef DEFAULT_REALM
#define DEFAULT_REALM		"DEFAULT"
#endif

#ifndef NULL_REALM
#define NULL_REALM		"NULL"
#endif

/* Server data structures */

typedef struct dict_attr
{
	char              name[NAME_LENGTH + 1];	/* attribute name */
	int               value;			/* attribute index */
	int               type;				/* string, int, etc. */
	struct dict_attr *next;
} DICT_ATTR;

typedef struct dict_value
{
	char               attrname[NAME_LENGTH +1];
	char               name[NAME_LENGTH + 1];
	int                value;
	struct dict_value *next;
} DICT_VALUE;

typedef struct value_pair
{
	char               name[NAME_LENGTH + 1];
	int                attribute;
	int                type;
	UINT4              lvalue;
	char               strvalue[AUTH_STRING_LEN + 1];
	struct value_pair *next;
} VALUE_PAIR;

typedef struct auth_req
{
	UINT4             ipaddr;           /* IP address of requestor */
	u_short           udp_port;         /* UDP reply socket of requestor */
	u_char            id;               /* Original request seq. number */
	u_char            code;             /* Type of RADIUS packet */
	u_char            vector[AUTH_VECTOR_LEN];
	char             *secret;
	char             *file_pfx;
	char             *realm_filter;
	u_char            ttl;              /* Global queue time-to-live secs */
	u_char            timer;            /* General utility timer */
	u_char            reply_id;         /* RADIUS-to-RADIUS seq. number */
	u_char            retry_cnt;        /* Counter for duplicate requests */
	u_char            state;            /* State of current request */
	u_char            sws;              /* Switches, flags, etc. */
	int               result;           /* Result of previous action */
	int               cur_count;        /* Original number request pairs */
	struct aatv      *fsm_aatv;         /* Pointer to current FSM action */
	struct aatv      *direct_aatv;      /* Pointer to actual action */
	struct event_ent *event_q;          /* Pointer to active event queue */
	struct auth_req  *next;             /* Global request queue link */
	VALUE_PAIR       *request;          /* Original client a/v pairs */
	VALUE_PAIR       *cur_request;      /* Represents current a/v pairs */
	VALUE_PAIR       *user_check;       /* List of users file check items */
} AUTH_REQ;

typedef struct event_ent
{
	struct event_ent *next;
	AUTH_REQ         *auth_head; /* pointer back to the authreq structure */
	struct aatv      *fsm_aatv;  /* record action from FSM table */
	struct aatv      *sub_aatv;  /* record action when request was issued */
	u_char           *packet;    /* copy of request packet which was sent */
	int               len;       /* length of packet */
	pid_t             pid;       /* fork type: pid, socket type: == zero */
	struct sockaddr_in sin;      /* socket info for packet re-sending */
	int               evalue;    /* AATV act_func integer argument */
	u_char            state;     /* state in which the request was issued */
	char              action[NAME_LENGTH+1]; /* "cmd" arg to radius_send */
	char              estring[AUTH_ID_LEN]; /* AATV act_func string arg */
} EVENT_ENT;

typedef struct user_ent
{
	struct user_ent *next;
	char            *name;
	VALUE_PAIR      *check;
	VALUE_PAIR      *reply;
} USER_ENTRY;

#ifdef  MERIT_LAS
typedef struct lasrealm_ent *LAS_REALM;
#endif	/* MERIT_LAS */

typedef struct auth_ent
{
	struct auth_ent *next;
	char            *name;
	struct auth_ent *parent;
	int              prot;
	int              type;
	char            *host;
	char            *filter;
#ifdef  MERIT_LAS
	LAS_REALM        las_realm;
#endif	/* MERIT_LAS */
} AUTH_ENTRY;

/* The following must match the beginning of the auth_ent structure */
typedef struct auth_aent
{
	struct auth_ent *next;
	char            *name;
	struct auth_ent *parent;
} AUTH_ALIAS_ENTRY;

typedef struct linklist_entry
{
	struct linklist_entry *next;	/* pointer to next entry in list */
} LINKLIST_ENT;

#define	numbof(X)	(sizeof(X)/sizeof(X[0]))

typedef struct name_list
{
	struct name_list  *next;
	char              *name;
	u_char             flag;
	u_short            num;
} NAME_LIST;

/*	Binary port entry structure used in Port-Entry attribute */

#define	PORT_ENTRY_VERSION	0	/* increase if change structure here */

typedef struct bin_port_ent
{
	u_char             version;	/* be sure to use PORT_ENTRY_VERSION */
	u_char             port_source; /* zero => was HGAS, one => otherwise */
	time_t             start_time;	/* start time of session on this port */
	UINT4              port_nbr;	/* port number of this session */
	UINT4              duration;	/* session length (seconds) */
} BIN_PORT_ENT;

/*
 * Use the following to specify default "realm" names to use for
 * authentication-type entries of RADIUS or TACACS that may be
 * configured in the "users" file.  May be configured globally
 * in the Makefile or changed in the authfile on a running server.
 */

#ifndef DEFAULT_RADIUS_SERVER
#define DEFAULT_RADIUS_SERVER "nimic.nas.nasa.gov"
#endif

#ifndef DEFAULT_TACACS_SERVER
#define DEFAULT_TACACS_SERVER ""
#endif

/******************************************************************
 *
 *      PW_PROTTYPE & PW_PROTTYPES - define authentication protocol allowed
 *                                   for particular realm entry in authfile.
 *
 *      The PW_PROTTYPE value is stored in the auth_ent.prot field.
 *      The PW_PROTTYPE value corresponds to the order of PW_PROTTYPES.
 *
 *****************************************************************/

#define PW_PROTTYPE_DFLT	0	/* Use this entry for any protocol */
#define PW_PROTTYPE_CHAP	1	/* Entry is for CHAP style authent. */
#define PW_PROTTYPE_PW		2	/* Entry is for id/pw style authent. */

#define PW_PROTTYPES_DFLT	"DEFAULT"
#define PW_PROTTYPES_CHAP	"CHAP"
#define PW_PROTTYPES_PW		"PW"

typedef struct file_list
{
	struct file_list       *next;
	char                   *prefix;
	USER_ENTRY             *user_list;
	AUTH_ENTRY             *auth_list;
} FILE_LIST;

typedef struct ip_address
{
	struct ip_address *next;
	struct in_addr     ipaddr;
} IP_ADDRESS;

typedef struct dns_name
{
	struct dns_name   *next;
	u_char             type;	/* 0 = official name, 1 = alias */
	char               name[1];
} DNS_NAME;

typedef struct client_ent
{
	struct client_ent *next;
	IP_ADDRESS        *addrs;
	char              *secret;
	char              *prefix;
	char              *hostname;
	DNS_NAME          *names;
	time_t             expire_time;
	enum {CE_DNS, CE_NUMERIC, CE_OURADDR} type;
} CLIENT_ENTRY;

/* 	Define return codes from "SendServer" utility */

#define BADRESP_RC	-2
#define ERROR_RC	-1
#define OK_RC		0
#define TIMEOUT_RC	1

typedef struct send_data /* Used to pass information to sendserver() function */
{
	u_char          code;		/* RADIUS packet code */
	u_char          seq_nbr;	/* Packet sequence number */
	char           *user_name;
	char           *password;	/* Cleartext user password */
	u_char          ustype;		/* Service-Type attribute */
	u_char          fptype;		/* Framed-Protocol attribute */
	char           *server;		/* Name/addrress of RADIUS server */
	int             svc_port;	/* RADIUS protocol destination port */
	int             timeout;	/* Session timeout in seconds */
	UINT4           client_id;	/* IP address of client */
	int             port_num;	/* Port number on client */
	char           *user_file;	/* Users style file of a/v pairs */
	char           *group;
	VALUE_PAIR     *send_pairs;     /* More a/v pairs to send */
	VALUE_PAIR    **receive_pairs;  /* Where to place received a/v pairs */
} SEND_DATA;

/*
 *	Handle older syslog versions, too!
 */

#ifndef	LOG_CONS
#define	LOG_DAEMON		0
#define	LOG_AUTH		0
#endif

#define	MGMT_POLL_SECRET	"Hardlyasecret"
#define	MAX_REQUESTS		128
#define	MAX_REQUEST_TIME	30	/* Lifetime of a request */
#define	CLEANUP_DELAY		5	/* Hold onto old requests this long */
#define	DEFAULT_INETD_TIMEOUT	15	/* Fifteen minutes by default */
#define	DEFAULT_TIMER_VALUE	3	/* Three seconds by default */
#define	ADDRESS_AGING		60*60	/* One hour by default */
#define	DFLT_TACACS_UDP_PORT	49	/* Default TACACS server port */
#define	SESS_ID_LEN		8	/* session id length */
#define SECONDS_PER_DAY		86400
#define TRUNCATION_DAY		7   /* Sunday is zero (0), daily is seven (7) */
#define	DNS_SLEEP		100	/* Time which DNS sub-process sleeps. */

typedef enum				/* error code */
{
  EC_OK,				/* no error */
  EC_INTERNAL,				/* internal error */
  EC_CONFIG,				/* configuration error */
  EC_NO_MEMORY,				/* out of memory */
  EC_CREATE_FILE,			/* error creating file */
  EC_NO_TOKEN,				/* no token available */
  EC_NO_PORTS,				/* no ports available for guests */
  EC_TOO_MANY_SESSIONS,			/* user has too many sessions */
  EC_ABS_FAILURE,                       /* ABS failed (with message) */
  EC_NO_BALANCE,			/* error querying for balance */
  EC_BAD_BALANCE			/* balance too low */
} ERRORCODE;

typedef enum				/* accounting code */
{
	AC_ERROR	= -1,		/* no accounting code */
	AC_NORMAL,			/* normal disconnect */
	AC_REJECT,			/* rejected by this server */
	AC_CANCEL,			/* access rejected by someone */
	AC_NOCONFIRM,			/* no confirmation */
	AC_OVERTIME,			/* session over maximum time allowed */
	AC_UNKNOWN,			/* session ended for unknown reason */
	AC_NOTOKEN,			/* rejected because no token */
	AC_NOTLOCAL,			/* session not local */
	AC_SUSPEND,			/* session suspended */
	AC_FAILED,			/* authentication failed */
	AC_AUTHORIZED,			/* session authorized (for stats) */
	AC_NASREBOOT,			/* released due to NAS reboot */
	AC_REMOTE,			/* remote session, failed to forward */
	AC_NUMBOFCODE			/* number of accounting code */
} ACCTCODE;

#ifndef PROTO
#ifdef __STDC__
#define PROTO(x) x
#else
#define PROTO(x) ()
#define const
#endif /* !__STDC__ */
#endif /* !PROTO */

union action_u
{
	struct aatv    *aatv;	/* points to the id field of an AATV */
	char           *proxy;	/* pointer to a Proxy-Action string */
} UACTION;

/*	Define event structure (for events generated by AATV recv functions */

typedef struct ev
{
	u_char          state;
	union action_u  a;
	int             isproxy;	/* set to one if action "a" is proxy */
	int             value;
	char            xstring[AUTH_ID_LEN];
} EV;

/*	Define aatvfunc_type codes */ 

#define	AA_DIRECT	0	/* Function gives direct reply */
#define	AA_SOCKET	1	/* Deferred reply returned on socket */
#define	AA_FORK		2	/* Spawn a process to wait for reply */
#define	AA_FREPLY	3	/* Fork & get reply on server socket */

typedef struct aatv
{
	u_char       id[NAME_LENGTH + 1];
	char         authen_type; /* a -1 value indicates built-in AATV types */
	u_char       aatvfunc_type;
	void       (*init) PROTO((struct aatv *));
	int        (*timer) PROTO((void));
	int        (*act_func) PROTO((AUTH_REQ *, int, char *));
	AUTH_REQ * (*recv) PROTO((struct sockaddr_in *, UINT4, u_int, EV *));
	void       (*cleanup) PROTO((void));
	UINT4        sockfd;
} AATV, *AATVPTR;

extern AATV    *authtype_tv[];

#ifdef  MERIT_LAS
extern AATVPTR  rad_log_aatv;		/* For logging (selector) */
extern AATVPTR  rad_log_all_aatv;	/* For logging (debugging) */
extern AATVPTR  rad_log_brief_aatv;	/* For logging (logging) */
extern AATVPTR  rad_log_old_aatv;	/* For logging (logging) */
extern AATVPTR  rad_log_v1_0_aatv;	/* For logging (logging) */
extern AATVPTR  rad_log_v1_1_aatv;	/* For logging (logging) */
extern AATVPTR  rad_log_v2_0_aatv;	/* For logging (logging) */
extern AATVPTR  rad_log_v2_1_aatv;	/* For logging (logging) */
#endif	/* MERIT_LAS */

/*	Specify all authentication/authorization transfer vectors here. */

extern AATVPTR	rad_realm_aatv;		/* Needed for authtype = realm */
extern AATVPTR	rad_2rad_aatv;		/* Authtype = Radius */
extern AATVPTR	rad_tacs_aatv;		/* Authtype = TACACS */
extern AATVPTR	rad_unix_aatv;		/* Authtype = Unix-pw */
extern AATVPTR	rad_kchp_aatv;		/* Authtype = KCHAP */
extern AATVPTR	rad_mnet_aatv;		/* Authtype = mnet */
extern AATVPTR	rad_akrb_aatv;		/* Authtype = akerb */
extern AATVPTR	rad_mkrb_aatv;		/* Authtype = mkerb */
#ifdef  MERIT_LAS
extern AATVPTR	rad_file_aatv;		/* Authtype = File */
#endif	/* MERIT_LAS */
extern AATVPTR	rad_authen_aatv;	/* Authentication begins here */
extern AATVPTR	rad_passwd_aatv;	/* Used for changing passwords */

#ifdef  MERIT_HUNTGROUP
#include	"huntgroup.h"
#define EN_HGAS1		"HGAS1"
#define EN_HGAS2		"HGAS2"
#define EN_HGAS3		"HGAS3"
#define EN_HGAS4		"HGAS4"
#define EN_BACCT		"BACCT"
extern AATVPTR	rad_hgas1_aatv;		/* Hg Authorization begins here */
extern AATVPTR	rad_hgas2_aatv;		/* Hg Authorization continues here */
extern AATVPTR	rad_hgas3_aatv;		/* Hg Accounting begins here */
extern AATVPTR	rad_hgas4_aatv; 	/* Hg Accounting continues here */
extern AATVPTR	rad_hgasrmt_aatv;	/* Hg forwarding to remote server */
extern AATVPTR	rad_hgacctrmt_aatv;	/* Hg accounting origination */
extern AATVPTR	rad_hgaslog_aatv;	/* Hg logging action (for HGAS1) */

#ifdef  MERIT_HUNTGROUP_DAC
extern AATVPTR	rad_hgdac1_aatv;	/* Hg DAC policy begins here */
extern AATVPTR	rad_hgdac2_aatv;	/* Hg DAC policy continues here */
extern AATVPTR	rad_hgdac3_aatv;	/* Hg DAC accounting begins here */
#define DACAATVS ,&rad_hgdac1_aatv,&rad_hgdac2_aatv,&rad_hgdac3_aatv
#else	/* MERIT_HUNTGROUP_DAC */
#define DACAATVS
#endif	/* MERIT_HUNTGROUP_DAC */

#ifdef  MERIT_HUNTGROUP_SHP
extern AATVPTR	rad_hgshp1_aatv;	/* Hg SHP policy begins here */
extern AATVPTR	rad_hgshp2_aatv;	/* Hg SHP policy continues here */
extern AATVPTR	rad_hgshp3_aatv;	/* Hg SHP accounting begins here */
#define SHPAATVS ,&rad_hgshp1_aatv,&rad_hgshp2_aatv,&rad_hgshp3_aatv
#else	/* MERIT_HUNTGROUP_SHP */
#define SHPAATVS
#endif	/* MERIT_HUNTGROUP_SHP */

#define HGAATVS	,&rad_hgas1_aatv,&rad_hgas2_aatv,&rad_hgas3_aatv,&rad_hgas4_aatv,&rad_hgasrmt_aatv,&rad_hgaslog_aatv,&rad_hgacctrmt_aatv DACAATVS SHPAATVS
#else	/* MERIT_HUNTGROUP */
#define HGAATVS
#define EN_HGAS1		""
#define EN_HGAS2		""
#define EN_HGAS3		""
#define EN_HGAS4		""
#define EN_BACCT		""
#endif	/* MERIT_HUNTGROUP */

#ifdef  MERIT_ORGANIZATION
#include	"oas.h"
#define EN_OAS			"OAS"
#define EN_OAS_ACCT		"OAS_ACCT"
extern AATVPTR	rad_oas_aatv;		/* Org Authorization begins here */
extern AATVPTR	rad_oasrem_aatv;	/* Org Authorization remote stuff */
extern AATVPTR	rad_oasloc_aatv;	/* Org Authorization local stuff */
extern AATVPTR	oas_acct_aatv;		/* Org Accounting begins here */
#define OASAATVS ,&rad_oas_aatv,&rad_oasrem_aatv,&rad_oasloc_aatv,&oas_acct_aatv
#else	/* MERIT_ORGANIZATION */
#define OASAATVS
#define EN_OAS			""
#define EN_OAS_ACCT		""
#endif	/* MERIT_ORGANIZATION */

#ifdef  MERIT_LAS
#include	"las.h"
#define EN_LAS			"AUTHENTICATE"
#define EN_LAS_ACCT		"LAS_ACCT"
extern AATVPTR	rad_las_aatv;		/* Local authorization */
extern AATVPTR	las_auth_subaatv;	/* Generic LAS authorization */
extern AATVPTR	las_acct_subaatv;	/* Generic LAS accounting */
extern AATVPTR	las_acct_aatv;		/* LAS accounting */

#ifdef	LAS_NO_HGAS
#define	LASCPAATV
#else	/* LAS_NO_HGAS */
extern AATVPTR	lascp_aatv;		/* LAS synchronizing */
#define	LASCPAATV	,&lascp_aatv
#endif	/* LAS_NO_HGAS */

#ifdef UOFM_LAS
#include	"umlas.h"
extern AATVPTR  las_um_aatv;		/* U of M LAS */
#define LASAATVS  ,&las_auth_subaatv,&las_acct_subaatv,&las_um_aatv, \
		&rad_las_aatv,&las_acct_aatv LASCPAATV
#else	/* UOFM_LAS */
#define LASAATVS  ,&las_auth_subaatv,&las_acct_subaatv, \
		&rad_las_aatv,&las_acct_aatv LASCPAATV
#endif	/* UOFM_LAS */
#else	/* MERIT_LAS */
#define LASAATVS
#define EN_LAS			""
#define EN_LAS_ACCT		""
#endif	/* MERIT_LAS */

#ifdef  MERIT_LAS
#define AUTHENAATVS	&rad_realm_aatv,   &rad_unix_aatv,   &rad_2rad_aatv, \
			&rad_tacs_aatv,    &rad_kchp_aatv,   &rad_mnet_aatv, \
			&rad_akrb_aatv,    &rad_mkrb_aatv,   &rad_file_aatv, \
			&rad_authen_aatv,  &rad_passwd_aatv
#else	/* MERIT_LAS */
#define AUTHENAATVS	&rad_realm_aatv,   &rad_unix_aatv,   &rad_2rad_aatv, \
			&rad_tacs_aatv,    &rad_kchp_aatv,   &rad_mnet_aatv, \
			&rad_akrb_aatv,    &rad_mkrb_aatv,   &rad_authen_aatv, \
			&rad_passwd_aatv
#endif	/* MERIT_LAS */


#define AATVS	AUTHENAATVS HGAATVS OASAATVS LASAATVS

/*
 *	Event names (EN_*) in RADIUS   ###   see the NOTE in enum_event()
 */

#define EN_NAK			"NAK"
#define EN_ACK			"ACK"
#define EN_ERROR		"ERROR"
#define EN_WAIT			"WAIT"
#define EN_FATAL		"FATAL"
#define EN_DUP_REQ		"DUP"
#define EN_TIMER		"TIMER"
#define EN_TIMEOUT		"TIMEOUT"
#define EN_ABORT		"ABORT"
#define EN_NEW_AUTHEN		"AUTHEN"
#define EN_NEW_ACCT		"ACCT"
#define EN_NEW_PASSWD		"PASSWD"
#define EN_RE_ACCESS		"REACCESS"
#define EN_ACC_CHAL		"ACC_CHAL"
#define EN_MGT_POLL		"MGT_POLL"
#define EN_AUTH_ONLY		"AUTH_ONLY"
#define EN_ACCT_START		"ACCT_START"
#define EN_ACCT_STOP		"ACCT_STOP"
#define EN_ACCT_ALIVE		"ACCT_ALIVE"
#define EN_ACCT_MODEM_START	"ACCT_MSTART"
#define EN_ACCT_MODEM_STOP	"ACCT_MSTOP"
#define EN_ACCT_CANCEL		"ACCT_CANCEL"
#define EN_RC1			"RC1"
#define EN_RC2			"RC2"
#define EN_RC3			"RC3"
#define EN_RC4			"RC4"
#define EN_RC5			"RC5"
#define EN_RC6			"RC6"
#define EN_RC7			"RC7"
#define EN_RC8			"RC8"
#define EN_RC9			"RC9"
#define EN_RC10			"RC10"
#define EN_RC11			"RC11"
#define EN_RC12			"RC12"
#define EN_RC13			"RC13"
#define EN_RC14			"RC14"
#define EN_RC15			"RC15"
#define EN_RC16			"RC16"
#define EN_RC17			"RC17"
#define EN_RC18			"RC18"
#define EN_RC19			"RC19"
#define EN_RC20			"RC20"
#define EN_RC21			"RC21"

/*
 *	Event numbers in RADIUS   ###   see the NOTE in enum_event()
 */
typedef enum
{
	EV_NAK			= -1,
	EV_ACK			= 0,
	EV_ERROR		= 1,
	EV_WAIT			= 2,
	EV_FATAL		= 3,
	EV_DUP_REQ		= 4,
	EV_TIMER		= 5,
	EV_TIMEOUT		= 6,
	EV_ABORT		= 7,

	/* arbitrary return codes from AATV action functions */

	EV_RC1			= 8,
	EV_RC2			= 9,
	EV_RC3			= 10,
	EV_RC4			= 11,
	EV_RC5			= 12,
	EV_RC6			= 13,
	EV_RC7			= 14,
	EV_RC8			= 15,
	EV_RC9			= 16,
	EV_RC10			= 17,
	EV_RC11			= 18,
	EV_RC12			= 19,
	EV_RC13			= 20,
	EV_RC14			= 21,
	EV_RC15			= 22,
	EV_RC16			= 23,
	EV_RC17			= 24,
	EV_RC18			= 25,
	EV_RC19			= 26,
	EV_RC20			= 27,
	EV_RC21			= 28
} EVENT;

/* Request type events */

#define	EV_NEW_AUTHEN		EV_RC1
#define	EV_NEW_ACCT		EV_RC2
#define	EV_NEW_PASSWD		EV_RC3
#define	EV_RE_ACCESS		EV_RC4
#define	EV_ACC_CHAL		EV_RC5
#define	EV_MGT_POLL		EV_RC6
#define	EV_AUTH_ONLY		EV_RC7
#ifdef  MERIT_HUNTGROUP
#define	EV_HGAS1		EV_RC8
#define	EV_HGAS2		EV_RC9
#define	EV_HGAS3		EV_RC10
#define	EV_BACCT		EV_RC11
#else	/* MERIT_HUNTGROUP */
#define	EV_HGAS1		EV_ACK
#define	EV_HGAS2		EV_ACK
#define	EV_HGAS3		EV_ACK
#define	EV_BACCT		EV_ACK
#endif	/* MERIT_HUNTGROUP */
#define EV_ACCT_START		EV_RC12
#define EV_ACCT_STOP		EV_RC13
#define EV_ACCT_ALIVE		EV_RC14
#define EV_ACCT_MODEM_START	EV_RC15
#define EV_ACCT_MODEM_STOP	EV_RC16
#define EV_ACCT_CANCEL		EV_RC17
#ifdef  MERIT_ORGANIZATION
#define	EV_OAS			EV_RC18
#define	EV_OAS_ACCT		EV_RC19
#else	/* MERIT_ORGANIZATION */
#define	EV_OAS			EV_ACK
#define	EV_OAS_ACCT		EV_ACK
#endif	/* MERIT_ORGANIZATION */
#ifdef  MERIT_LAS
#define	EV_LAS			EV_RC20
#define	EV_LAS_ACCT		EV_RC21
#else	/* MERIT_LAS */
#define	EV_LAS			EV_ACK
#define	EV_LAS_ACCT		EV_ACK
#endif	/* MERIT_LAS */

typedef enum		/* Typedef for second add_string() argument */
{
	ASIS		= 0x0000,	/* No conversion on string */
	ASLC		= 0x0001,	/* Store as lower case sting */
	FINDONLY	= 0x0002	/* Find string only */
} AS_CONVERT;

/*
 *	The finite state machine (FSM) table is laid out as follows:
 *
 *	state0:
 *		event01         aatv01          nextstate01
 *		event02         aatv02          nextstate02
 *		...
 *	state1:
 *		event11         aatv11          nextstate11
 *		...
 */

#define NUMSTATES	32	/* initial maximum number of states */

#define ST_INIT		0	/* initial state */

#define ST_RESERVED	240	/* beginning of reserved state range */
#define ST_SEEN		241	/* flag for state seen before being defined */
#define ST_DEFINED	242	/* flag for state definition */

#define ST_RECV		251	/* to indicate state which receives requests */
#define ST_HOLD		252	/* to indicate dead requests */
#define ST_SAME		253	/* for default action table */
#define ST_ANY		254	/* for default action table */
#define ST_END		255	/* end of FSM table */

typedef struct statelist        /* list of all state names */
{
	int        maxst;	/* capacity of this list */
	int        nst;		/* number of states already there */
	NAME_LIST *states;	/* list of states found in the config file */
} STATELIST;

typedef struct fsm_entry	/* The Finite State Machine an array of these */
{
	struct fsm_entry *next;		/* list of entries for this state */
	EV                event;	/* (state.action.event) 3-tuple */
	AATV             *action;	/* what AATV (action) to invoke */
	int               xvalue;	/* miscellaneous integer from FSM */
	char             *xstring;	/* miscellaneous string from FSM */
	u_char            next_state;	/* the next state to visit */
} FSM_ENT;

typedef struct prun_rule /* Pruning data structure (from RADIUS DRAFT RFC) */
{
	int               value;	/* this is the attribute value */
	int               flags;	/* inclusive OR of PRUN_FLG values */
	int               count;	/* how many the RFC says to allow */
} PRUN_RULE;

typedef struct prun_list
{
	char              vendor[AUTH_ID_LEN + 1];
	PRUN_RULE        *rules;
	struct prun_list *next;
} PRUN_LIST;

#define	PRUN_FLG1	1	/* this attribute allowable in Access_Accept */
#define	PRUN_FLG2	2	/* this attribute allowable in Access_Reject */

#define AR_NO_LOG	0x01		    /* sws: Suppress logging flag */
#define AR_FROM_PROXY	0x04		    /* sws: authreq came from NAS */

#define SAR_NO_LOG(authreq) (authreq->sws |= AR_NO_LOG)	      /* set flag */
#define CAR_NO_LOG(authreq) (authreq->sws &= ~AR_NO_LOG)      /* clear flag */
#define TAR_NO_LOG(authreq) ((authreq->sws & AR_NO_LOG) != 0) /* test flag */

#define SAR_FROM_PROXY(authreq) (authreq->sws |= AR_FROM_PROXY)   /* set flag */
#define CAR_FROM_PROXY(authreq) (authreq->sws &= ~AR_FROM_PROXY)  /* clr flag */
#define TAR_FROM_PROXY(authreq) ((authreq->sws & AR_FROM_PROXY) != 0) /* test */

#define AVPAIR_VTOA_QUOTE 0x0001 /* Quote strings with "'" */
#define AVPAIR_VTOA_NULL  0x0002 /* Print "" instead of NULL for missing item */
#define AVPAIR_VTOA_MASK  0x00ff /* Reserve fourteen more bits. */

#define LOG_VP_QUOTE	0x0001	/* Quote strings (same as AVPAIR_VTOA_QUOTE) */
#define LOG_VP_NULL	0x0002  /* Use "" (incompatible with LOG_VP_NA) */
#define LOG_VP_TAB	0x0100	/* Put tab after printing. */
#define LOG_VP_NA	0x0200  /* fprintf ("NA") if no attr exists in list. */
#define LOG_VP_LAST	0x0400	/* Log last value pair found. */
#define LOG_VP_ALL	0x0800	/* Log all attributes found. */
#define LOG_VP_MASK	0xFFFF	/* Switches available. */

/* dict.c */
int dict_init PROTO((void));
DICT_ATTR * dict_attrget PROTO((int));
DICT_ATTR * dict_attrfind PROTO((char *));
DICT_VALUE * dict_valfind PROTO((char *));
DICT_VALUE * dict_valget PROTO((UINT4, char *));

/* fsm.c */
AATV * find_aatv PROTO((char *));
int init_fsm PROTO((int, AATVPTR **, int, char *, FSM_ENT ***, FSM_ENT ***));

/* funcs.c */
char * add_string PROTO((char *, int));
char * authtype_toa PROTO((int));
VALUE_PAIR * avpair_add PROTO((VALUE_PAIR **, int, void *, int));
int avpair_assign PROTO((VALUE_PAIR *, void *, int));
int avpair_copy PROTO((VALUE_PAIR **, VALUE_PAIR *, int));
int avpair_get PROTO((void *, VALUE_PAIR *, int));
VALUE_PAIR * avpair_new PROTO((int, void *, int));
char * avpair_vtoa PROTO((VALUE_PAIR *, int));
void compress_file PROTO((FILE **, char *));
void debug_list PROTO((FILE *, VALUE_PAIR *));
void debug_pair PROTO((FILE *, VALUE_PAIR *));
int dumpit PROTO((/* int, int, void *, int, int, char *, ...*/));
void fprint_attr_val PROTO((FILE *, VALUE_PAIR *));
VALUE_PAIR * gen_valpairs PROTO((AUTH_HDR *));
char * get_errmsg PROTO((void));
int get_passwd PROTO((AUTH_REQ *, char *, char *, char *));
VALUE_PAIR * get_vp PROTO((VALUE_PAIR *, UINT4));
VALUE_PAIR * get_last_vp PROTO((VALUE_PAIR *, UINT4));
int hex_dump PROTO((char *, char *, int, int));
void insert_vp PROTO((VALUE_PAIR **, VALUE_PAIR *, VALUE_PAIR *));
int loghead PROTO(( /* va_alist */ ));

void missing_attribute PROTO((AUTH_REQ *, char *, int, char *));
VALUE_PAIR * parse_realm PROTO((AUTH_REQ *));
int prune_pairs PROTO((AUTH_REQ *, PRUN_LIST *, int));
#define reply_message(authreq, msgno, msg) _reply_message(authreq, msgno, msg,__FILE__, __LINE__)
int _reply_message PROTO((AUTH_REQ *, ERRORCODE, char *, char *, int));
int reply_sprintf PROTO(( /* int logsw, AUTHREQ *, char *format, ... */ ));
int setupsock PROTO((struct sockaddr_in *, int));
void trunc_logfile PROTO((FILE **, char *));
char * type_string PROTO((AUTH_REQ *, VALUE_PAIR *));

/* passchange.c */
int pw_expired PROTO((UINT4));

/* radiusd.c */
AUTH_REQ * build_acct_req PROTO((AUTH_REQ *, int, char *, int, VALUE_PAIR *));
int call_action PROTO((AATV *, AUTH_REQ *, int, char *));
AUTH_REQ * rad_2rad_recv PROTO((struct sockaddr_in *, UINT4, u_int, EV *));
AUTH_REQ * rad_recv PROTO((struct sockaddr_in *, UINT4, u_int, EV *));
int radius_send PROTO((char *, u_int, char *, AUTH_REQ *, int));
void start_fsm PROTO((AUTH_REQ *, int, char *, char *));

/* sesslog.c */
VALUE_PAIR *log_vp PROTO((FILE *, VALUE_PAIR *, int, int));
int logfmt_brief PROTO((FILE *, VALUE_PAIR *));
int logfmt_old PROTO((FILE *, VALUE_PAIR *, int));
int logfmt_v1_0 PROTO((FILE *, VALUE_PAIR *));
int logfmt_v1_1 PROTO((FILE *, VALUE_PAIR *));
int logfmt_v2_0 PROTO((FILE *, VALUE_PAIR *, int, u_short *));
int logfmt_v2_1 PROTO((FILE *, VALUE_PAIR *, int));

/* users.c */
int add_file_list PROTO((char *));
void config_init PROTO((void));
int config_files PROTO((int, int, int));
void config_fini PROTO((void));
void dns_recv PROTO((struct sockaddr_in *, UINT4, int));
AUTH_ENTRY * find_auth_ent PROTO((char *, int, char*));
int find_auth_type PROTO((char *, int, char *, int *, char **, char **, char **));
int find_client PROTO((UINT4, char **, char **, char **));
int find_client_by_name PROTO((UINT4 *, char *, char **, char **));
int find_host_by_name PROTO((UINT4 *, char *));
void free_user_ent PROTO((USER_ENTRY *));
UINT4 get_our_addr PROTO((void));
char * ip_hostname PROTO((UINT4));
void list_cat PROTO((VALUE_PAIR **, VALUE_PAIR *));
void list_copy PROTO((VALUE_PAIR **, VALUE_PAIR *));
int pair_parse PROTO((char *, VALUE_PAIR **));
FILE_LIST * return_file_list PROTO((void));
int update_clients PROTO((void));
int user_find PROTO((char *, char *, int, VALUE_PAIR **, VALUE_PAIR **, int));
void user_gettime PROTO((char *, struct tm *));
int user_update PROTO((char *, VALUE_PAIR *, VALUE_PAIR*));

/* util.c */
UINT4 get_ipaddr PROTO((char *));
int good_ipaddr PROTO((char *));
void list_free PROTO((VALUE_PAIR *));

/* version.c */
char * version PROTO((void));

#endif /* RADIUS_H */
