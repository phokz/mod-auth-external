/*************************************************************************
 *
 *      Function: get_ipaddr
 *
 *      Purpose: Return an IP address in host long notation from a host
 *               name or address in dot notation.
 *
 *************************************************************************/

UINT4
get_ipaddr (host)

char           *host;

{
        struct hostent *hp;

        if (good_ipaddr (host) == 0)
        {
                return ntohl(inet_addr (host));
        }
        else if ((hp = gethostbyname (host)) == (struct hostent *) NULL)
        {
                return ((UINT4) 0);
        }
        return ntohl((*(UINT4 *) hp->h_addr));
} /* end of get_ipaddr () */


/*************************************************************************
 *
 *      Function: good_ipaddr
 *
 *      Purpose: Check for valid IP address in standard dot notation.
 *
 *************************************************************************/

int
good_ipaddr (addr)

char           *addr;

{
        int             dot_count;
        int             digit_count;

        if (addr == (char *) NULL)
        {
                return (-1);
        }

        dot_count = 0;
        digit_count = 0;

        while (*addr != '\0' && *addr != ' ')
        {
                if (*addr == '.')
                {
                        dot_count++;
                        digit_count = 0;
                }
                else if (!isdigit (*addr))
                {
                        dot_count = 5;
                }
                else
                {
                        digit_count++;
                        if (digit_count > 3)
                        {
                                dot_count = 5;
                        }
                }
                addr++;
        }
        if (dot_count != 3)
        {
                return (-1);
        }
        else
        {
                return (0);
        }
} /* end of good_ipaddr () */


/*************************************************************************
*
*       find_match - See if given IP address matches any address of hostname.
*
*       Returns:         0 success
*                       -1 failure
*
**************************************************************************/

static int 
find_match (ip_addr, hostname)

UINT4          *ip_addr;
char           *hostname;

{
        UINT4           addr;
        char          **paddr;
        struct hostent *hp;

        if (good_ipaddr (hostname) == 0)
        {
                if (*ip_addr == ntohl(inet_addr (hostname)))
                {
                        return (0);
                }
        }
        else
        {
                if ((hp = gethostbyname (hostname)) == (struct hostent *) NULL)
                {
                        return (-1);
                }
                if (hp->h_addr_list != (char **) NULL)
                {
                        for (paddr = hp->h_addr_list; *paddr; paddr++)
                        {
                                addr = ** (UINT4 **) paddr;
                                if (ntohl(addr) == *ip_addr)
                                {
                                        return (0);
                                }
                        }
                }
        }
        return (-1);
} /* end of find_match */


/*************************************************************************
*
*       find_server - Look up the given server name in the clients file.
*
*       Returns:         0 success
*                       -1 failure
*
**************************************************************************/

static int 
find_server (server_name, ustype, ip_addr, secret, msg)

char           *server_name;
int             ustype;
UINT4          *ip_addr;
char           *secret;
char           *msg;

{
        static UINT4    myipaddr = 0;
        int             len;
        int             line_nbr = 0;
        int             result;
        FILE           *clientfd;
        char           *h;
        char           *s;
        char           *host2;
        char            buffer[128];
        char            fname[MAXPATHLEN];
        char            hostnm[AUTH_ID_LEN + 1];

        /* Get the IP address of the authentication server */
        if ((*ip_addr = get_ipaddr (server_name)) == (UINT4) 0)
        {
                return (-1);
        }
        sprintf (fname, "%s/%s", radius_dir, RADIUS_CLIENTS);
        if ((clientfd = fopen (fname, "r")) == (FILE *) NULL)
        {
                return (-1);
        }
        if (!myipaddr)
        {
                if ((myipaddr = get_ipaddr (ourhostname)) == 0)
                {
                        fclose (clientfd);
                        return (-1);
                }
        }

        result = 0;
        while (fgets (buffer, sizeof (buffer), clientfd) != (char *) NULL)
        {
                line_nbr++;

                if (*buffer == '#')
                {
                        continue;
                }

                if ((h = strtok (buffer, " \t\n\r")) == NULL) /* 1st hostname */                {
                        continue;
                }

                memset (hostnm, '\0', AUTH_ID_LEN);
                len = strlen (h);
                if (len > AUTH_ID_LEN)
                {
                        len = AUTH_ID_LEN;
                }
                strncpy (hostnm, h, len);
                hostnm[AUTH_ID_LEN] = '\0';

                if ((s = strtok (NULL, " \t\n\r")) == NULL) /* & secret field */                {
                        continue;
                }

                memset (secret, '\0', MAX_SECRET_LENGTH);
                len = strlen (s);
                if (len > MAX_SECRET_LENGTH)
                {
                        len = MAX_SECRET_LENGTH;
                }
                strncpy (secret, s, len);
                secret[MAX_SECRET_LENGTH] = '\0';

                if (!strchr (hostnm, '/')) /* If single name form */
                {
                        if (find_match (ip_addr, hostnm) == 0)
                        {
                                result++;
                                break;
                        }
                }
                else /* <name1>/<name2> "paired" form */
                {
                        strtok (hostnm, "/"); /* replaces "/" with NULL char */
                        host2 = strtok (NULL, " ");
                        if (find_match (&myipaddr, hostnm) == 0)
                        {            /* If we're the 1st name, target is 2nd */
                                if (find_match (ip_addr, host2) == 0)
                                {
                                        result++;
                                        break;
                                }
                        }
                        else    /* Check to see if we are the second name */
                        {
                                if (find_match (&myipaddr, host2) == 0)
                                { /* We are the 2nd name, target is 1st name */
                                        if (find_match (ip_addr, hostnm) == 0)
                                        {
                                                result++;
                                                break;
                                        }
                                }
                        }
                }
        }
        fclose (clientfd);
        if (result == 0)
        {
                memset (buffer, '\0', sizeof (buffer));
                memset (secret, '\0', sizeof (secret));
                return (-1);
        }
        return 0;
} /* end of find_server () */


/*************************************************************************
*
*       random_vector - Generates a random vector of AUTH_VECTOR_LEN octets.
*
*       Returns:        the vector (call by reference)
*
**************************************************************************/

void
random_vector (vector)

u_char         *vector;

{
        int             randno;
        int             i;

        srand (time (0));
        for (i = 0; i < AUTH_VECTOR_LEN;)
        {
                randno = rand ();
                memcpy ((char *) vector, (char *) &randno, sizeof (int));
                vector += sizeof (int);
                i += sizeof (int);
        }
        return;
} /* end of random_vector () */





/*************************************************************************
*
*       send_server - Sends request to specified RADIUS server and waits
*                     for response.  Request is retransmitted every
*                     "response_timeout" seconds a maximum of "retry_max"
*                     times.  Result is 0 if response was received, -1 if
*                     a problem occurred, or +1 on no-response condition.
*                     Returns request retransmit count in "retries" if
*                     server does respond.
*
*       Returns:        -1 ERROR_RC   -- on local error,
*                        0 OK_RC      -- on valid response from server,
*                        1 TIMEOUT_RC -- after retries * resp_timeout seconds,
*                       -2 BADRESP_RC -- if response from server had errors.
*
**************************************************************************/

int 
send_server (data, retries, msg)

SEND_DATA      *data;           /* Data structure built by clients */
int            *retries;        /* Maximum num of times to retransmit request */
                                /* Receives number of retries required, also */
char           *msg;            /* Receives error or advisory message */

{
        u_char          seq_nbr;    /* Sequence number to use in request  */
        int             fptype;     /* Framed proto, ustype == PW_FRAMED */
        int             i;
        int             length;
        int             result;
        int             retry_max;
        int             salen;
        int             secretlen;
        int             sockfd;
        int             timeout;    /* Number of secs. to wait for response */
        int             total_length;
        int             ustype;     /* User service type for this user */
        UINT4           auth_ipaddr;
        UINT4           lvalue;
        UINT4           myipaddr;
        UINT4           port_num;   /* Port number to use in request  */
        AUTH_HDR       *auth;
        VALUE_PAIR     *check;
        char           *passwd;         /* User password (unencrypted) */
        u_char         *ptr;
        VALUE_PAIR     *reply;
        char           *server_name;    /* Name of server to query */
        struct sockaddr_in *sin;
        struct servent *svp;
        struct timeval  authtime;
        fd_set          readfds;
        struct sockaddr salocal;
        struct sockaddr saremote;
        u_char          md5buf[256];
        u_char          passbuf[AUTH_PASS_LEN];
        u_char          send_buffer[1024];
        u_char          recv_buffer[1024];
        u_char          vector[AUTH_VECTOR_LEN];
        char            file[MAXPATHLEN];
        char            secret[MAX_SECRET_LENGTH + 1];

        server_name = data->server;


        if (server_name == (char *) NULL || server_name[0] == '\0')
        {
                server_name = DEFAULT_RADIUS_SERVER;
        }

        ustype = data->ustype;

        if (find_server (server_name, ustype, &auth_ipaddr, secret, msg) != 0)
        {
                return (ERROR_RC);
        }

        timeout = data->timeout;
        if (timeout == 0)
        {
                timeout++;
        }

        if (data->svc_port == 0)
        {
                if ((svp = getservbyname ("radius", "udp")) == NULL)
                {
                        data->svc_port = PW_AUTH_UDP_PORT;
                }
                else
                {
                        data->svc_port = ntohs (svp->s_port);
                }
        }

        if (!radsock)
        {
                sockfd = socket (AF_INET, SOCK_DGRAM, 0);
                if (sockfd < 0)
                {
                        memset (secret, '\0', sizeof (secret));
                        return (ERROR_RC);
                }

                length = sizeof (salocal);
                sin = (struct sockaddr_in *) & salocal;
                memset ((char *) sin, '\0', length);
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = INADDR_ANY;
                sin->sin_port = htons (0);
                if (bind (sockfd, (struct sockaddr *) sin, length) < 0 ||
                           getsockname (sockfd, (struct sockaddr *) sin,
                                        &length) < 0)
                {
                        close (sockfd);
                        memset (secret, '\0', sizeof (secret));
                        return (ERROR_RC);
                }
                retry_max = *retries;   /* Max. numbers to try for reply */
                *retries = 0;   /* Init retry cnt for blocking call */
        }
        else
        {
                sockfd = radsock;
                retry_max = 0;  /* No retries if non-blocking */
        }

        /* Build an authentication request */
        auth = (AUTH_HDR *) send_buffer;
        auth->code = data->code;
        random_vector (vector);
        seq_nbr = data->seq_nbr;
        auth->id = seq_nbr;
        memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);
        total_length = AUTH_HDR_LEN;
        ptr = auth->data;

        /* User Name */
        *ptr++ = PW_USER_NAME;
        length = strlen (data->user_name);
        if (length > AUTH_ID_LEN)
        {
                length = AUTH_ID_LEN;
        }
        *ptr++ = length + 2;
        memcpy ((char *) ptr, data->user_name, length);
        ptr += length;
        total_length += length + 2;

        passwd = data->password;

        if (auth->code != PW_ACCOUNTING_REQUEST)
        {
                        /* User Password */
                        *ptr++ = PW_USER_PASSWORD;
                        *ptr++ = AUTH_PASS_LEN + 2;

                        /* Encrypt the Password */
                        length = strlen (passwd);
                        if (length > AUTH_PASS_LEN)
                        {
                                length = AUTH_PASS_LEN;
                        }
                        memset ((char *) passbuf, '\0', AUTH_PASS_LEN);
                        memcpy ((char *) passbuf, passwd, length);

                        /* Calculate the MD5 Digest */
                        secretlen = strlen (secret);
                        strcpy ((char *) md5buf, secret);
                        memcpy ((char *) md5buf + secretlen,
                                (char *) auth->vector, AUTH_VECTOR_LEN);
                        md5_calc (ptr, md5buf, secretlen + AUTH_VECTOR_LEN);

                        /* Xor the password into the MD5 digest */
                        for (i = 0; i < AUTH_PASS_LEN; i++)
                        {
                                *ptr++ ^= passbuf[i];
                        }
                        total_length += AUTH_PASS_LEN + 2;

        }

        /* Service Type */
        *ptr++ = PW_SERVICE_TYPE;
        *ptr++ = 2 + sizeof (UINT4);
        lvalue = htonl (ustype);
        memcpy ((char *) ptr, (char *) &lvalue, sizeof (UINT4));
        ptr = ptr + sizeof (UINT4);
        total_length += sizeof (UINT4) + 2;

        fptype = data->fptype;
        if (fptype > 0)                 /* if -t [slip | ppp] */
        {
                /* Framed Protocol Type */
                *ptr++ = PW_FRAMED_PROTOCOL;
                *ptr++ = 2 + sizeof (UINT4);
                lvalue = htonl (fptype);
                memcpy ((char *) ptr, (char *) &lvalue, sizeof (UINT4));
                ptr = ptr + sizeof (UINT4);
                total_length += sizeof (UINT4) + 2;
        }

        /* Client IP Address */
        *ptr++ = PW_NAS_IP_ADDRESS;
        *ptr++ = 2 + sizeof (UINT4);
        myipaddr = htonl(data->client_id);
        memcpy ((char *) ptr, (char *) &myipaddr, sizeof (UINT4));
        ptr = ptr + sizeof (UINT4);
        total_length += sizeof (UINT4) + 2;

        /* Client Port Number */
        *ptr++ = PW_NAS_PORT;
        *ptr++ = 2 + sizeof (UINT4);
        port_num = htonl((UINT4) data->port_num);
        memcpy ((char *) ptr, (char *) &port_num, sizeof (UINT4));
        ptr = ptr + sizeof (UINT4);
        total_length += sizeof (UINT4) + 2;

        if (data->user_file != (char *) NULL) /* add a/v pairs from user_file */        {
	  /* We should never get here! but just in case */
	  return(-77);
        }

        if (data->send_pairs != (VALUE_PAIR *) NULL) /* add more a/v pairs */
        {
	  /* We should never get here! but just in case */
	  return(-88);

        }

        auth->length = htons (total_length);

        sin = (struct sockaddr_in *) & saremote;
        memset ((char *) sin, '\0', sizeof (saremote));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl (auth_ipaddr);
        sin->sin_port = htons (data->svc_port);

        for (;;)
        {
                sendto (sockfd, (char *) auth, (int) total_length, (int) 0,
                        (struct sockaddr *) sin, sizeof (struct sockaddr_in));

                if (radsock)
                {               /* If non-blocking */

                        /*
                         * Return stuff to be saved for evaluation of reply
                         * when it comes in
                         */
                        strcpy (msg, secret);
                        memcpy (msg + strlen (msg) + 1, (char *) vector,
                                AUTH_VECTOR_LEN);
                        memset (secret, '\0', sizeof (secret));
                        return 1;       /* Pos. return means no error */
                }
                /* according to radius@msg.com 0L causing problems with BSD */
                /* Changing it to 999L for a longer timeout interval */
                authtime.tv_usec = 999L;
                authtime.tv_sec = (long) timeout;
                FD_ZERO (&readfds);
                FD_SET (sockfd, &readfds);
                if (select (sockfd + 1, &readfds, NULL, NULL, &authtime) < 0)
                {
                        if (errno == EINTR)
                                continue;
                        memset (secret, '\0', sizeof (secret));
                        close (sockfd);
                        return (ERROR_RC);
                }
                if (FD_ISSET (sockfd, &readfds))
                        break;

                /*
                 * Timed out waiting for response.  Retry "retry_max" times
                 * before giving up.  If retry_max = 0, don't retry at all.
                 */
                if (++(*retries) >= retry_max)
                {
                        close (sockfd);
                        memset (secret, '\0', sizeof (secret));
                        return (TIMEOUT_RC);
                }
        }
        salen = sizeof (saremote);
        length = recvfrom (sockfd, (char *) recv_buffer,
                           (int) sizeof (recv_buffer),
                           (int) 0, &saremote, &salen);

        if (length <= 0)
        {
                close (sockfd);
                memset (secret, '\0', sizeof (secret));
                return (ERROR_RC);
        }
        result = check_radius_reply (recv_buffer, secret, vector,
                (u_int) seq_nbr, msg);
        close (sockfd);
        memset (secret, '\0', sizeof (secret));
        return (result);

} /* end of send_server () */


/*************************************************************************
*
*       check_radius_reply - Verify items in returned packet.
*
*       Returns:        OK_RC       -- upon success,
*                       BADRESP_RC  -- if anything looks funny.
*
*       Public entry point necessary for MINOS/MNET daemon.
*
**************************************************************************/

int 
check_radius_reply (buffer, secret, vector, seq_nbr, msg)

u_char         *buffer;
char           *secret;
u_char          vector[];
u_int           seq_nbr;
char           *msg;

{
        u_char          len;
        int             result;
        int             secretlen;
        int             totallen;
        AUTH_HDR       *auth;
        u_char         *next;
        u_char         *ptr;
        VALUE_PAIR     *vp;
        u_char          calc_digest[AUTH_VECTOR_LEN];
        u_char          reply_digest[AUTH_VECTOR_LEN];

        auth = (AUTH_HDR *) buffer;
        totallen = ntohs (auth->length);


        /* Verify that id (seq. number) matches what we sent */
        if (auth->id != (u_char) seq_nbr)
        {
                return (BADRESP_RC);
        }

        /* Verify the reply digest */
        memcpy ((char *) reply_digest, (char *) auth->vector, AUTH_VECTOR_LEN);
        memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);
        secretlen = strlen (secret);
        memcpy ((char *) buffer + totallen, secret, secretlen);
        md5_calc (calc_digest, (char *) auth, totallen + secretlen);

        if (memcmp ((char *) reply_digest, (char *) calc_digest,
                    AUTH_VECTOR_LEN) != 0)
        {
                return (BADRESP_RC);
        }

        msg[0] = '\0';
        ptr = (u_char *) auth->data;
        totallen -= AUTH_HDR_LEN;
        while (totallen > 0)
        {
                len = ptr[1];
                totallen -= len;
                next = ptr + len;
                if (*ptr == '\0')
                {
                        return (BADRESP_RC);
                }

                if (*ptr == PW_REPLY_MESSAGE)
                {
                        ptr++;
                        ptr++;
                        strncat (msg, (char *) ptr, len - 2);
                        strcat (msg, "\n");
                }
                ptr = next;
        }

        if ((auth->code == PW_ACCESS_ACCEPT) ||
                (auth->code == PW_PASSWORD_ACK) ||
                (auth->code == PW_ACCOUNTING_RESPONSE))
        {
                result = OK_RC;
        }
        else
        {
                result = BADRESP_RC;
        }

        return (result);
} /* end of check_radius_reply () */


