/*-----------------------------------------------------------------------------/
 * project: rfc4938
 * file: rfc4938.c
 * version: 1.05
 * date: October 4, 2007
 *
 * Copyright owner (c) 2007-2009 by cisco Systems, Inc.
 *
 * ===========================
 * This file implements the rfc4938 controlling program which communicates
 * with other rfc4938 processes and accepts user input from the rfc4938ctl
 * process.  This file also fork/execs pppoe processes corresponding to new
 * neighbors.
 * ===========================
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *----------------------------------------------------------------------------*/

#include "rfc4938.h"
#include "rfc4938ctl_message.h"
#include "sys/wait.h"

static int pppoe_port = PPPOE_START_PORT;

/* rfc4938 usage information */
static char usage[] =

    "\n"
    "  usage: rfc4938 [options]\n"
    "\n"
    "  Options:\n"
    "      -h                : Show this help menu\n"
    "      -f (filepath)     : Override the default config file path\n"
    "      -v                : Display version info\n"
    "\n";

/* version information */
static char version[] =

    "\n"
    "\tversion: rfc4938 1.05\n"
    "\t      Copyright (C) 2007-2009 by Cisco Systems, Inc.\n"
    "\n";


/*
 * This function processes packets received from rfc4938ctl and 
 * the pppoe proccesses
 *
 * input:
 *   rcv_buffer - message buffer
 *   bufsize - size of the buffer
 *   source_addr - source address of the buffer
 *   source_len - length of the source address sockaddr   
 *
 * return:
 *   SUCCESS
 */

static void
packet_parser ( unsigned char * rcv_buffer,
                int bufsize,
                struct sockaddr *source_addr,
                socklen_t source_len)
{

    rfc4938_ctl_message_t  *p2ctlmsg;

    if (rcv_buffer == NULL) {
        return;
    }
     
    p2ctlmsg = (rfc4938_ctl_message_t *)rcv_buffer;


    switch (p2ctlmsg->header.cmd_code) {

        /* CTL */
    case CTL_SESSION_START:
        recv_session_start(p2ctlmsg, source_addr, source_len);
        break;
    case CTL_SESSION_START_READY:
        recv_session_start_ready(p2ctlmsg->ctl_start_ready_payload.ip_addr,
                                 p2ctlmsg->ctl_start_ready_payload.port_number);                                 
        break;
    case CTL_SESSION_STOP:
        recv_session_stop(p2ctlmsg->ctl_stop_payload.ip_addr);
        break;

        /* CLI */
    case CLI_SESSION_INITIATE:
        initiate_sessions(p2ctlmsg->cli_initiate_payload.neighbor_id,
                          p2ctlmsg->cli_initiate_payload.credit_scalar);
        break;
    case CLI_SESSION_TERMINATE:
        terminate_sessions(p2ctlmsg->cli_terminate_payload.neighbor_id);
        break;
    case CLI_SESSION_PADQ:
        padq_session(p2ctlmsg->cli_padq_payload.neighbor_id,
                     p2ctlmsg->cli_padq_payload.receive_only,
                     p2ctlmsg->cli_padq_payload.rlq,
                     p2ctlmsg->cli_padq_payload.resources,
                     p2ctlmsg->cli_padq_payload.latency,
                     p2ctlmsg->cli_padq_payload.cdr_scale,
                     p2ctlmsg->cli_padq_payload.current_data_rate,
                     p2ctlmsg->cli_padq_payload.mdr_scale,
                     p2ctlmsg->cli_padq_payload.max_data_rate);
        break;
    case CLI_SESSION_PADG:
        padg_session(p2ctlmsg->cli_padg_payload.neighbor_id,
                     p2ctlmsg->cli_padg_payload.credits);
        break;
    case CLI_SESSION_SHOW:
        show_session();
        break;
    case CLI_SESSION_SHOW_RESPONSE:
        break;
    default:
        RFC4938_DEBUG_ERROR("rfc4938: Error, unknown command 0x%x \n",
                            p2ctlmsg->header.cmd_code);
        break;
    }

    return;
}

static int 
sendCTLPacket (UINT16_t port, void *p2buffer)
{
    struct sockaddr_in peer_addr;
    socklen_t len_inet;
    int s, z;
    int buffer_length;
    rfc4938_ctl_message_t *p2ctlmsg;

    if (p2buffer == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: Attempted to send NULL p2buffer\n");
        return (ERANGE);
    }

    if (port == 0) {
        RFC4938_DEBUG_ERROR("rfc4938: No port to send CTLPacket to\n");
        return (ERANGE);
    }

    p2ctlmsg = (rfc4938_ctl_message_t *) p2buffer;

    switch (p2ctlmsg->header.cmd_code) {

    case CTL_SESSION_START:
        buffer_length = SIZEOF_CTL_START_REQUEST;
        break;
    case CTL_SESSION_START_READY:
        buffer_length = SIZEOF_CTL_START_READY;
        break;
    case CTL_SESSION_STOP:
        buffer_length = SIZEOF_CTL_STOP_REQUEST;
        break;
    case CTL_SESSION_PADQ:
        buffer_length = SIZEOF_CTL_PADQ_REQUEST;
        break;
    case CTL_SESSION_PADG:
        buffer_length = SIZEOF_CTL_PADG_REQUEST;
        break;
    default:
        RFC4938_DEBUG_ERROR("rfc4938: Error, unsupported command 0x%x \n",
                            p2ctlmsg->header.cmd_code);
        return (ERANGE);
        break;
    }

    s = socket(AF_INET,SOCK_DGRAM,0);
    if ( s == -1 ) {
        RFC4938_DEBUG_ERROR("rfc4938: Unable to create socket\n");
        return (EFAULT);
    }

    memset(&peer_addr,0,sizeof (peer_addr));
    peer_addr.sin_family = AF_INET;    
    peer_addr.sin_port = htons(port);
    peer_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if ( peer_addr.sin_addr.s_addr == INADDR_NONE ) {
        RFC4938_DEBUG_ERROR("rfc4938: sendCTLPacket: Bad address.\n");
        return (ERANGE);
    } 

    if ( peer_addr.sin_port == 0 ) {
        RFC4938_DEBUG_ERROR("rfc4938: sendCTLPacket: Bad port.\n");
        return (ERANGE);
    }     

    len_inet = sizeof (peer_addr);

    z = sendto(s,   
               p2buffer,
               buffer_length,
               0,               
               (struct sockaddr *)&peer_addr,
               len_inet);  

    if ( z < 0 ) {
        RFC4938_DEBUG_ERROR("rfc4938: sendCTLPacket(): Error sending packet\n");
        return (ERANGE);
    } else {
        RFC4938_DEBUG_EVENT("rfc4938: CTL packet sent successfully"
                            " to %s:%u\n",  
                            inet_ntoa(peer_addr.sin_addr),
                            port);
    }

    close(s);
    
    return (SUCCESS);
}


/*
 * This function parses the configuration file and assigns
 * the appropriate parameters in the CONFIG struct. Then
 * neighbors are added to linked list.
 *
 * input:
 *   filename: name of config file
 *
 * return:
 *   SUCCESS
 */

static int
receive_messages (void)
{
    int rc_socket, rc_bind, rc_recvfrom;
    struct sockaddr_in my_addr;
    struct sockaddr_in source_addr;
    socklen_t source_len, my_len;


#define RCV_BUF_LEN    ( 1800 )
    unsigned char rcv_buffer[RCV_BUF_LEN];

    rc_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if ( rc_socket == -1 ) {
        perror("socket()");
        return (EFAULT);
    }
    
    memset(&my_addr,0,sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(CONFIG.rfc4938_port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if ( my_addr.sin_addr.s_addr == INADDR_NONE ) {
        RFC4938_DEBUG_ERROR("rfc4938: Bad address to bind to\n");
        return (EFAULT);
    }
    
    my_len = sizeof (my_addr);

    RFC4938_DEBUG_EVENT("rfc4938: rfc4938 binding to %d\n", CONFIG.rfc4938_port);

    rc_bind = bind(rc_socket,
                   (struct sockaddr *)&my_addr,
                   my_len);

    if ( rc_bind == -1 ) {
        RFC4938_DEBUG_ERROR("rfc4938: Unable to bind to address\n");
        return (EFAULT);
    }

    while (rc_socket >= 0) {
         
        source_len = sizeof (source_addr);
         
        rc_recvfrom = recvfrom(rc_socket,            
                               rcv_buffer,
                               RCV_BUF_LEN,
                               0,          
                               (struct sockaddr *)&source_addr,
                               &source_len); 
         
        if ( rc_recvfrom < 0 ) {
            RFC4938_DEBUG_ERROR("rfc4938: Error receiving UDP packet\n");
            return (EFAULT);
        }

        packet_parser(rcv_buffer,
                      rc_recvfrom,
                      (struct sockaddr *)&source_addr,
                      source_len);                 
         
    }
    return SUCCESS;
}

/*
 * Config Neighbor
 *
 * This function takes information from read_config_file and uses it to
 * allocate a neighbor.
 *
 * input:
 *   argc
 *   *argv[]
 *
 * output:
 *   rc_errno
 */
int
config_neighbor (UINT32_t argc, char *argv[])
{
    int rc_errno;

    RFC4938_DEBUG_EVENT("rfc4938: NEIGHBOR %u %s\n", 
                        (UINT32_t)strtoul(argv[1], NULL, 10), argv[2]);
    RFC4938_DEBUG_EVENT("rfc4938: PORT %u\n", CONFIG.rfc4938_port);

    rc_errno = neighbor_allocate(strtoul(argv[1], NULL, 10),       /* node id */
                                 inet_addr(argv[2]),          /* node addr */
                                 0);      /* rfc4938 port */
    return rc_errno;
}

/*
 * get_ipaddrs
 *
 * Fills in an array of the ip addresses currently configured
 * on the box.
 *
 * source: http://www.hungry.com/~alves/local-ip-in-C.html
 *
 */
static void
get_ipaddrs(char **ip_addrs)
{
    int i, j=0;
    struct ifreq ifr;
    int s = socket (PF_INET, SOCK_STREAM, 0);
    char *ip;
    
    for (i=1,j=0;;i++,j++)
    {
        ip_addrs[j] = malloc(sizeof(char) * IPV4_STR_LENGTH);
        if (ip_addrs[j] == NULL){
            RFC4938_DEBUG_ERROR("rfc4938: get_ipaddrs() malloc failure");
            return;
        }
        
        struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
        
        ifr.ifr_ifindex = i;
        if (ioctl (s, SIOCGIFNAME, &ifr) < 0) {
            break;
        }
        
        /* now ifr.ifr_name is set */
        if (ioctl (s, SIOCGIFADDR, &ifr) < 0) {
            continue;
        }
        
        ip = inet_ntoa (sin->sin_addr);
        strncpy(ip_addrs[j], ip, IPV4_STR_LENGTH);
    }
    
    ip_addrs[j] = NULL;
    close (s);
}

/*
 * Read Config File
 *
 * This function parses the configuration file and assigns
 * the appropriate parameters in the CONFIG struct. Then
 * neighbors are added to linked list.
 *
 * input:
 *   filename: name of config file
 *
 * return:
 *   SUCCESS
 */
int
read_config_file (char *filename) 
{
    int i, skip_address = 0;

    FILE *fp;
#define MAX_INPUT_LENGTH  ( 512 )
    char input_string[MAX_INPUT_LENGTH];

#define ARGC_MAX   ( 5 )
    UINT32_t argc;
    char *argv[ARGC_MAX];
    char *ip_addrs[IPV4_STR_LENGTH];
    int ip_check = 0;

    fp = fopen(filename, "r");
    if (!fp) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, problem opening config file: %s\n", filename);
        return (ENOENT);
    }

    /* retrieve the currently configured IPv4 addresses */
    get_ipaddrs(ip_addrs);

    while (fgets(input_string, MAX_INPUT_LENGTH, fp)) {

        argv[0] = strtok(input_string, " \t\n");
        argc = 1;

        for (i=1; i<ARGC_MAX; i++) {
            argv[i] = strtok(NULL, " \t\n");

            if (argv[i] == NULL) {
                break;
            } else {
                argc++;
            }
        }

        /* empty line */
        if (argv[0] == NULL) {
            continue;
        }

        /* comment */
        else if (strncmp(argv[0], "#", strlen("#")) == 0) {
            continue;
        }

        /* iface */
        else if (strncmp(argv[0], "IFACE", strlen("IFACE")) == 0) {
        //CONFIG.iface = (char *)malloc(STR_MAX*sizeof(char));
        if (CONFIG.iface == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: ERROR: iface malloc error\n");
        return (ENOMEM);
        }
            strncpy(CONFIG.iface, argv[1], STR_MAX - 1);
        }

        /* max_neighbors */
        else if (strncmp(argv[0], "MAX_NEIGHBORS", 
                         strlen("MAX_NEIGHBORS")) == 0) {
            CONFIG.max_nbrs = strtoul(argv[1], NULL, 10);
        neighbor_init(CONFIG.max_nbrs);
        }

        /* port */
        else if (strncmp(argv[0], "PORT", strlen("PORT")) == 0) {
            CONFIG.rfc4938_port = strtoul(argv[1], NULL, 10);
        }

        /* ctl_port */
        else if (strncmp(argv[0], "CTL_PORT", strlen("CTL_PORT")) == 0) {
            CONFIG.ctl_port = strtoul(argv[1], NULL, 10);
        }

        /* neighbor */
        else if (strncmp(argv[0], "NEIGHBOR", strlen("NEIGHBOR")) == 0) {            
        if (check_ip(argv[2]) != SUCCESS) {
        return (ENOENT);
        }

            /* make sure we don't add ourselves as a valid neighbor */
            skip_address = 0;
            
            for (ip_check = 0; 
                 (ip_check < MAX_IFACES) && (ip_addrs[ip_check] != NULL);
                 ip_check++) {
                if (strncmp(argv[2], ip_addrs[ip_check], IPV4_STR_LENGTH) == 0) {
                    skip_address = 1;
                    RFC4938_DEBUG_EVENT("rfc4938: Skipping neighbor creation of %s"
                                        " since that is our address.\n",
                                        ip_addrs[ip_check]);
                    break;
                }
            }

            if (skip_address != 1) {
                if (config_neighbor(argc, argv) != SUCCESS) {
                    RFC4938_DEBUG_ERROR("rfc4938: Error allocating neighbor\n");
                    return (ENOENT);
                }
            }
        }

        /* service_name */
        else if (strncmp(argv[0], "SERVICE_NAME", strlen("SERVICE_NAME")) == 0) {
        //CONFIG.service_name = (char *)malloc(STR_MAX*sizeof(char));
        if (CONFIG.service_name == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, service_name malloc error\n");
        return (ENOMEM);
        }
            strncpy(CONFIG.service_name, argv[1], STR_MAX-1);
        }

    /* debug_level */
        else if (strncmp(argv[0], "DEBUG_LEVEL", strlen("DEBUG_LEVEL")) == 0) {
            CONFIG.debug_level = strtoul(argv[1], NULL, 10);
        } else {
            RFC4938_DEBUG_ERROR("rfc4938: Unknown config file command  %s \n", argv[0]);
            return (ENOENT);
        }
    }

    fclose(fp);
    return SUCCESS;
}

/*
 * This function checks the validity of an ip address
 *
 * input:
 *   addr: the input ipv4 address
 *
 * return:
 *   SUCCESS
 */
int
check_ip (char *addr)
{
    int i, value;
    char *token, orig[16];
    memcpy(orig, addr, 16);
    i = 0;
    token = strtok(orig, ".");

    while (strtok(NULL, ".") != NULL) {
    i++;
    value = strtoul(token, 0, 10);
    if (value < 0 || value > 255) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, ip address octets must be between 0 and 255\n");
        return (EFAULT);
    }
    }
    if (i != 3) {
    RFC4938_DEBUG_ERROR("rfc4938: Error, ip address incorrect length\n");
    return (EFAULT);
    }
    
    return SUCCESS;
}

/*
 * This function returns the iface
 *
 * return:
 *   iface
 */
char* 
get_iface (void)
{
    return CONFIG.iface;
}

/*
 * This function returns the service name
 *
 * return:
 *   service name
 */
char* 
get_service_name (void)
{
    return CONFIG.service_name;
}

/*
 * This function returns the max_nbrs
 *
 * return:
 *   max_nbrs
 */
UINT16_t
get_max_nbrs (void)
{
    return CONFIG.max_nbrs;
}

/*
 * This function returns the rfc4938_port
 *
 * return:
 *   rfc4938_port
 */
UINT16_t
get_rfc4938_port (void)
{
    return CONFIG.rfc4938_port;
}

/*
 * This function returns the ctl_port
 *
 * return:
 *   ctl_port
 */
UINT16_t
get_ctl_port (void)
{
    return CONFIG.ctl_port;
}

/*
 * This function returns the debug level
 *
 * return:
 *   debug_level
 */
UINT16_t
get_debug_level (void)
{
    return CONFIG.debug_level;
}

/*
 * This function sets the specified neighbor to ACTIVE
 *
 * input:
 *   neighbor_id - individual neighbor id, or 0 for all neighbors
 *   credit_scalar - scalar for those sessions, or 0 for 4938 only session
 *
 * output:
 *   SUCCESS
 */
int
initiate_sessions (UINT32_t neighbor_id, UINT16_t credit_scalar)
{
    rfc4938_neighbor_element_t *tmp;

    if (neighbor_id == 0) {
    neighbor_toggle_all(&initiate_neighbor, credit_scalar);
    return SUCCESS;
    } else {
        if (neighbor_pointer(neighbor_id, &tmp) != SUCCESS) {
            RFC4938_DEBUG_ERROR("ERROR: unable to find neighbor_id %u\n",
                                neighbor_id);
           return (EBADMSG); 
        }    

        RFC4938_DEBUG_EVENT("rfc4938: initiating session for neighbor %u "
                            "credit_scalar %u\n", neighbor_id,
                            credit_scalar);

        initiate_neighbor(tmp, 0, credit_scalar);

        return SUCCESS;  
    }
}

/*
 * This function sets the specified neighbor to INACTIVE
 *
 * input:
 *   neighbor_id - individual neighbor id, or 0 for all neighbors
 *
 * output:
 *   SUCCESS
 */
int
terminate_sessions (UINT32_t neighbor_id)
{
    rfc4938_neighbor_element_t *tmp;

    if (neighbor_id == 0) {
        RFC4938_DEBUG_EVENT("rfc4938: terminating all neighbors\n");
    neighbor_toggle_all(&terminate_neighbor, 0);
    return SUCCESS;
    } else {
        if (neighbor_pointer(neighbor_id, &tmp) != SUCCESS) {
            RFC4938_DEBUG_ERROR("rfc4938: Error, unable to find neighbor_id %u\n",
                                neighbor_id);
           return (EBADMSG); 
        }

        terminate_neighbor(tmp, 0, 0);
    RFC4938_DEBUG_EVENT("rfc4938: terminate:\nneighbor\t%u\n", neighbor_id);
        return SUCCESS;  
    }
}

/*
 * zombie_killer: kill those zombies!
 *
 * input:
 * signo - signal number
 *
 * output:
 */
void
zombie_killer(int signo)
{
    pid_t   pid;
    rfc4938_neighbor_element_t *tmp;
    int rc;
    int status;

    pid = 1;
    while (pid > 0) {
        pid = waitpid (-1, &status, WNOHANG);        
        
        if (pid > 0) {
            if (WIFEXITED(status)) {
                RFC4938_DEBUG_EVENT("rfc4938: pppoe child %d terminated %s.\n", 
                                    pid,
                                    (WEXITSTATUS(status)==0)? "cleanly":"unexpectedly");
            }

            rc = neighbor_pointer_by_pid (pid, &tmp);

            if (rc == SUCCESS) {
                terminate_neighbor(tmp, 0, 0); 
            }
        }
    }
}


/*
 * padq session: inject a padq based on rfc4938ctl user input
 *
 * input:
 *   neighbor_id
 *   receive_only
 *   rlq
 *   resources
 *   latency
 *   cdr_scale
 *   current_data_rate
 *   mdr_scale
 *   max_data_rate
 *
 * output:
 *   SUCCESS
 */
int
padq_session (UINT32_t neighbor_id,
              UINT8_t receive_only,
              UINT8_t rlq,
              UINT8_t resources,
              UINT16_t latency,
              UINT16_t cdr_scale,
              UINT16_t current_data_rate,
              UINT16_t mdr_scale,
              UINT16_t max_data_rate)
{
    int retval;
    rfc4938_neighbor_element_t *tmp;
    void *p2buffer;

    /* find the neighbor */
    if (neighbor_pointer(neighbor_id, &tmp) != SUCCESS) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, unable to find neighbor_id %u\n", neighbor_id);
       return (EBADMSG); 
    }

    /* check to see if there is a session up for it */
    if (tmp->session_state != ACTIVE) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, neighbor_id %u is not active\n", neighbor_id);
        return (EBADMSG);
    }

    p2buffer = malloc(SIZEOF_CTL_PADQ_REQUEST);

    if (p2buffer == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, unable to allocate buffer for ctl_padq_request\n");
        return (EBADMSG);
    }

    if (rfc4938_ctl_format_session_padq(receive_only,
                                        rlq,
                                        resources,
                                        latency,
                                        cdr_scale,
                                        current_data_rate,
                                        mdr_scale,
                                        max_data_rate,
                                        p2buffer) != SUCCESS) {
        RFC4938_DEBUG_ERROR("rfc4938: ERror, padq_session(): unable to format message\n");
        free(p2buffer);
        return (EBADMSG);
    }
    
    retval = sendCTLPacket(tmp->neighbor_port, p2buffer);
    
    RFC4938_DEBUG_EVENT("rfc4938: padq_session(): sent PADQ to neighbor %u on port %u with values "
                        "receive_only %u rlq %u resources %u latency %u\n"
                        "cdr_scale %u current_data_rate %u mdr_scale %u\n"
                        "max_data_rate %u\n",
                        tmp->neighbor_id, tmp->neighbor_port,
                        receive_only, rlq, resources, latency,
                        cdr_scale, current_data_rate, mdr_scale, max_data_rate);
    free(p2buffer);
    return (retval);
}

/*
 * padg_session: inject a padg based on rfc4938ctl user input
 *
 * input:
 *   neighbor_id
 *   credits
 *
 * output:
 *   SUCCESS
 */
int
padg_session (UINT32_t neighbor_id, UINT16_t credits) 
{
    int retval;
    rfc4938_neighbor_element_t *tmp;
    void *p2buffer;

    p2buffer = malloc(SIZEOF_CTL_PADG_REQUEST);

    if (p2buffer == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, unable to allocate "
                            "buffer for ctl_padg_request\n");
        return (EBADMSG);
    }

    RFC4938_DEBUG_EVENT("rfc4938: padg_session(): received CLI request to send "
                        "%u credits to nbr %u\n", credits, neighbor_id);

    /* find the neighbor */
    if (neighbor_pointer(neighbor_id, &tmp) != SUCCESS) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, unable to find neighbor_id %u"
                            "in padg_session()\n", neighbor_id);
        free(p2buffer);
       return (EBADMSG); 
    }    
    
    /* check to see if there is a session up for it */
    if (tmp->session_state != ACTIVE) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, neighbor_id %u is not "
                            "active in padg_session()\n", neighbor_id);
        free(p2buffer);
        return (EBADMSG);
    }

    if (rfc4938_ctl_format_session_padg(credits, p2buffer) != SUCCESS) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, unable to format message in padg_session()\n");
        free(p2buffer);
        return (EBADMSG);
    }
    
    retval = sendCTLPacket(tmp->neighbor_port, p2buffer);

    RFC4938_DEBUG_EVENT("rfc4938: sent PADG with %u credits"
                        " to neighbor %d on port %u\n", credits, 
                        tmp->neighbor_id, tmp->neighbor_port);

    free(p2buffer);
    return (retval);
}

/*
 * show_session
 *
 * This function sends all of the neighbor information back to rfc4938ctl.c
 *
 * output:
 *   SUCCESS
 */
int
show_session (void)
{
    int z;
    struct sockaddr_in adr_srvr;
    int len_inet;
    int s;
    char dgram[SHOWLEN];
    char *ptr = &dgram[0];

    neighbor_print_all_string(&ptr); 
    
    memset(&adr_srvr,0,sizeof adr_srvr);
    adr_srvr.sin_family = AF_INET;
    adr_srvr.sin_port = htons(CONFIG.ctl_port);
    adr_srvr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

    if ( adr_srvr.sin_addr.s_addr == INADDR_NONE ) {
        RFC4938_DEBUG_ERROR("rfc4938: Bad address to bind to in show_session()");
        return (EFAULT);
    }

    len_inet = sizeof adr_srvr;

    s = socket(AF_INET,SOCK_DGRAM,0);
    if ( s == -1 ) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, unable to create "
                            "socket in show_session()\n");
        return (EFAULT);
    }

    z = sendto(s,
               dgram,
               (strlen(dgram) + 1),
               0,
               (struct sockaddr *)&adr_srvr,
               len_inet);

    if ( z < 0 ) {
        RFC4938_DEBUG_ERROR("rfc4938: Error sending UDP "
                            "packet in show_session()");
    close(s);
        return (EFAULT);
    }

    close(s);

    return (SUCCESS);
}


/*
 * initiate_neighbor
 *
 * Initiates a single neighbor by fork/exec'ing a pppoe process
 *
 * input:
 *   *nbr: pointer to neighbor
 *
 * return:
 *
 */
void
initiate_neighbor (rfc4938_neighbor_element_t *nbr, 
                   UINT16_t peer_port,
                   UINT16_t credit_scalar) 
{
    int i, a=0;
    pid_t pid;
    char *arguments[MAXARGS];

    UINT16_t debug_level = get_debug_level();
    
    if (nbr->session_state == ACTIVE) {
        RFC4938_DEBUG_EVENT("rfc4938: neighbor %s already ACTIVE, not "
                            "initiating new one\n",
                            inet_ntoa(*(struct in_addr *)&(nbr->neighbor_addr)));        
        return;
    }
    
    if (nbr->pid != 0) {
        RFC4938_DEBUG_EVENT("rfc4938: neighbor %s already has a pid (%u),"
                            " not initiating new one\n",
                            inet_ntoa(*(struct in_addr *)&(nbr->neighbor_addr)),
                            nbr->pid);
        return;
    }
    
    /* build argument list */

    /* prevent rollover of port */
    if (pppoe_port == 65535) {
        pppoe_port = PPPOE_START_PORT;
    } else {
        pppoe_port++;
    }

    arguments[a] = "pppoe";
    a++;
    
    /* set inactivity timeout to infinity */
    arguments[a] = "-T0";
    a++;

    /* set host unique tag to be used */
    arguments[a] = "-U";
    a++;

    /* set interface name */
    arguments[a] = malloc(sizeof(char) * (strlen(get_iface()) + OPTLEN));
    if (arguments[a] == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: malloc error for iface name\n");
        return;
    }
    sprintf(arguments[a], "-I%s", get_iface());
    a++;

    /* set service name */
    arguments[a] = malloc(sizeof(char) * (strlen(CONFIG.service_name) + OPTLEN));
    if (arguments[a] == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: malloc error for service name\n");
        return;
    }
    sprintf(arguments[a], "-S%s", CONFIG.service_name);
    a++;

    /* set ip of neighbor */
    arguments[a] = malloc(sizeof(char) * 
                          (strlen((const char *)
                                  inet_ntoa(*(struct in_addr *)&(nbr->neighbor_addr))) 
                           + OPTLEN));
    if (arguments[a] == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: malloc error for ip arg\n");
        return;
    }
    sprintf(arguments[a], "-y%s", inet_ntoa(*(struct in_addr *)&(nbr->neighbor_addr)));
    a++;
    
    /* set port for pppoe to listen to */
    arguments[a] = malloc(sizeof(char) * PORTARG);
    if (arguments[a] == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: malloc error for pppoe port arg\n"); 
        return;
    }
    sprintf(arguments[a], "-r%u", pppoe_port);
    a++;

    /* set port for the peer pppoe process */
    if (peer_port != 0) {
        arguments[a] = malloc(sizeof(char) * PORTARG);
        if (arguments[a] == NULL) {
            RFC4938_DEBUG_ERROR("rfc4938: malloc error for rfc4938 port arg\n"); 
            return;
        }
        sprintf(arguments[a], "-R%u", peer_port);
        a++;
    }

    /* set the scaling factor */
    arguments[a] = malloc(sizeof(char) * PORTARG);
    if (arguments[a] == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: malloc error for rfc4938 scalar arg\n");
        return;
    }
    sprintf(arguments[a], "-x%u", credit_scalar);
    a++;

    /* set port for parent process */
    arguments[a] = malloc(sizeof(char) * PORTARG);
    if (arguments[a] == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: malloc error for rfc4938 port arg\n");
        return;
    }
    sprintf(arguments[a], "-c%u", get_rfc4938_port());
    a++;

    /* set debug level */
    arguments[a] = malloc(sizeof(char) * PORTARG);
    if (arguments[a] == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: malloc error for debug level arg\n");
        return;
    }
    sprintf(arguments[a], "-z%u", debug_level);
    a++;

    arguments[a] = NULL;

    RFC4938_DEBUG_EVENT("rfc4938: Creating pppoe session with params:\n");
    for (i = 0; i < a; i++){
        RFC4938_DEBUG_EVENT("rfc4938: %s\n", arguments[i]);
    }

    pid = fork();

    switch (pid) {
    case 0: /* The child process */
        execvp(PPPOEBINARY, arguments);
        RFC4938_DEBUG_EVENT("rfc4938: Child process terminated "
                            "ID: %u for %s\n", 
                            nbr->pid,
                            inet_ntoa(*(struct in_addr *)&(nbr->neighbor_addr)));
        break;
    case -1: /* error */
        RFC4938_DEBUG_ERROR("rfc4938: Error, fork failed with error: %s for"
                            " child %s\n", 
                            strerror(errno),  
                            inet_ntoa(*(struct in_addr *)&(nbr->neighbor_addr)));
        break;
    default: /* The parent process */
        nbr->pid = pid;
        RFC4938_DEBUG_EVENT("rfc4938: Child process created "
                            "successfully. New process' ID: %u for %s\n", 
                            nbr->pid,
                            inet_ntoa(*(struct in_addr *)&(nbr->neighbor_addr)));
        break;
    }

    /* free argument string */
    for (i = 3; i < a; i++){
        /* start at 3 since 0,1,2 are statics */
        if (arguments[i] != NULL){
            free(arguments[i]);
        }
    }
}

/*
 * terminate_neighbor
 *
 * Terminates one neighbor
 *
 * input:
 *   *pointer: pointer to neighbor
 *   not_used: unused parameter to satisfy neighbor_toggle_all
 * return:
 *
 */
void
terminate_neighbor (rfc4938_neighbor_element_t *nbr, 
                    UINT16_t not_used, UINT16_t not_used2)
{
    
    void *p2buffer;

    if (nbr == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: NULL nbr requested to be terminated\n");
        return;
    }
    
    if (nbr->session_state == INACTIVE) {
        RFC4938_DEBUG_EVENT("rfc4938: INACTIVE nbr requested to be terminated\n");
        return;
    }

    p2buffer = malloc(SIZEOF_CTL_STOP_REQUEST);

    if (p2buffer == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, unable to allocate buffer for "
                            "ctl_stop_request\n");
        return;
    }

    if (rfc4938_ctl_format_session_stop(nbr->neighbor_addr, p2buffer) != SUCCESS) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, terminate_neighbor(): unable to "
                            "format message\n");
        free(p2buffer);
        return;
    }
    
    nbr->session_state = INACTIVE;
    nbr->pid = 0;
    nbr->neighbor_port = 0;
    nbr->send_session_start_ready = 0;
    free(p2buffer);
}


/*
 * recv_session_start
 *
 * Receives a session start message from a peer pppoe process
 *
 * input:
 *   p2ctlmsg: control message
 *   source_addr: source address of the message
 *   source_len: length of the message
 *
 * return:
 *
 */
void
recv_session_start (rfc4938_ctl_message_t *p2ctlmsg,
                    struct sockaddr *source_addr,
                    int source_len)
{
    rfc4938_neighbor_element_t *tmp;
    UINT32_t ip_addr;
    UINT16_t port, scalar;
    void *p2buffer;

    ip_addr = (UINT32_t) ((struct sockaddr_in *)source_addr)->sin_addr.s_addr;
    port = ntohs(p2ctlmsg->ctl_start_payload.port_number);
    scalar = ntohs(p2ctlmsg->ctl_start_payload.credit_scalar);
    
    RFC4938_DEBUG_EVENT("rfc4938: Received session start message with"
                        " port %u and address of %s, embedded port %u and "
                        "scalar of %u\n",
                        ((struct sockaddr_in *) source_addr)->sin_port,
                        inet_ntoa(*(struct in_addr *)&(ip_addr)),
                        port, scalar);

    if (neighbor_pointer_by_addr(ip_addr, &tmp) != SUCCESS) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, received session start message from"
                            " %s port %u, but no neighbor exists for that peer\n",
                            inet_ntoa(*(struct in_addr *)&(ip_addr)),
                            port);
        return;
    }

    if (tmp->session_state == ACTIVE || tmp->pid != 0) {
        /* 
         * we've hit a timing window where both pppoe clients were started
         * but neither will get the session_start_ready message to learn
         * the peer's port.  We will send this message.
         */
        RFC4938_DEBUG_EVENT("rfc4938: Received session start message from"
                            " %s port %u, pppoe client already started"
                            " sending start ready message to it\n",
                            inet_ntoa(*(struct in_addr *)&(ip_addr)),
                            port);

        p2buffer = malloc(SIZEOF_CTL_START_READY);

        if (p2buffer == NULL) {
            RFC4938_DEBUG_ERROR("rfc4938: Error, unable to allocate buffer for ctl_start_ready\n");
            return;
        }

        if (rfc4938_ctl_format_session_start_ready(ip_addr, 
                                                   port, 
                                                   p2buffer) != SUCCESS) {
            RFC4938_DEBUG_ERROR("rfc4938: recv_session_start(): "
                                "Unable to format message\n");
            free(p2buffer);
        }
        
        if (tmp->session_state == INACTIVE){
            RFC4938_DEBUG_EVENT("rfc4938: pppoe processs %s was still inactive, we don't"
                                " have a port to send him a message on\n",
                                inet_ntoa(*(struct in_addr *)&(tmp->neighbor_addr)));
            tmp->send_session_start_ready = port;
        } else {
            sendCTLPacket(tmp->neighbor_port, p2buffer);
        }
        free(p2buffer);
    } else {
        RFC4938_DEBUG_EVENT("rfc4938: Peer %s was not ACTIVE or had a nonzero pid"
                            " or both.  Initiating now.\n",
                            inet_ntoa(*(struct in_addr *)&(ip_addr)));
        initiate_neighbor(tmp, port, scalar);
    }
}

/*
 * recv_session_start_ready
 *
 * Receives a session start ready message from a pppoe process that 
 * has been fork/exec'ed
 *
 * input:
 *   ip_addr: ip address of the neighbor it corresponds to
 *   port: port of the pppoe process
 *
 * return:
 *
 */
void
recv_session_start_ready (UINT32_t ip_addr, UINT16_t port)
{
    rfc4938_neighbor_element_t *tmp;
    void *p2buffer;

    RFC4938_DEBUG_EVENT("rfc4938: Received session start rdy message from pppoe"
                        " process with port %u and address of %s\n",
                        port,
                        inet_ntoa(*(struct in_addr *)&(ip_addr)));


    if (neighbor_pointer_by_addr(ip_addr, &tmp) != SUCCESS) {
        return;
    }
    
    tmp->session_state = ACTIVE;
    tmp->neighbor_port = ntohs(port);

    /* 
     * check to see if we need to echo a start_ready message back
     * since the peer has already sent us a start message 
     */
    if (tmp->send_session_start_ready != 0) {
        
        p2buffer = malloc(SIZEOF_CTL_START_READY);

        if (p2buffer == NULL) {
            RFC4938_DEBUG_ERROR("rfc4938: Error, unable to allocate buffer "
                                "for recv_session_start_ready\n");
            return;
        }

        if (rfc4938_ctl_format_session_start_ready(0, 
                                                   tmp->send_session_start_ready,
                                                   p2buffer) != SUCCESS) {
            RFC4938_DEBUG_ERROR("rfc4938: recv_session_start(): "
                                "Unable to format message\n");
            free(p2buffer);
        }

        RFC4938_DEBUG_EVENT("rfc4938: Received session start ready message from pppoe"
                            " process for %s port %u, now bouncing delayed start ready message"
                            " back to it with port %u\n",
                            inet_ntoa(*(struct in_addr *)&(ip_addr)),
                            port,
                            tmp->send_session_start_ready);
        
        sendCTLPacket(tmp->neighbor_port, p2buffer);
        free(p2buffer);
    }
}


/*
 * recv_session_stop
 *
 * Receives a session stop message from a pppoe process that 
 * has been terminated
 *
 * input:
 *   ip_addr: ip address of the neighbor it corresponds to
 *
 * return:
 *
 */
void
recv_session_stop (UINT32_t ip_addr)
{
    rfc4938_neighbor_element_t *tmp;

    RFC4938_DEBUG_EVENT("rfc4938: Received session stop message from %s\n",
                        inet_ntoa(*(struct in_addr *)&(ip_addr)));

    if (neighbor_pointer_by_addr(ip_addr, &tmp) != SUCCESS) {
        return;
    }
    
    terminate_neighbor(tmp, 0, 0);
}

/*
 * kill_all_sessions 
 *
 * Terminates all current sessions
 *
 */
void
kill_all_sessions (int signo)
{

    if (signo == SIGINT) {
        RFC4938_DEBUG_EVENT("rfc4938: received SIGINT\n");
    } else if (signo == SIGHUP) {
        RFC4938_DEBUG_EVENT("rfc4938: received SIGHUP\n");
    } else if (signo == SIGTERM) {
        RFC4938_DEBUG_EVENT("rfc4938: received SIGTERM\n");
    } else if (signo == SIGTSTP) {
        RFC4938_DEBUG_EVENT("rfc4938: received SIGTSTP\n");
    }

    terminate_sessions(0);
    exit(0);
}

/*
 * MAIN
 */
int
main (int argc, char *argv[])
{
    int c;
    int rfc4938_debug;
    char filename[MAXFILENAME];
    FILE *f;

    /* read options */
    while ((c = getopt(argc, argv, "vhf:")) != EOF)
    {
        switch (c) {
    case 'h':  /* usage */
            printf("%s", usage);
            return SUCCESS;
        break;
        case 'v':
            printf("%s", version);
            return SUCCESS;
            break;
        case 'f':  /* config file */
            memcpy(filename, optarg, MAXFILENAME);
            break;
    default:
            return (EBADMSG);
        }
    }

    if (filename[0] == 0) {
    strncpy(filename, CONFIGPATH, MAXFILENAME);
    }

    /* read the config file */
    if (read_config_file(filename)){
        RFC4938_DEBUG_ERROR("rfc4938: Error reading config file\n");
    return (ECANCELED);
    }

    /* Initialize debugs */
    rfc4938_debug = get_debug_level();

    /* setup debugs */
    if (rfc4938_debug >= 1) {
        rfc4938_set_debug_mask(RFC4938_G_ERROR_DEBUG);
    }
    if (rfc4938_debug >= 2) {
        rfc4938_set_debug_mask(RFC4938_G_EVENT_DEBUG);
    }
    if (rfc4938_debug >= 3) {
        rfc4938_set_debug_mask(RFC4938_G_PACKET_DEBUG);
    }

    /* print neighbors */
    if (rfc4938_debug == 2 || rfc4938_debug == 3) {
    neighbor_print_all();
    }

    /* Check to make sure the pppoe binary exists */
    f = fopen(PPPOEBINARY, "r");
    if (f == NULL) {
        RFC4938_DEBUG_ERROR("rfc4938: Error, pppoe binary doesn't exist\n");
        return (ENOENT);
    }
    fclose(f);

    signal(SIGCHLD, zombie_killer);
    signal(SIGINT, kill_all_sessions);
    signal(SIGHUP, kill_all_sessions);  
    signal(SIGTERM, kill_all_sessions);
    signal(SIGTSTP, kill_all_sessions);
    
    RFC4938_DEBUG_EVENT("rfc4938: CONFIG struct: \n");
    RFC4938_DEBUG_EVENT("rfc4938: IFACE: %s\n", get_iface());
    RFC4938_DEBUG_EVENT("rfc4938: MAX_NBR: %u\n", get_max_nbrs());
    RFC4938_DEBUG_EVENT("rfc4938: RFC4938 port: %u\n", get_rfc4938_port());
    RFC4938_DEBUG_EVENT("rfc4938: RFC4938CTL port: %u\n", get_ctl_port());
    RFC4938_DEBUG_EVENT("rfc4938: SERVICE_NAME: %s\n", get_service_name());
    RFC4938_DEBUG_EVENT("rfc4938: DEBUG_LEVEL: %u\n", get_debug_level());

    /* open a socket an listen for messages */
    receive_messages();

    return SUCCESS;
}

/* EOF */
