
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <limits.h>
#include <libaudit.h>
#include <sys/stat.h>

#include <tacplus/libtac.h>
#include "shell.h"
#include "error.h"

const char *configfile = "/etc/tacplus_servers";

/*
 * WARNING: don't show the key in any debug messages, since we are
 * usually run by an unprivileged user.
 */
typedef struct {
    struct addrinfo *addr;
    const char *key;
} tacplus_server_t;

/* set from configuration file parsing */
static tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
static int tac_srv_no, tac_key_no;
static int debug = 0;
static uid_t auth_uid;

static const char *progname = "bash-tacacsauth"; /* for syslogs and errors */

static void
tacplus_config(const char *cfile, int level)
{
    FILE *conf;
    char lbuf[256];

    conf = fopen(cfile, "r");
    if(conf == NULL) {
        fprintf(stderr, "%s: can't open TACACS config file %s: %s\n",
            progname, cfile, strerror(errno));
        return;
    }

    while(fgets(lbuf, sizeof lbuf, conf)) {
        if(*lbuf == '#' || isspace(*lbuf))
            continue; /* skip comments, white space lines, etc. */
        strtok(lbuf, " \t\n\r\f"); /* terminate buffer at first whitespace */
        if(!strncmp(lbuf, "include=", 8)) {
            /*
             * allow include files, useful for centralizing tacacs
             * server IP address and secret.
             */
            if(lbuf[8]) /* else treat as empty config */
                tacplus_config(&lbuf[8], level+1);
        }
        else if(!strncmp(lbuf, "debug=", 6))
            debug = strtoul(lbuf+6, NULL, 0);
        else if (!strncmp (lbuf, "timeout=", 8)) {
            tac_timeout = (int)strtoul(lbuf+8, NULL, 0);
            if (tac_timeout < 0) /* explict neg values disable poll() use */
                tac_timeout = 0;
            else /* poll() only used if timeout is explictly set */
                tac_readtimeout_enable = 1;
        }
        else if(!strncmp(lbuf, "secret=", 7)) {
            /* no need to complain if too many on this one */
            if(tac_key_no < TAC_PLUS_MAXSERVERS) {
                int i;
                if((tac_srv[tac_key_no].key = strdup(lbuf+7)))
                    tac_key_no++;
                else {
                    /*
                     * don't show the actual key, since we are usually run
                     * by an unprivileged user.
                     */
                    fprintf(stderr, "%s: unable to copy TACACS server secret\n",
                        progname);
                }
                /* handle case where 'secret=' was given after a 'server='
                 * parameter, fill in the current secret */
                for(i = tac_srv_no-1; i >= 0; i--) {
                    if (tac_srv[i].key)
                        continue;
                    tac_srv[i].key = strdup(lbuf+7);
                }
            }
        }
        else if(!strncmp(lbuf, "server=", 7)) {
            if(tac_srv_no < TAC_PLUS_MAXSERVERS) {
                struct addrinfo hints, *servers, *server;
                int rv;
                char *port, server_buf[sizeof lbuf];

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC;  /* use IPv4 or IPv6, whichever */
                hints.ai_socktype = SOCK_STREAM;

                strcpy(server_buf, lbuf + 7);

                port = strchr(server_buf, ':');
                if(port != NULL) {
                    *port = '\0';
					port++;
                }
                if((rv = getaddrinfo(server_buf, (port == NULL) ?
                            "49" : port, &hints, &servers)) == 0) {
                    for(server = servers; server != NULL &&
                        tac_srv_no < TAC_PLUS_MAXSERVERS;
                        server = server->ai_next) {
                        tac_srv[tac_srv_no].addr = server;
                        /* use current key, if our index not yet set */
                        if(tac_key_no && !tac_srv[tac_srv_no].key)
                            tac_srv[tac_srv_no].key = tac_srv[tac_key_no-1].key;
                        tac_srv_no++;
                    }
                }
                else if(debug) {
                    fprintf(stderr,
                        "%s: skip invalid server: %s (getaddrinfo: %s)\n",
                        progname, server_buf, gai_strerror(rv));
                }
            }
            else if(debug) {
                fprintf(stderr, "%s: maximum number of servers (%d) exceeded, "
                    "skipping\n", progname, TAC_PLUS_MAXSERVERS);
            }
        }
        else if(!strncmp(lbuf, "vrf=", 4) ||
            !strncmp(lbuf, "user_homedir=", 13))
            ; /*  we don't use these options, but don't complain below */
        else if(debug) /* ignore unrecognized lines, unless debug on */
            fprintf(stderr, "%s: unrecognized parameter: %s\n",
                progname, lbuf);
    }

    if(level == 0 && tac_srv_no == 0)
        fprintf(stderr, "%s no TACACS servers in file %s\n",
            progname, configfile);

    fclose(conf);
}

int
send_auth_msg(int tac_fd, const char *user, const char *tty, const char *host,
    uint16_t taskid, const char *cmd, char **args, int argc)
{
    char buf[128];
    struct tac_attrib *attr;
    int retval;
    struct areply re;
    int i;

    attr=(struct tac_attrib *)tac_xcalloc(1, sizeof(struct tac_attrib));

    snprintf(buf, sizeof buf, "%hu", taskid);
    tac_add_attrib(&attr, "task_id", buf);
    tac_add_attrib(&attr, "protocol", "ssh");
    tac_add_attrib(&attr, "service", "shell");

    tac_add_attrib(&attr, "cmd", (char*)cmd);

    /*
     * Add the command arguments.  Each argument has to be
     * less than 255 chars, including the "cmdargs=" portion
     * With the linux tac_plus server, at least, somewhere around
     * 2300 bytes of total argument always fails authorization.
     * I don't see a need to handle that specially.  Any truncation
     * might mean that something the administrator wants to deny
     * might miss being denied, if we didn't send that argument.
     */
    for(i=1; i<argc; i++) {
        char tbuf[248];
        const char *arg;
        if(strlen(args[i]) > 247) {
            snprintf(tbuf, sizeof tbuf, "%s", args[i]);
            arg = tbuf;
        }
        else
            arg = args[i];
        tac_add_attrib(&attr, "cmd-arg", (char *)arg);
    }

    re.msg = NULL;
    retval = tac_author_send(tac_fd, (char *)user, (char *)tty, (char *)host,
        attr);

    if(retval < 0)
        fprintf(stderr, "%s: send of authorization msg failed: %s\n",
            progname, strerror(errno));
    else {
        retval = tac_author_read(tac_fd, &re);
        if (retval < 0) {
            if(debug)
                fprintf(stderr, "%s: authorization response failed: %d\n",
                    progname, retval);
        }
        else if(re.status == AUTHOR_STATUS_PASS_ADD ||
            re.status == AUTHOR_STATUS_PASS_REPL)
            retval = 0;
        else  {
            if(debug)
                fprintf(stderr, "%s: cmd not authorized (%d)\n",
                    progname, re.status);
            retval = 1;
        }
    }

    tac_free_attrib(&attr);
    if(re.msg != NULL)
        free(re.msg);

    return retval;
}

/*
 * Send the command authorization request to the to each TACACS+ server
 * in the list, until one responds successfully or we exhaust the list.
 */
static int
send_tacacs_auth(const char *user, const char *tty, const char *host,
    const char *cmd, char **args, int argc)
{
    int retval = 1, srv_i, srv_fd, servers=0;
    uint16_t task_id;

    task_id = (uint16_t)getpid();

    for(srv_i = 0; srv_i < tac_srv_no; srv_i++) {
        srv_fd = tac_connect_single(tac_srv[srv_i].addr, tac_srv[srv_i].key,
            NULL, NULL);
        if(srv_fd < 0) {
            /*
             * This is annoying in the middle of a command, so
             * only print for debug.
            */
            if(debug)
                fprintf(stderr, "%s: error connecting to %s to request"
                    " authorization for %s: %s\n", progname,
                    tac_ntop(tac_srv[srv_i].addr->ai_addr),
                    cmd, strerror(errno));
            continue;
        }
        servers++;
        retval = send_auth_msg(srv_fd, user, tty, host, task_id,
            cmd, args, argc);
        if(retval && debug)
            fprintf(stderr, "%s: %s not authorized from %s\n",
                progname, cmd, tac_ntop(tac_srv[srv_i].addr->ai_addr));
        close(srv_fd);
        if(!retval && debug) {
            fprintf(stderr, "%s: %s authorized command %s\n",
                progname, tac_ntop(tac_srv[srv_i].addr->ai_addr), cmd);
            break; /* stop after first successful response */
        }
    }
    /*  if not debug, let them know when we couldn't reach any servers */
    if(!servers) {
        retval = -2; /*  so we don't say command not authorized */
        if(!debug)
            fprintf(stderr, "%s: Unable to connect to TACACS server(s)\n",
                progname);
    }
    return retval;
}


/*
 * Build up the command authorization request, using as many of the
 * args as will fit in a single tacacs packet.
 */
static int
build_auth_req(const char *user, const char *cmd, char **argv, int argc)
{
    int i;
    char tty[64], host[64];

    tty[0] = host[0] = 0;
    (void)gethostname(host, sizeof host -1);

    for(i=0; i<3; i++) {
        int r;
        if (isatty(i)) {
            r = ttyname_r(i, tty, sizeof tty -1);
            if (r && debug)
                fprintf(stderr, "%s: failed to get tty name for fd %d: %s\n",
                    progname, i, strerror(r));
            break;
        }
    }
    if (!host[0]) {
        snprintf(host, sizeof host, "UNK");
        if (debug)
            fprintf(stderr, "%s: Unable to determine hostname, passing %s\n",
                progname, host);
    }
    if (!tty[0]) {
        snprintf(tty, sizeof tty, "UNK");
        if (debug)
            fprintf(stderr, "%s: Unable to determine tty, passing %s\n",
                progname, tty);
    }

    return send_tacacs_auth(user, tty, host, cmd, argv, argc);
}



/*
 * Tacacs authorization.
 */
int tacacs_authorization (cmd)
     char *cmd;
{
	char* current_user_name = current_user.user_name;
	
    tacplus_config(configfile, 0);
	
    int ret = build_auth_req(current_user_name, cmd, 0, 0);
	switch (ret) {
		case 0:
			internal_warning ("%s authorized, executing\n", cmd);
		break;
		case 2:
			/*  -2 means no servers, so already a message */
			internal_warning ("%s not authorized by TACACS+ with given arguments, not executing\n", cmd);
		break;
		default:
			internal_warning ("%s authoriz failed by TACACS+ with given arguments, not executing\n", cmd);
		break;
	}
	
	return ret;
    
}