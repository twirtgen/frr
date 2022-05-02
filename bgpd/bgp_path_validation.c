//
// Created by thomas on 26/04/22.
//

#include "bgp_path_validation.h"

#include <sys/socket.h>
#include <sys/eventfd.h>

#include "command.h"
#include "lib/yang.h"
#include "lib/routemap.h"
#include "lib/northbound_cli.h"
#include "lib/command.h"
#include "lib/frr_pthread.h"

#include "lib/prefix.h"

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_memory.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_path_validation_clippy.c"
#endif

#define RETRIES_DEFAULT 3
#define TIMEOUT_DEFAULT_MS 300

#define PATH_VALIDATION_STRING "Validate path with TLS server contained in large community\n"


struct pval_arg {
	struct sockaddr_storage saddr;
	struct bgp_path_info *p_info;
	const struct prefix *pfx;
};

static struct frr_pthread *bgp_pth_pval = NULL;

static unsigned int retries_number;
static unsigned int timeout_ms;

static int config_write(struct vty *vty);
static int config_on_exit(struct vty *vty);

static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,
					       void *object);
static void *route_match_compile(const char *arg);
static void route_match_free(void *rule);
static void install_cli_commands(void);
static int reset(bool force);

static struct cmd_node path_validation_node = {
	.name = "path-validation",
	.node = PATH_VALIDATION_NODE, // enum node_type lib/command.h
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-path-validation)# ",
	.config_write = config_write,
	.node_exit = config_on_exit,
};

static const struct route_map_rule_cmd route_match_path_validation_cmd = {
	"path-validation", route_match, route_match_compile, route_match_free};


static int process_path_validation(struct thread *thread) {
	struct pval_arg *arg;
	char addr[45];
	char pfx[PREFIX2STR_BUFFER];

	arg = THREAD_ARG(thread);

	if (arg->saddr.ss_family == AF_INET) {
		inet_ntop(AF_INET,
			  &((struct sockaddr_in *) &arg->saddr)->sin_addr,
			  addr, sizeof (addr));
	} else if (arg->saddr.ss_family == AF_INET6) {
		inet_ntop(AF_INET6,
			  &((struct sockaddr_in6 *) &arg->saddr)->sin6_addr,
			  addr, sizeof(addr));
	} else {
		fprintf(stderr, "Unrecognized address family !\n");
	}


	fprintf(stderr, "Contacting TLS server %s for prefix %s\n",
		addr, prefix2str(arg->pfx, pfx, sizeof(pfx)));


	free(arg);
	return 0;
}

static int config_write(struct vty *vty) {

	vty_out(vty, "!\n");
	vty_out(vty, "path-validation\n");

	if (retries_number != RETRIES_DEFAULT)
		vty_out(vty, "path-validation retries %u\n", retries_number);
	if (timeout_ms != TIMEOUT_DEFAULT_MS)
		vty_out(vty, "path-validation timeout %u\n", timeout_ms);

	vty_out(vty, "exit");
	return 1;
}

static int config_on_exit(struct vty *vty) {
	reset(false);
	return 1;
}

static int reset(bool force) {
	return 0;
}

static void bgp_path_validation_thread_init(void) {

	assert(!bgp_pth_pval);

	struct frr_pthread_attr pval = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop,
	};


	bgp_pth_pval = frr_pthread_new(&pval, "BGP Path Validation thread",
				       "bgp_pval");

}


int bgp_path_validation_init(struct thread_master *master) {
	retries_number = RETRIES_DEFAULT;
	timeout_ms = TIMEOUT_DEFAULT_MS;

	install_cli_commands();

	bgp_path_validation_thread_init();
	fprintf(stderr, "BGP Path validation initialized !\n");
	return 0;
}

void bgp_path_validation_run(void) {
	frr_pthread_run(bgp_pth_pval, NULL);
	frr_pthread_wait_running(bgp_pth_pval);
}

struct my_lcom {
	uint32_t global_admin;
	union {
		struct {
			uint32_t val1;
			uint32_t val2;
		};
		uint64_t val64;
	} val;
};

struct my_addr {
	union {
		struct {
			uint64_t high;
			uint64_t lo;
		};
		uint32_t v4[4];
	};
};


#define hip6tobe(ip6) ({\
    struct in6_addr ip6be_;                    \
    uint32_t *ip_;      \
    ip_ = ((ip6)->v4);    \
    ip6be_.s6_addr32[0] = htobe32(ip_[0]);\
    ip6be_.s6_addr32[1] = htobe32(ip_[1]);\
    ip6be_.s6_addr32[2] = htobe32(ip_[2]);\
    ip6be_.s6_addr32[3] = htobe32(ip_[3]);     \
    ip6be_;\
})


/*
 * try to match large communities
 * having the following form
 * FFFF FFFE: xxxx xxxx : xxxx xxxx (hi bits id ipv6)
 * FFFF FFFF: xxxx xxxx : xxxx xxxx (ipv4 && lo bits of ipv6)
 */
static int match_large_communities(struct lcommunity *lcom,
				   struct sockaddr *saddr) {
	int i;
	int matchv6 = 0, matchv4 = 0;
	int nb_com;
	struct lcommunity_val *values;
	struct my_lcom *current_lcom;
	struct my_addr addr;


	nb_com = lcom->size ; // / LCOMMUNITY_SIZE;
	values = (struct lcommunity_val *) lcom->val;
	for (i = 0; i < nb_com; i++) {
		current_lcom = (struct my_lcom *) values[i].val;

		if (current_lcom->global_admin == 0xFFFFFFFE) {
			matchv6 = 1;
			addr.high = be64toh(current_lcom->val.val64);
		} else if (current_lcom->global_admin == 0xFFFFFFFF) {
			matchv4 = 1;
			addr.lo = be64toh(current_lcom->val.val64);
		}
	}

	if (matchv6 && !matchv4) {
		return 0; // no match
	}

	if (!matchv6 && matchv4) {
		/* ipv4 addr */
		struct sockaddr_in *addr4 = (struct sockaddr_in *) saddr;
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = htobe32(addr.v4[3]);
	} else {
		/* ipv6 addr */
		struct sockaddr_in6 *addr6  = (struct sockaddr_in6 *) saddr;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_addr = hip6tobe(&addr);
	}

	return matchv4;
}


static enum route_map_cmd_result_t route_match(void *rule,
					       const struct prefix *prefix,
					       void *object) {
	int *path_validation_status = rule;
	struct bgp_path_info *path;
	struct attr *bgp_attr;
	struct lcommunity *lcommunity;
	struct sockaddr_storage addr;
	struct pval_arg *arg;

	path = object;
	bgp_attr = path->attr;

	/* no match if no large bgp communities */
	if (!(bgp_attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES)))
		return RMAP_NOMATCH;


	/* check if we need to check the path */
	lcommunity = bgp_attr->lcommunity;
	if (!match_large_communities(lcommunity, (struct sockaddr *) &addr)) {
		return RMAP_NOMATCH;
	}

	arg = XMALLOC(MTYPE_PATH_VALIDATION_THREAD_ARG, sizeof(*arg));
	*arg = (struct pval_arg) {
		.pfx = prefix,
		.p_info = path,
		.saddr = addr,
	};

	/* there is a match, push the sockaddr to a queue for validation */
	thread_add_event(bgp_pth_pval->master,
			 process_path_validation, arg, 0, NULL);


	/*if (rpki_validate_prefix(path->peer, path->attr, prefix)
	    == *rpki_status) {
		return RMAP_MATCH;
	}*/

	return *path_validation_status == PATH_VALIDATION_PENDING ? RMAP_MATCH : RMAP_NOMATCH;
}


static void *route_match_compile(const char *arg)
{
	int *path_validation_status;

	path_validation_status = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(int));

	if (strcmp(arg, "valid") == 0)
		*path_validation_status = PATH_VALIDATION_VALID;
	else if (strcmp(arg, "invalid") == 0)
		*path_validation_status = PATH_VALIDATION_INVALID;
	else
		*path_validation_status = PATH_VALIDATION_PENDING;

	return path_validation_status;
}

static void route_match_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}


DEFUN_NOSH(path_validation,
	   path_validation_cmd,
	   "path-validation",
	   "Enable path validation and enter path-configuration mode\n"
	   ) {
	vty->node =  PATH_VALIDATION_NODE;
	return CMD_SUCCESS;
}


DEFPY (path_validation_retries,
      path_validation_retries_cmd,
      "path-validation retries (1-7200)$ret",
      PATH_VALIDATION_STRING
      "Set retry interval\n"
      "retry interval value\n")
{
	retries_number = ret;
	return CMD_SUCCESS;
}

DEFUN (no_path_validation_retries,
      no_path_validation_retries_cmd,
      "no path-validation retries",
      NO_STR
	PATH_VALIDATION_STRING
      "Set retry numbers back to default\n")
{
	retries_number = RETRIES_DEFAULT;
	return CMD_SUCCESS;
}


DEFPY (path_validation_timeout,
      path_validation_timeout_cmd,
      "path-validation timeout (1-4294967295)$tm",
      PATH_VALIDATION_STRING
      "Set timeout limit\n"
      "Timeout value\n")
{
	timeout_ms = tm;
	return CMD_SUCCESS;
}

DEFUN (no_path_validation_timeout,
      no_path_validation_timeout_cmd,
      "no path-validation timeout",
      NO_STR
      PATH_VALIDATION_STRING
      "Set timeout value back to default\n")
{
	timeout_ms = TIMEOUT_DEFAULT_MS;
	return CMD_SUCCESS;
}



DEFUN_YANG (match_path_validation,
	   match_path_validation_cmd,
	   "match path-validation <valid|invalid|pending>",
	   MATCH_STR
	   PATH_VALIDATION_STRING
	   "Valid prefix, the TLS server responds\n"
	   "Invalid prefix, the TLS servers is not valid\n"
	   "The prefix is not in cache and will be validated async\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:path-validation']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:path-validation", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[2]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_path_validation,
	   no_match_path_validation_cmd,
	   "no match path-validation <valid|invalid|pending>",
	   NO_STR
	   MATCH_STR
	   PATH_VALIDATION_STRING
	   "Valid prefix\n"
	   "Invalid prefix\n"
	   "The prefix is not in cache and will be validated async\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:path-validation']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}


static void install_cli_commands(void) {
	install_node(&path_validation_node);
	install_default(PATH_VALIDATION_NODE);
	install_element(CONFIG_NODE, &path_validation_cmd);
	install_element(ENABLE_NODE, &path_validation_cmd);

	/* Install retries command */
	install_element(PATH_VALIDATION_NODE, &path_validation_retries_cmd);
	install_element(PATH_VALIDATION_NODE, &no_path_validation_retries_cmd);

	/* Install timeout command */
	install_element(PATH_VALIDATION_NODE, &path_validation_timeout_cmd);
	install_element(PATH_VALIDATION_NODE, &no_path_validation_timeout_cmd);

	/* Install route match */
	route_map_install_match(&route_match_path_validation_cmd);
	install_element(RMAP_NODE, &match_path_validation_cmd);
	install_element(RMAP_NODE, &no_match_path_validation_cmd);
}