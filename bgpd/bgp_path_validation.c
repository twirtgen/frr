//
// Created by thomas on 26/04/22.
//

#include "bgp_path_validation.h"

#include <assert.h>

#include <sys/socket.h>
#include <sys/eventfd.h>
#include <ifaddrs.h>

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
#include "bgpd/bgp_path_validation_ping.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_path_validation_clippy.c"
#endif

#define RETRIES_DEFAULT 3
#define TIMEOUT_DEFAULT_MS 300

#define PATH_VALIDATION_STRING "Validate path with TLS/PING server contained in large community\n"


#define print_prefix(file, pfx, fmt, ...) ({                              \
	char pfx_str[PREFIX2STR_BUFFER + 1];                              \
								          \
	memset(pfx_str, 0, sizeof(pfx_str));                              \
	prefix2str(pfx, pfx_str, sizeof(pfx_str) - 1);                    \
                                                                          \
	fprintf(file, "[Prefix %18s] " fmt, pfx_str, ##__VA_ARGS__);     \
})



enum validation_method {
	VALIDATION_METHOD_TLS,
	VALIDATION_METHOD_PING,
	VALIDATION_METHOD_MAX,
};

struct prefix_validation_status {
	enum path_validation_states status;
	struct prefix *p;
};

struct pval_arg {
	struct sockaddr_storage saddr;
	struct prefix_validation_status *pfx_v;
};

static struct frr_pthread *bgp_pth_pval = NULL;

static unsigned int retries_number;
static unsigned int timeout_ms;
static enum validation_method v_method;
static char out_iface[IF_NAMESIZE + 1];

static struct hash *validated_pfx = NULL;

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


static int set_port(struct sockaddr *saddr, uint16_t port) {
	struct sockaddr_in *saddr4;
	struct sockaddr_in6 *saddr6;

	switch (saddr->sa_family) {
	case AF_INET:
		saddr4 = (struct sockaddr_in *) saddr;
		saddr4->sin_port = htobe16(port);
		break;
	case AF_INET6:
		saddr6 = (struct sockaddr_in6 *) saddr;
		saddr6->sin6_port = htobe16(port);
		break;
	default:
		return -1;
	}

	return 0;
}


static int valid_path(struct sockaddr *saddr) {

	/* debug purpose */
	struct sockaddr_in sock_in;

	sock_in.sin_family = AF_INET;
	sock_in.sin_port = 0;
	// comp5 emulated delay addr
	inet_pton(AF_INET, "42.4.0.1", &sock_in.sin_addr);
	/* end debug purpose */

	switch (v_method) {
	case VALIDATION_METHOD_TLS:
		assert(0 && "TLS validation not yet supported !");
		break;
	case VALIDATION_METHOD_PING:
		return send_ping( &sock_in /*(struct sockaddr_in *)saddr*/, timeout_ms * 1000,
			  retries_number, out_iface) == 0;

		break;
	case VALIDATION_METHOD_MAX:
	default:
		return 0;
	}

	return 1;
}

static void *pfx_hash_alloc(void *arg) {
	const struct prefix_validation_status *pfx;
	struct prefix_validation_status *nprefix;
	pfx = arg;

	nprefix = XMALLOC(MTYPE_PREFIX_VALIDATION_STATUS, sizeof(*nprefix));
	nprefix->p = prefix_new();

	nprefix->status = pfx->status;
	*nprefix->p = *pfx->p;

	return nprefix;
}

static void validate_bgp_node(struct bgp_node *bgp_node, afi_t afi, safi_t safi) {
	struct bgp_adj_in *ain;
	const struct prefix *pfx;

	for (ain = bgp_node->adj_in; ain; ain = ain->next) {
		struct bgp_path_info *path =
			bgp_dest_get_bgp_path_info(bgp_node);
		mpls_label_t *label = NULL;
		uint32_t num_labels = 0;

		if (path && path->extra) {
			label = path->extra->label;
			num_labels = path->extra->num_labels;
		}
		pfx = bgp_dest_get_prefix(bgp_node);
		print_prefix(stderr, pfx, "BEGIN Triggering BGP UPDATE !\n");

		(void)bgp_update(ain->peer, bgp_dest_get_prefix(bgp_node),
				 ain->addpath_rx_id, ain->attr, afi, safi,
				 ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, label,
				 num_labels, 1, NULL);

		print_prefix(stderr, pfx, "END Triggering BGP UPDATE !\n");
	}
}

static void validate_prefix(const struct prefix *pfx) {
	afi_t afi;
	safi_t safi;
	struct listnode *node;
	struct bgp *bgp;
	struct bgp_node *match;
	struct bgp_node *match_node;

	afi = pfx->family == AF_INET ? AFI_IP : AFI_IP6;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp)) {
		for (safi=SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			if (!bgp->rib[afi][safi])
				continue;

			match = bgp_table_subtree_lookup(bgp->rib[afi][safi],
							 pfx);

			match_node = match;
			while (match_node) {
				if (bgp_dest_has_bgp_path_info_data(match_node)) {
					validate_bgp_node(match_node,
							  afi, safi);
				}
				match_node = bgp_route_next_until(match_node,
								  match);
			}
		}
	}
}


static int process_path_validation(struct thread *thread) {
	struct pval_arg *arg;
	char addr[45];
	uint16_t port;

	//struct prefix_validation_status pval;

	arg = THREAD_ARG(thread);

	if (arg->saddr.ss_family == AF_INET) {
		inet_ntop(AF_INET,
			  &((struct sockaddr_in *) &arg->saddr)->sin_addr,
			  addr, sizeof (addr));
	} else if (arg->saddr.ss_family == AF_INET6) {
		inet_ntop(AF_INET6,
			  &((struct sockaddr_in6 *) &arg->saddr)->sin6_addr,
			  addr, sizeof(addr));
		fprintf(stderr, "IPv6 not yet supported\n");
		goto end;
	} else {
		fprintf(stderr, "Unrecognized address family !\n");
		goto end;
	}
	print_prefix(stderr, arg->pfx_v->p, "Contacting %s server %s\n",
		v_method == VALIDATION_METHOD_PING ? "ping":
		v_method == VALIDATION_METHOD_TLS ? "tls" : "???",
		addr);
	/* todo refactor later (avoid magic numbers) */
	port = v_method == VALIDATION_METHOD_PING ? 0 :
	       v_method == VALIDATION_METHOD_TLS ? 443 : 0;

	if (set_port((struct sockaddr *)&arg->saddr, port) != 0) {
		fprintf(stderr, "Set port failed !");
	}

	if (valid_path((struct sockaddr *)&arg->saddr)) {
		/* the path is valid */
		print_prefix(stderr, arg->pfx_v->p, "Decision: VALID !\n");
		arg->pfx_v->status = PATH_VALIDATION_VALID;
	} else {
		print_prefix(stderr, arg->pfx_v->p, "Decision: INVALID!\n");
		arg->pfx_v->status = PATH_VALIDATION_INVALID;
	}

	validate_prefix(arg->pfx_v->p);

end:
	free(arg);
	return 0;
}

static int config_write(struct vty *vty) {

	vty_out(vty, "!\n");
	vty_out(vty, "path-validation\n");

	switch (v_method) {
	case VALIDATION_METHOD_TLS:
		vty_out(vty, " path-validation method tls\n");
		break;
	case VALIDATION_METHOD_PING:
		vty_out(vty, " path-validation method ping\n");
		break;
	case VALIDATION_METHOD_MAX:
	default:
		break;
	}

	if (*out_iface != 0) {
		vty_out(vty, " path-validation interface %s\n", out_iface);
	}

	if (retries_number != RETRIES_DEFAULT)
		vty_out(vty, " path-validation retries %u\n", retries_number);
	if (timeout_ms != TIMEOUT_DEFAULT_MS)
		vty_out(vty, " path-validation timeout %u\n", timeout_ms);

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


static bool pfx_hash_cmp(const void *a, const void *b) {
	const struct prefix_validation_status *p_a = a;
	const struct prefix_validation_status *p_b = b;
	return prefix_same(p_a->p, p_b->p);
}

static unsigned int pfx_hash_key_make(const void *a) {
	const struct prefix_validation_status *p_a = a;
	return prefix_hash_key(p_a->p);
}

int bgp_path_validation_init(struct thread_master *master) {
	retries_number = RETRIES_DEFAULT;
	timeout_ms = TIMEOUT_DEFAULT_MS;
	v_method = VALIDATION_METHOD_PING;
	memset(out_iface, 0, sizeof(out_iface));

	validated_pfx = hash_create(pfx_hash_key_make, pfx_hash_cmp,
				    "Validated Prefix");

	install_cli_commands();

	bgp_path_validation_thread_init();
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


static enum route_map_cmd_result_t
route_match(void *rule, const struct prefix *prefix, void *object)
{
	int *path_validation_status = rule;
	struct bgp_path_info *path;
	struct attr *bgp_attr;
	struct lcommunity *lcommunity;
	struct sockaddr_storage addr;
	struct pval_arg *arg;
	struct prefix_validation_status *hash_pfx;
	struct prefix_validation_status pfx_v;
	static unsigned long triggered_prefixes = 0;

	pfx_v.p = prefix;
	hash_pfx = hash_get(validated_pfx, &pfx_v, NULL);

	if (hash_pfx) { /* if prefix is in cache */
		if (hash_pfx->status != PATH_VALIDATION_PENDING) {
			print_prefix(stderr, prefix, "In cache! Validation status: %s\n",
				     hash_pfx->status == PATH_VALIDATION_VALID ? "VALID" :
				     hash_pfx->status == PATH_VALIDATION_INVALID ? "INVALID" :
				     hash_pfx->status == PATH_VALIDATION_PENDING ? "PENDING" :
				     hash_pfx->status == PATH_VALIDATION_NOT_REQUESTED ? "NOT REQUESTED":
				     hash_pfx->status == PATH_VALIDATION_UNKNOWN ? "UNKNOWN": "???? BUG..." );

		}
		if (*path_validation_status == PATH_VALIDATION_VALID) {
			return hash_pfx->status == PATH_VALIDATION_VALID
				       ? RMAP_MATCH
				       : RMAP_NOMATCH;
		} else if (*path_validation_status == PATH_VALIDATION_INVALID) {
			return hash_pfx->status == PATH_VALIDATION_INVALID
				       ? RMAP_MATCH
				       : RMAP_NOMATCH;
		} else {
			return RMAP_NOMATCH;
		}
	}
	/* the prefix is not in cache, trigger validation */
	path = object;
	bgp_attr = path->attr;

	/* no match if no large bgp communities */
	if (!(bgp_attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES))) {
		if (*path_validation_status == PATH_VALIDATION_NOT_REQUESTED)
			return RMAP_MATCH;
		return RMAP_NOMATCH;
	}


	/* check if we need to check the path */
	lcommunity = bgp_attr->lcommunity;
	if (!match_large_communities(lcommunity, (struct sockaddr *) &addr)) {
		if (*path_validation_status == PATH_VALIDATION_NOT_REQUESTED)
			return RMAP_MATCH;
		return RMAP_NOMATCH;
	}

	triggered_prefixes += 1;

	/* put the prefix in cache as "pending" */
	hash_pfx = hash_get(validated_pfx, &pfx_v, pfx_hash_alloc);
	assert(hash_pfx != &pfx_v);
	assert(prefix_same(prefix, hash_pfx->p));
	hash_pfx->status = PATH_VALIDATION_PENDING;

	arg = XMALLOC(MTYPE_PATH_VALIDATION_THREAD_ARG, sizeof(*arg));
	*arg = (struct pval_arg) {
		.pfx_v = hash_pfx,
		.saddr = addr,
	};

	/* there is a match, push the sockaddr to a queue for validation */
	thread_add_event(bgp_pth_pval->master,
			 process_path_validation, arg, 0, NULL);

	if (*path_validation_status == PATH_VALIDATION_UNKNOWN)
		return RMAP_MATCH;
	return RMAP_NOMATCH;
}


static void *route_match_compile(const char *arg)
{
	int *path_validation_status;

	path_validation_status = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(int));

	if (strcmp(arg, "valid") == 0)
		*path_validation_status = PATH_VALIDATION_VALID;
	else if (strcmp(arg, "invalid") == 0)
		*path_validation_status = PATH_VALIDATION_INVALID;
	else if (strcmp(arg, "unknown") == 0)
		*path_validation_status = PATH_VALIDATION_UNKNOWN;
	else
		*path_validation_status = PATH_VALIDATION_NOT_REQUESTED;

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

DEFPY (path_validation_method,
      path_validation_method_cmd,
      "path-validation method <tls|ping>$method",
      PATH_VALIDATION_STRING
      "Set path validation method\n"
      "Use TLS validation\n"
      "Use ICMP ping validation\n")
{
	if (strcmp("tls", method) == 0) {
		v_method = VALIDATION_METHOD_TLS;
	} else if (strcmp("ping", method) == 0) {
		v_method = VALIDATION_METHOD_PING;
	} else {
		v_method = VALIDATION_METHOD_MAX;
		return CMD_ERR_NO_MATCH;
	}
	return CMD_SUCCESS;
}


DEFUN (no_path_validation_method,
      no_path_validation_method_cmd,
      "no path-validation method",
      NO_STR
      PATH_VALIDATION_STRING
      "Unset path validation method. Default will be ping\n")
{
	v_method = VALIDATION_METHOD_PING;
	return CMD_SUCCESS;
}

static inline int check_iface(const char *name) {
	int ret;
	struct ifaddrs *addrs = NULL;
	struct ifaddrs *tmp;

	if (getifaddrs(&addrs) != 0) {
		return -1;
	}

	tmp = addrs;
	ret = -1;

	while (tmp) {
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
			if (strncmp(tmp->ifa_name, name, IF_NAMESIZE) == 0) {
				ret = 0;
				goto end;
			}
		}

		tmp = tmp->ifa_next;
	}

end:
	if (addrs) {
		freeifaddrs(addrs);
	}
	return ret; // interface not found
}


DEFPY (path_validation_iface,
      path_validation_iface_cmd,
      "path-validation interface WORD$interface",
      PATH_VALIDATION_STRING
      "Set path validation interface\n"
      "The name of the interface to send path validation messages\n")
{
	if (check_iface(interface) != 0) {
		vty_out(vty, "Interface %s not found !\n", interface);
		return CMD_WARNING_CONFIG_FAILED;
	}

	memset(out_iface, 0, sizeof(out_iface));
	strncpy(out_iface, interface, sizeof(out_iface) -1);
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
	   "match path-validation <valid|invalid|unknown|notrequested>",
	   MATCH_STR
	   PATH_VALIDATION_STRING
	   "Valid prefix, the TLS server responds\n"
	   "Invalid prefix, the TLS servers is not valid\n"
	   "Unknown prefix (path validation is pending and will be played)\n"
	   "Path Validation not requested for this prefix\n")
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
	   "no match path-validation <valid|invalid|unknown>",
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

	/* Install path validation method command */
	install_element(PATH_VALIDATION_NODE, &path_validation_method_cmd);
	install_element(PATH_VALIDATION_NODE, &no_path_validation_method_cmd);

	/* Install path validation interface command */
	install_element(PATH_VALIDATION_NODE, &path_validation_iface_cmd);

	/* Install route match */
	route_map_install_match(&route_match_path_validation_cmd);
	install_element(RMAP_NODE, &match_path_validation_cmd);
	install_element(RMAP_NODE, &no_match_path_validation_cmd);
}