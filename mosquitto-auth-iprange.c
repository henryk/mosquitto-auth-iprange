#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <mosquitto.h>
#include <mosquitto_plugin.h>

#include "mosquitto-auth-iprange.h"

#define ACL_MASK_NONE 0
#define ACL_MASK_READ 0x04
#define ACL_MASK_WRITE 0x02
#define ACL_MASK_SUBSCRIBE 0x01
#define ACL_MASK_ALL (ACL_MASK_READ | ACL_MASK_WRITE | ACL_MASK_SUBSCRIBE)

struct acl_entry {
        uint8_t addr[16];
        size_t addr_len;
        unsigned int prefix_len;
        char *topic;
        struct acl_rule {
                uint8_t allow;
                uint8_t deny;
        } rule;
        struct acl_entry *next;
};

#define OPTION_WHITESPACE " \t"
#define ACL_RULE_IGNORE (struct acl_rule){ ACL_MASK_NONE, ACL_MASK_NONE }

struct acl_entry *acl_head = NULL;

#if MOSQ_AUTH_PLUGIN_VERSION < 3
#error "MOSQ_AUTH_PLUGIN_VERSION must be at least 3"
#endif

static void free_acl_entry(struct acl_entry *entry)
{
        free(entry->topic);
        free(entry);
}

static int parse_rule(const char *const rule, struct acl_rule *result)
{
        *result = (struct acl_rule) {
        ACL_MASK_NONE, ACL_MASK_NONE};
        if (strcmp(rule, "allow") == 0) {
                result->allow |= ACL_MASK_ALL;
                result->deny &= ~ACL_MASK_ALL;
        } else if (strcmp(rule, "deny") == 0) {
                result->deny |= ACL_MASK_ALL;
                result->allow &= ~ACL_MASK_ALL;
        } else if (strcmp(rule, "ignore") == 0) {
                result->deny &= ~ACL_MASK_ALL;
                result->allow &= ~ACL_MASK_ALL;
        } else {
                const char *c = rule;
                int mode = '+';
                while (*c) {
                        int mask = ACL_MASK_NONE;
                        switch (*c) {
                        case '-':
                        case '+':
                        case '~':
                                mode = *c;
                                break;
                        case 's':
                                mask = ACL_MASK_SUBSCRIBE;
                                break;
                        case 'r':
                                mask = ACL_MASK_READ;
                                break;
                        case 'w':
                                mask = ACL_MASK_WRITE;
                                break;
                        default:
                                return -1;
                        }

                        if (mode == '+') {
                                result->allow |= mask;
                                result->deny &= ~mask;
                        } else if (mode == '-') {
                                result->deny |= mask;
                                result->allow &= ~mask;
                        } else {
                                result->allow &= ~mask;
                                result->deny &= ~mask;
                        }

                        c++;
                }
        }

        return 0;
}

static bool match_ip_prefix(const struct acl_entry *entry,
                            struct sockaddr *sa)
{
        uint8_t *match_start = NULL;
        int match_dir = 0;
        if (entry->addr_len == 16) {
                if (sa->sa_family != AF_INET6) {
                        return false;
                }
                match_start =
                    (uint8_t *) (((struct sockaddr_in6 *) sa)->
                                 sin6_addr.s6_addr);
                match_dir = 1;
        } else if (entry->addr_len == 4) {
                if (sa->sa_family != AF_INET) {
                        return false;
                }
                match_start =
                    (uint8_t *) & (((struct sockaddr_in *) sa)->
                                   sin_addr.s_addr) + 4;
                match_dir = -1;
        } else {
                return false;
        }

        // Matching max 8 bits at once
        //  IPv4: Start at last byte
        //  IPv6: Start at first byte
        int match_left = entry->prefix_len;
        int match_pos = 0;

        while (match_left && match_pos < entry->addr_len) {
                int match_bits = match_left;
                if (match_bits > 8) {
                        match_bits = 8;
                }
                match_left -= match_bits;
                // mask keeps the highest match_bits bits
                uint8_t mask = ~(0xff >> match_bits);

                if ((entry->addr[match_dir * match_pos] & mask) !=
                    (match_start[match_dir * match_pos] & mask)) {
                        return false;
                }

                match_pos++;
        }

        // "No mismatch so far" means match
        return true;
}

static struct acl_rule evaluate_acl(const char *const ip,
                                    const char *const topic)
{
        struct acl_rule result = { ACL_MASK_NONE, ACL_MASK_NONE };
        struct addrinfo *addr = NULL;

        int gai_err;
        struct addrinfo hints = {
                .ai_socktype = SOCK_STREAM,
                .ai_protocol = 0,
                .ai_family = AF_UNSPEC,
                .ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
        };
        if ((gai_err = getaddrinfo(ip, NULL, &hints, &addr)) != 0) {
                mosquitto_log_printf(MOSQ_LOG_ERR,
                                     "iprange: evaluate_acl failure: %s",
                                     gai_strerror(gai_err));
                return ACL_RULE_IGNORE;
        }

        struct acl_entry *current = acl_head;
        while (current) {
                // Match IP address against getaddrinfo() results, skip if no match
                struct addrinfo *a = addr;
                bool matched_any = false;
                while (a) {
                        if (match_ip_prefix(current, a->ai_addr)) {
                                matched_any = true;
                                break;
                        }
                        a = a->ai_next;
                }

                if (!matched_any) {
                        goto next_loop;
                }
                // Match topic, skip if no match
                bool r;
                if (mosquitto_topic_matches_sub(current->topic, topic, &r)
                    != MOSQ_ERR_SUCCESS) {
                        mosquitto_log_printf(MOSQ_LOG_ERR,
                                             "iprange: evaluate_acl failure in mosquitto_topic_matches_sub");
                        freeaddrinfo(addr);
                        return ACL_RULE_IGNORE;
                }

                if (!r) {
                        goto next_loop;
                }
                // Apply rule
                result.allow |= current->rule.allow;
                result.deny |= current->rule.deny;
                result.allow &= ~current->rule.deny;
                result.deny &= ~current->rule.allow;

              next_loop:
                current = current->next;
        }

        freeaddrinfo(addr);
        return result;
}

static int add_acl_entry(char *optstr)
{
        /* parse optstr as   <allow|deny|[+|-][r][w][s]...> <ip>[/<prefix_length>] <topic>
         * and append (possibly multiple) struct acl_entry * to the end of the
         * list in acl_head
         */

        char *saveptr_opt = NULL;
        char *saveptr_len = NULL;
        const char *err_reason = NULL;
        struct addrinfo *addr = NULL;
        struct acl_entry *pending_entry = NULL;

        int retval = MOSQ_ERR_UNKNOWN;

        // Use strtok_r to tokenize by whitespace
        // Extract <allow/deny>
        char *mode = strtok_r(optstr, OPTION_WHITESPACE, &saveptr_opt);
        if (!mode) {
                err_reason = "no allow/deny found";
                goto abort;
        }

        struct acl_rule rule = { ACL_MASK_NONE, ACL_MASK_NONE };
        if (parse_rule(mode, &rule) < 0) {
                err_reason = "parse error in rule";
                goto abort;
        }
        // Extract <ip>[/<prefix_length>]
        char *ip_net = strtok_r(NULL, OPTION_WHITESPACE, &saveptr_opt);
        if (!ip_net) {
                err_reason = "no ip/net found";
                goto abort;
        }
        // Split off /<prefix_length> and parse to integer separately
        char *ip = strtok_r(ip_net, "/", &saveptr_len);
        char *prefix_str = strtok_r(NULL, "/", &saveptr_len);
        int prefix_len = -1;
        if (prefix_str) {
                prefix_len = atoi(prefix_str);
        }
        // Using getaddrinfo on <ip> allows to transparently handle
        // IPv4/IPv6, and even hostnames
        int gai_err;
        struct addrinfo hints = {
                .ai_socktype = SOCK_STREAM,     // Prevent multiple results for
                .ai_protocol = 0,       // the same hostname by restricting
                .ai_family = AF_UNSPEC, // to TCP
                .ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
        };
        if ((gai_err = getaddrinfo(ip, NULL, &hints, &addr)) != 0) {
                err_reason = gai_strerror(gai_err);
                goto abort;
        }
        // Extract topic
        char *topic = strtok_r(NULL, OPTION_WHITESPACE, &saveptr_opt);
        if (!topic) {
                err_reason = "no topic found";
                goto abort;
        }

        char addrstr[INET6_ADDRSTRLEN];
        struct addrinfo *addr_ptr = addr;

        // Generate struct acl_entry * objects, one per getaddrinfo() result
        // and append to list. Note: getaddrinfo() may return multiple
        // results for example for hostnames
        while (addr_ptr) {
                pending_entry = calloc(1, sizeof(*pending_entry));
                if (!pending_entry) {
                        err_reason = "malloc failure";
                        retval = MOSQ_ERR_NOMEM;
                        goto abort;
                }
                pending_entry->rule = rule;
                pending_entry->topic = strdup(topic);

                // Copy raw IP address bytes (in network byte order)
                if (addr_ptr->ai_family == AF_INET) {
                        pending_entry->addr_len = 4;
                        struct sockaddr_in *sin =
                            (struct sockaddr_in *) addr_ptr->ai_addr;
                        memcpy(pending_entry->addr,
                               ((char *) &sin->sin_addr.s_addr),
                               pending_entry->addr_len);
                } else if (addr_ptr->ai_family == AF_INET6) {
                        pending_entry->addr_len = 16;
                        struct sockaddr_in6 *sin =
                            (struct sockaddr_in6 *) addr_ptr->ai_addr;
                        memcpy(pending_entry->addr,
                               ((char *) sin->sin6_addr.s6_addr),
                               pending_entry->addr_len);
                } else {
                        mosquitto_log_printf(MOSQ_LOG_WARNING,
                                             "iprange: ignoring %s resolving to unknown address family",
                                             ip);
                        goto next_loop;
                }

                // Unspecified prefix length defaults to maximum length
                if (prefix_len == -1) {
                        pending_entry->prefix_len =
                            pending_entry->addr_len * 8;
                } else {
                        pending_entry->prefix_len = prefix_len;
                }

                // Clamp prefix length to [0, maximum length]
                if (pending_entry->prefix_len < 0) {
                        pending_entry->prefix_len = 0;
                }
                if (pending_entry->prefix_len >
                    pending_entry->addr_len * 8) {
                        pending_entry->prefix_len =
                            pending_entry->addr_len * 8;
                }
                // Render IP address back to ASCII for debugging
                inet_ntop(pending_entry->addr_len ==
                          4 ? AF_INET : AF_INET6, pending_entry->addr,
                          addrstr, sizeof(addrstr)
                    );

                mosquitto_log_printf(MOSQ_LOG_INFO,
                                     "iprange: adding ACL allow %X deny %X for %s/%i on %s",
                                     pending_entry->rule.allow,
                                     pending_entry->rule.deny, addrstr,
                                     pending_entry->prefix_len,
                                     pending_entry->topic);

                // Find end and append
                if (!acl_head) {
                        acl_head = pending_entry;
                        pending_entry = NULL;
                } else {
                        struct acl_entry *append_position = acl_head;
                        while (append_position->next) {
                                append_position = append_position->next;
                        }
                        append_position->next = pending_entry;
                        pending_entry = NULL;
                }

              next_loop:
                if (pending_entry) {
                        free_acl_entry(pending_entry);
                        pending_entry = NULL;
                }

                addr_ptr = addr_ptr->ai_next;
        }

        retval = MOSQ_ERR_SUCCESS;

      abort:
        if (addr) {
                freeaddrinfo(addr);
        }

        if (pending_entry) {
                free_acl_entry(pending_entry);
        }

        if (retval != MOSQ_ERR_SUCCESS) {
                mosquitto_log_printf(MOSQ_LOG_ERR,
                                     "iprange: parse error in '%s', %s",
                                     optstr, err_reason);
        }

        return retval;
}

int mosquitto_auth_plugin_version(void)
{
        return MOSQ_AUTH_PLUGIN_VERSION;
}

int mosquitto_auth_plugin_init(void **user_data,
                               struct mosquitto_opt *opts, int opt_count)
{
        return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_plugin_cleanup(void *user_data,
                                  struct mosquitto_opt *opts,
                                  int opt_count)
{
        return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_init(void *user_data,
                                 struct mosquitto_opt *opts, int opt_count,
                                 bool reload)
{
        mosquitto_log_printf(MOSQ_LOG_INFO,
                             "mosquitto-auth-iprange: starting up");
        for (int i = 0; i < opt_count; i++) {
                if (strcmp(opts[i].key, "iprange") == 0) {
                        add_acl_entry(opts[i].value);
                }
        }
        return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_security_cleanup(void *user_data,
                                    struct mosquitto_opt *opts,
                                    int opt_count, bool reload)
{
        mosquitto_log_printf(MOSQ_LOG_INFO,
                             "mosquitto-auth-iprange: shutting down");

        struct acl_entry *current = acl_head;
        acl_head = NULL;

        while (current) {
                struct acl_entry *tmp = current->next;
                free_acl_entry(current);
                current = tmp;
        }

        return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client,
                               const char *username, const char *password)
{
        const char *ip = mosquitto_client_address(client);
        mosquitto_log_printf(MOSQ_LOG_DEBUG,
                             "iprange: pwd check ip %s, user %s, password %s",
                             username, password, ip);
        return MOSQ_ERR_SUCCESS;
}

int mosquitto_auth_acl_check(void *user_data, int access,
                             struct mosquitto *client,
                             const struct mosquitto_acl_msg *msg)
{
        const char *ip = mosquitto_client_address(client);

        struct acl_rule rule = evaluate_acl(ip, msg->topic);


        const char *what;
        uint8_t mask;
        switch (access) {
        case MOSQ_ACL_SUBSCRIBE:
                what = "subscribe";
                mask = ACL_MASK_SUBSCRIBE;
                break;
        case MOSQ_ACL_READ:
                what = "read";
                mask = ACL_MASK_READ;
                break;
        case MOSQ_ACL_WRITE:
                what = "write";
                mask = ACL_MASK_WRITE;
                break;
        default:
                what = "unknown";
                mask = 0;
                break;
        }

        mosquitto_log_printf(MOSQ_LOG_DEBUG,
                             "iprange: acl check ip %s, %s %s, allow %X deny %X",
                             ip, what, msg->topic, rule.allow, rule.deny);

        if (rule.allow & mask) {
                return MOSQ_ERR_SUCCESS;
        } else if (rule.deny & mask) {
                return MOSQ_ERR_ACL_DENIED;
        } else {
                return MOSQ_ERR_PLUGIN_DEFER;
        }
}
