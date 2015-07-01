#ifndef MG_IPV4_H
#define MG_IPV4_H
#include <inttypes.h>

void mg_ipv4_check_valid(
    struct rte_mbuf **pkts,
    struct mg_bitmask * in_mask,
    struct mg_bitmask * out_mask
    );

#endif
