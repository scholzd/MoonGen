#include "ipv4.h"
#include <rte_mbuf.h>

void mg_ipv4_check_valid(
    struct rte_mbuf **pkts,
    struct mg_bitmask * in_mask,
    struct mg_bitmask * out_mask
    ){
  mg_bitmask_clear_all(out_mask);
  for(i=0; i< in_mask.size; i++){
    if(mg_bitmask_get_bit(in_mask, i)){
      uint16_t flags = pkts[i]->ol_flags;
      if(
          ((PKT_RX_IPV4_HDR | PKT_RX_IPV4_HDR_EXT) & flags == 0)
          &&
          (PKT_RX_IP_CKSUM_BAD & flags == 0)
          &&
          (pkts[i]->pkt.data_len >= 20)
        ){
        mg_bitmask_set_bit(out_mask, i);
      }else{
        printf("invalid ipv4\n")
      }
    }
  }
}
