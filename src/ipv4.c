#include "ipv4.h"
#include "bitmask.h"
#include <rte_config.h>
#include <rte_common.h>
#include <rte_mbuf.h>

void mg_ipv4_check_valid2(
    struct rte_mbuf **pkts,
    struct mg_bitmask * in_mask,
    struct mg_bitmask * out_mask
    ){
  //printf("start check valid\n");
  mg_bitmask_clear_all(out_mask);
  uint16_t i = 0;
  uint64_t iterator_mask;
  uint16_t i_o = 0;
  uint64_t * iterator_mask_2;
  //printf("loop\n");
  while(i<in_mask->size){
    //printf("i=%u\n", i);
    uint8_t value = 0;
    if(mg_bitmask_iterate_get(in_mask, &i, &iterator_mask)){
      //printf("have to process\n");
      uint16_t flags = pkts[i-1]->ol_flags;
      if(
          (((PKT_RX_IPV4_HDR | PKT_RX_IPV4_HDR_EXT) & flags) != 0)
          &&
          ((PKT_RX_IP_CKSUM_BAD & flags) == 0)
          &&
          (pkts[i-1]->pkt.data_len >= 20)
        ){
        //printf("is valid\n");
        value = 1;
      }
    }
    //printf("set: %u\n", value);
    //printf("i=%u\n", i);
    mg_bitmask_iterate_set(out_mask, &i_o, &iterator_mask_2, value);
  }
  //printf("done check valid\n");
}

void mg_ipv4_check_valid(
    struct rte_mbuf **pkts,
    struct mg_bitmask * in_mask,
    struct mg_bitmask * out_mask
    ){
  mg_bitmask_clear_all(out_mask);
  uint16_t i;
  for(i=0; i< in_mask->size; i++){
    if(mg_bitmask_get_bit(in_mask, i)){
      uint16_t flags = pkts[i]->ol_flags;
      if(
          (((PKT_RX_IPV4_HDR | PKT_RX_IPV4_HDR_EXT) & flags) != 0)
          &&
          ((PKT_RX_IP_CKSUM_BAD & flags) == 0)
          &&
          (pkts[i]->pkt.data_len >= 20)
        ){
        mg_bitmask_set_bit(out_mask, i);
      }
    }
  }
}
