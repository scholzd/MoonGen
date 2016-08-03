#include "siphash.c"
#include <stdlib.h>
#include <stdint.h>

struct sipkey * mg_siphash_cookie_init() {
	struct sipkey *key = malloc(sizeof(struct sipkey));
	key = sip_keyof("518dee47394431d4");
	//printf("key  %p %d %d\n", key, key->k[0], key->k[1]);
	return key;
}

uint32_t mg_siphash_cookie_hash(uint32_t ip_src, uint32_t ip_dst, uint16_t tcp_src, uint16_t tcp_dst, uint32_t ts) {
	struct sipkey *key2 = sip_keyof("518dee47394431d4");
	//printf("key  %p %d %d\n", key, key->k[0], key->k[1]);
	//printf("key2 %p %d %d\n", key2, key2->k[0], key2->k[1]);
	//printf("%d %d %d %d\n", ip_src, ip_dst, tcp_src, tcp_dst);
	struct siphash state;

	sip24_init(&state, key2);

	sip24_update(&state, sip_binof(ip_src), 4);
	sip24_update(&state, sip_binof(ip_dst), 4);
	sip24_update(&state, sip_binof(tcp_src), 2);
	sip24_update(&state, sip_binof(tcp_dst), 2);
	sip24_update(&state, sip_binof(ts), 4);

	uint32_t result = (uint32_t) sip24_final(&state);
	result &= 0x000fffff; // 20 bits
	return result;
}
