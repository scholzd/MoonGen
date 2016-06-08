#include <unordered_map>
#include <cstring> // for memcmp 
#include "nmmintrin.h" // for sse4.2 hardware crc checksum
#include <map>
#include <vector>
#include <iostream> // for std::endl

#include <sparsehash/dense_hash_map>

typedef struct ipv4_5t {
	uint32_t ext_ip;
	uint32_t int_ip;		
	uint16_t ext_port;
	uint16_t int_port;
	uint8_t proto;
		
		
	bool operator==(const ipv4_5t& rhs) const {
		return 
       	this->ext_ip == rhs.ext_ip &&
       	this->int_ip == rhs.int_ip &&
       	this->ext_port == rhs.ext_port &&
        this->int_port == rhs.int_port &&
        this->proto == rhs.proto
        ;
    }
} ipv4_5t;

struct eq_ipv4_5t{
	bool operator()(const ipv4_5t& lhs, const ipv4_5t& rhs) const {
		return 
       	lhs.ext_ip == rhs.ext_ip &&
       	lhs.int_ip == rhs.int_ip &&
       	lhs.ext_port == rhs.ext_port &&
        lhs.int_port == rhs.int_port &&
        lhs.proto == rhs.proto
        ;
	}
};

namespace std {
	template <> struct hash<ipv4_5t>{
   		inline size_t operator()(const ipv4_5t& ft) const {
			// fastest hash possible, but no perf increase
			uint32_t hash = 0;
			hash = _mm_crc32_u32(hash, ft.ext_ip);
			hash = _mm_crc32_u32(hash, ft.int_ip);
			hash = _mm_crc32_u16(hash, ft.int_port);
			hash = _mm_crc32_u16(hash, ft.ext_port);
			hash = _mm_crc32_u8(hash, ft.proto);
			return hash;
		}
	};
}

size_t hash_ipv4_5t(const ipv4_5t& ft) {
	uint32_t hash = 0;
	hash = _mm_crc32_u32(hash, ft.ext_ip);
	hash = _mm_crc32_u32(hash, ft.int_ip);
	hash = _mm_crc32_u16(hash, ft.int_port);
	hash = _mm_crc32_u16(hash, ft.ext_port);
	hash = _mm_crc32_u8(hash, ft.proto);
	return (size_t) hash;
}

typedef struct ipv4_tcppkt {
	struct ipv4_5t t5;
	uint64_t ts;
	uint8_t ttl;
	uint8_t flags;
} ipv4_tcppkt;



using ttlmap = std::map<uint8_t,std::vector<uint64_t>>;
	

using dmap_cookie = google::dense_hash_map<ipv4_5t, ttlmap*, std::hash<ipv4_5t> , eq_ipv4_5t>;

extern "C" {
	/* Google HashMap Densehash */
	dmap_cookie* mg_dmap_cookie_create(){
		dmap_cookie* m = new dmap_cookie(113234544);
		struct ipv4_5t e;
		memset(&e, 0, sizeof(ipv4_5t));
		m->set_empty_key(e);
		return m;
	}

	void mg_dmap_cookie_insert(dmap_cookie *m, ipv4_tcppkt *p) {
         auto it = m->find(p->t5);
         if (it == m->end() ){ // fourtupel not in list yet, add flow
 			(*m)[p->t5] = new ttlmap;
			auto v = (*(*m)[p->t5])[p->ttl];
			v.reserve(16);
			v.emplace_back((uint64_t)((p->ts & 0xffffffffffffff ) | ((uint64_t)p->flags)<<56));
		} else {
			auto v = (*(*m)[p->t5])[p->ttl];
			v.emplace_back((uint64_t)((p->ts & 0xffffffffffffff ) | ((uint64_t)p->flags)<<56));
		}	
		
    };
	ttlmap* mg_dmap_cookie_find(dmap_cookie *m, ipv4_tcppkt *p) {
		return (*m)[p->t5];
	};
}
