#include <unordered_map>
#include <cstring> // for memcmp 
#include "nmmintrin.h" // for sse4.2 hardware crc checksum
#include <map>
#include <iostream> // for std::endl

#include <sparsehash/dense_hash_map>


typedef struct ipv4_4t {
	uint32_t ext_ip;
	uint32_t int_ip;		
	uint16_t ext_port;
	uint16_t int_port;
		
		
	bool operator==(const ipv4_4t& rhs) const {
		return 
       	this->ext_ip == rhs.ext_ip &&
       	this->int_ip == rhs.int_ip &&
       	this->ext_port == rhs.ext_port &&
        this->int_port == rhs.int_port
        ;
    }
} ipv4_4t;

struct eq_ipv4_4t{
	bool operator()(const ipv4_4t& lhs, const ipv4_4t& rhs) const {
		return 
       	lhs.ext_ip == rhs.ext_ip &&
       	lhs.int_ip == rhs.int_ip &&
       	lhs.ext_port == rhs.ext_port &&
        lhs.int_port == rhs.int_port
        ;
	}
};

namespace std {
	template <> struct hash<ipv4_4t>{
   		inline size_t operator()(const ipv4_4t& ft) const {
			// fastest hash possible, but no perf increase
			uint32_t hash = 0;
			hash = _mm_crc32_u32(hash, ft.ext_ip);
			hash = _mm_crc32_u32(hash, ft.int_ip);
			hash = _mm_crc32_u16(hash, ft.int_port);
			hash = _mm_crc32_u16(hash, ft.ext_port);
			return hash;
		}
	};
}

typedef struct ipv4_tcppkt {
	struct ipv4_4t t4;
	uint64_t ts;
	uint8_t ttl;
	uint8_t flags;
} ipv4_tcppkt;

typedef struct dmap_cookie_value {
	uint32_t diff;
} dmap_cookie_value;

using dmap_cookie = google::dense_hash_map<ipv4_4t, dmap_cookie_value*, std::hash<ipv4_4t> , eq_ipv4_4t>;

extern "C" {
	/* Google HashMap Densehash */
	dmap_cookie* mg_dmap_cookie_create(){
		dmap_cookie* m = new dmap_cookie(113234544);
		struct ipv4_4t e;
		memset(&e, 0, sizeof(ipv4_4t));
		m->set_empty_key(e);
		return m;
	}

	void mg_dmap_cookie_insert(dmap_cookie *m, ipv4_tcppkt *p) {
         auto it = m->find(p->t4);
         if (it == m->end() ){ // fourtupel not in list yet, add flow
 			dmap_cookie_value *tmp = new dmap_cookie_value;
			tmp->diff = p->ttl;
			(*m)[p->t4] = tmp;
		} else {
		}	
		
    };
	dmap_cookie_value* mg_dmap_cookie_find(dmap_cookie *m, ipv4_tcppkt *p) {
		return (*m)[p->t4];
	};
}
