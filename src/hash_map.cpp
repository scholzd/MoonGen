#include <unordered_map>
#include <cstring> // for memcmp 
#include "nmmintrin.h" // for sse4.2 hardware crc checksum
#include <map>
#include <iostream> // for std::endl

#include <sparsehash/sparse_hash_map>


typedef struct sparse_hash_map_cookie_key {
	uint32_t ip_src;
	uint32_t ip_dst;		
	uint16_t tcp_src;
	uint16_t tcp_dst;
		
		
	bool operator==(const sparse_hash_map_cookie_key& rhs) const {
		return 
       	this->ip_src == rhs.ip_src &&
       	this->ip_dst == rhs.ip_dst &&
       	this->tcp_src == rhs.tcp_src &&
        this->tcp_dst == rhs.tcp_dst
        ;
    }
} sparse_hash_map_cookie_key;

struct eq_sparse_hash_map_cookie_key{
	bool operator()(const sparse_hash_map_cookie_key& lhs, const sparse_hash_map_cookie_key& rhs) const {
		return 
       	lhs.ip_src == rhs.ip_src &&
       	lhs.ip_dst == rhs.ip_dst &&
       	lhs.tcp_src == rhs.tcp_src &&
        lhs.tcp_dst == rhs.tcp_dst
        ;
	}
};

namespace std {
	template <> struct hash<sparse_hash_map_cookie_key>{
   		inline size_t operator()(const sparse_hash_map_cookie_key& ft) const {
			// fastest hash possible, but no perf increase
			uint32_t hash = 0;
			hash = _mm_crc32_u32(hash, ft.ip_src);
			hash = _mm_crc32_u32(hash, ft.ip_dst);
			hash = _mm_crc32_u16(hash, ft.tcp_dst);
			hash = _mm_crc32_u16(hash, ft.tcp_src);
			return hash;
		}
	};
}

typedef struct sparse_hash_map_cookie_value {
	uint32_t diff;
	uint32_t last_ack;
	uint8_t flags;
} sparse_hash_map_cookie_value;

using sparse_hash_map_cookie = google::sparse_hash_map<sparse_hash_map_cookie_key, sparse_hash_map_cookie_value*, std::hash<sparse_hash_map_cookie_key> , eq_sparse_hash_map_cookie_key>;

extern "C" {
	/* Google HashMap Densehash */
	sparse_hash_map_cookie* mg_sparse_hash_map_cookie_create(){
		return new sparse_hash_map_cookie;
	}

	void mg_sparse_hash_map_cookie_insert(sparse_hash_map_cookie *m, sparse_hash_map_cookie_key *k, uint32_t v) {
		auto it = m->find(*k);
        if (it == m->end() ){ // fourtupel not in list yet, add flow
 			sparse_hash_map_cookie_value *tmp = new sparse_hash_map_cookie_value;
			tmp->diff = v;
			(*m)[*k] = tmp;
		} else {
			((*m)[*k])->diff = v;
		}	
		
    };
	sparse_hash_map_cookie_value* mg_sparse_hash_map_cookie_find(sparse_hash_map_cookie *m, sparse_hash_map_cookie_key *k) {
		return (*m)[*k];
	};
}
