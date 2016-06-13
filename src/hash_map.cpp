#include <unordered_map>
#include <cstring> // for memcmp 
#include "nmmintrin.h" // for sse4.2 hardware crc checksum
#include <map>
#include <iostream> // for std::endl
#include <string>
#include <sparsehash/sparse_hash_map>
#include <thread>
#include <unistd.h>

#define unlikely(x)     __builtin_expect(!!(x), 0)

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
	uint8_t flags;
	/* 
		#1: leftFIN			1
		#2: rightFIN		2
		#3: leftVerified	4
		#4: rightVerified	8
		#5: ts1				16
		#6: ts2				32
		#rest: reserved (0)
	*/
} sparse_hash_map_cookie_value;

using sparse_hash_map_cookie = google::sparse_hash_map<sparse_hash_map_cookie_key, sparse_hash_map_cookie_value*, std::hash<sparse_hash_map_cookie_key> , eq_sparse_hash_map_cookie_key>;
using namespace std;

extern "C" {
	/* Google HashMap Sparsehash */
	void mg_sparse_hash_map_cookie_gc(sparse_hash_map_cookie *m) {
   	 	while(true) {
			for(auto it = m->begin(); it != m->end(); it++) {
				auto tmp = it->second;
				if ((tmp->flags & 32) == 32) {
					tmp->flags = tmp->flags ^ 32;
					continue;
				}
				if ((tmp->flags & 16) == 16) {
					tmp->flags = tmp->flags ^ 16;
					continue;
				}
				m->erase(it->first);			
			}
			sleep(30);
   	 	}
	}

	sparse_hash_map_cookie* mg_sparse_hash_map_cookie_create(uint32_t size){
		sparse_hash_map_cookie *tmp = new sparse_hash_map_cookie(size);
		sparse_hash_map_cookie_key k;
		memset(&k, 0, sizeof(sparse_hash_map_cookie_key));
		tmp->set_deleted_key(k);

		// start gc thread
		thread gc(mg_sparse_hash_map_cookie_gc, tmp);
		gc.detach();

		return tmp;
	}



	/* Insert on setLeftVerified
	 * Stores the Ack Number for later calculation of the diff in the diff field
	 * Sets the leftVerified flag
	 * If entry already present:
	 *  connection is already left verified, 
	 *  hence, this packet and the syn we send next is duplicated
	 *  option A: drop it
	 *  		disadvantage: original syn might have gotten lost (server busy, ...)
	 *  option B (chosen): send again
	 *  		we assume the Ack number has not changed (which it obviously shouldn't)
	 * 		if it has changed, something is wrong
	 * 		hence, we assume the first Ack number to be the correct one and don't update it here
	 */
	void mg_sparse_hash_map_cookie_insert(sparse_hash_map_cookie *m, sparse_hash_map_cookie_key *k, uint32_t ack) {
		auto it = m->find(*k);
		// not existing yet
        if (it == m->end() ){
 			sparse_hash_map_cookie_value *tmp = new sparse_hash_map_cookie_value;
			tmp->diff = ack;
			tmp->flags = 52; // set leftVerified flag 4 + ts flags 16 32
			(*m)[*k] = tmp;
			//printf("Entry: %d %d\n", tmp->diff, tmp->flags);
			return;
		}
		//printf("NOT inserted\n");
    };

	/* Finalize an entry on setRightVerified
	 * Find the entry and check that flags are correct (only leftVerified set)
	 * Calculate and store diff from seq number and stored ack number
	 * Set rightVerified flag
	 */
	bool mg_sparse_hash_map_cookie_finalize(sparse_hash_map_cookie *m, sparse_hash_map_cookie_key *k, uint32_t seq) {
		auto it = m->find(*k);
		if (it == m->end() ) {
			return false;
		}

 		sparse_hash_map_cookie_value *tmp = (*m)[*k];
		
		// Check that flags are correct
		// Only leftVerified must be set
		if ( unlikely((tmp->flags & 4) != 4) ) {
			return false;
		}
		
		tmp->diff = seq - tmp->diff + 1;
		tmp->flags = tmp->flags | 56; // set rightVerified flag 8 + ts flags 16 32
		//printf("Entry: %d %d\n", tmp->diff, tmp->flags);
		return true;
	};

	/* Find and update on isVerified
	 * If it is verified, update the timestamp bits
	 * Return the value struct
	 */	
	sparse_hash_map_cookie_value* mg_sparse_hash_map_cookie_find_update(sparse_hash_map_cookie *m, sparse_hash_map_cookie_key *k) {
		auto it = m->find(*k);
		if (it == m->end() ) {
			return 0;
		}
		
		sparse_hash_map_cookie_value *tmp = (*m)[*k];
		
		// Check verified flags (both 4 8 must be set)
		// TODO maybe even drop this, not necessary really
		if ((tmp->flags & 12) != 12) {
			return 0;
		}

		tmp->flags = tmp->flags | 48; // update ts flags 16 32
		return tmp;
	};
	
	void mg_sparse_hash_map_cookie_delete(sparse_hash_map_cookie *m, sparse_hash_map_cookie_key *k) {
		m->erase(*k);
	}
	
	string mg_sparse_hash_map_cookie_string(sparse_hash_map_cookie *m) {
		string str = "NYI";
		return str;
	}
}
