#include <unordered_map>
#include <cstring> // for memcmp 
#include "nmmintrin.h" // for sse4.2 hardware crc checksum
#include <map>
#include <iostream> // for std::endl
#include <string>
#include <sparsehash/sparse_hash_map>
#include <time.h>

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
		#1: unused
		#2: unused
		#3: leftVerified	4
		#4: rightVerified	8
		#5: unused
		#6: unused
		#rest: reserved (0)
	*/
} sparse_hash_map_cookie_value;

using sparse_hash_map_cookie = google::sparse_hash_map<sparse_hash_map_cookie_key, sparse_hash_map_cookie_value*, std::hash<sparse_hash_map_cookie_key> , eq_sparse_hash_map_cookie_key>;
using namespace std;

typedef struct sparse_hash_maps_cookie {
	sparse_hash_map_cookie *current;
	sparse_hash_map_cookie *old;
	clock_t last_swap;
} sparse_hash_maps_cookie;

extern "C" {
	/* Google HashMap Sparsehash */
	double SWAP_INTERVAL = 30;	
	void mg_sparse_hash_map_cookie_swap(sparse_hash_maps_cookie *maps) {
		clock_t time = clock();
		if ( ((double) time - maps->last_swap) > ((double) SWAP_INTERVAL * CLOCKS_PER_SEC) ) {
			printf("swapping\n");
			delete maps->old;
			maps->old = maps->current;
			maps->current = new sparse_hash_map_cookie(0);
			maps->last_swap = time;
		}
	}

	sparse_hash_maps_cookie* mg_sparse_hash_map_cookie_create(uint32_t size){
		sparse_hash_maps_cookie *maps = new sparse_hash_maps_cookie;	

		sparse_hash_map_cookie *tmp = new sparse_hash_map_cookie(size);
		sparse_hash_map_cookie_key k;
		memset(&k, 0, sizeof(sparse_hash_map_cookie_key));
		tmp->set_deleted_key(k);

		maps->current = tmp;
		
		tmp = new sparse_hash_map_cookie(size);
		memset(&k, 0, sizeof(sparse_hash_map_cookie_key));
		tmp->set_deleted_key(k);

		maps->old = tmp;

		maps->last_swap = clock();

		return maps;
	}

	/* Insert on setLeftVerified
	 * Always insert into current
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
	void mg_sparse_hash_map_cookie_insert(sparse_hash_maps_cookie *maps, sparse_hash_map_cookie_key *k, uint32_t ack) {
		auto m = maps->current;
		auto it = m->find(*k);
		// not existing yet
        if (it == m->end() ){
 			sparse_hash_map_cookie_value *tmp = new sparse_hash_map_cookie_value;
			tmp->diff = ack;
			tmp->flags = 4; // set leftVerified flag 4
			(*m)[*k] = tmp;
			//printf("Entry: %d %d\n", tmp->diff, tmp->flags);
			mg_sparse_hash_map_cookie_swap(maps);
			return;
		}
		//printf("NOT inserted\n");
		mg_sparse_hash_map_cookie_swap(maps);
    };

	/* Finalize an entry on setRightVerified
	 * Find the entry and check that flags are correct (only leftVerified set)
	 * Calculate and store diff from seq number and stored ack number
	 * Set rightVerified flag
	 */
	bool mg_sparse_hash_map_cookie_finalize(sparse_hash_maps_cookie *maps, sparse_hash_map_cookie_key *k, uint32_t seq) {
		auto m = maps->current;
		auto it = m->find(*k);
		if (it == m->end() ) {
			//printf("fin not found in current, checking old\n");
			m = maps->old;
			it = m->find(*k);
			if (it == m->end() ) {
				//printf("fin also not found here\n");
				mg_sparse_hash_map_cookie_swap(maps);
				return false;
			}
			// copy and proceed normally
			printf("right found-> copy\n");
			(*(maps->current))[*k] = (*m)[*k];
		}

 		sparse_hash_map_cookie_value *tmp = (*m)[*k];
		
		// Check that flags are correct
		// Only leftVerified must be set
		// TODO can we do this without flags..., reduces complexity to single uint32_t
		if ( unlikely((tmp->flags & 4) != 4) ) {
			mg_sparse_hash_map_cookie_swap(maps);
			return false;
		}
		
		tmp->diff = seq - tmp->diff + 1;
		tmp->flags = tmp->flags | 8; // set rightVerified flag 8
		//printf("Entry: %d %d\n", tmp->diff, tmp->flags);
		
		mg_sparse_hash_map_cookie_swap(maps);
		return true;
	};

	/* Find and update on isVerified
	 * If it is verified, update the timestamp bits
	 * Return the value struct
	 */	
	sparse_hash_map_cookie_value* mg_sparse_hash_map_cookie_find_update(sparse_hash_maps_cookie *maps, sparse_hash_map_cookie_key *k) {
		auto m = maps->current;
		auto it = m->find(*k);
		if (it == m->end() ) {
			//printf("upd not found in current, checking old\n");
			m = maps->old;
			it = m->find(*k);
			if (it == m->end() ) {
				//printf("upd also not found here\n");
				mg_sparse_hash_map_cookie_swap(maps);
				return 0;
			}
			// copy and proceed normally
			printf("find found-> copy\n");
			(*(maps->current))[*k] = (*m)[*k];
		}
		
		sparse_hash_map_cookie_value *tmp = (*m)[*k];
		
		// Check verified flags (both 4 8 must be set)
		// TODO maybe even drop this, not necessary really
		if ((tmp->flags & 12) != 12) {
			mg_sparse_hash_map_cookie_swap(maps);
			return 0;
		}

		mg_sparse_hash_map_cookie_swap(maps);
		return tmp;
	};
	
	string mg_sparse_hash_map_cookie_string(sparse_hash_map_cookie *m) {
		string str = "NYI";
		return str;
	}
}
