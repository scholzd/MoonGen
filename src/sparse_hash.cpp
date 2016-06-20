#include <iostream>
#include <sparsehash/sparse_hash_map>
#include <functional>
#include <unordered_map>

using google::sparse_hash_map;      // namespace where class lives by default
using std::cout;
using std::endl;
using std::hash;



struct eqstr {
	bool operator()(const char* s1, const char* s2) const {
		return (s1 == s2) || (s1 && s2 && strcmp(s1, s2) == 0);
	}
};

using hash_map_type = sparse_hash_map<const char*, int, hash<const char*>, eqstr>;

extern "C" {
	hash_map_type* mg_create_sparse_hash_map() {
		printf("C get sparse hash");
		auto map = new hash_map_type();
		(*map)["test"] = 42;
		cout << "test -> " << (*map)["test"] << endl;
		
		return map; 
	}
	
	void mg_free_sparse_hash_map(hash_map_type* map) {
		free(map);
	}
	
	void mg_set_sparse_hash_map(hash_map_type* map, const char* k, int v) {
		(*map)[k] = v;
	}
	
	int mg_get_sparse_hash_map(hash_map_type* map, const char* k) {
		return (*map)[k];
	}
	
	void mg_erase_sparse_hash_map(hash_map_type* map, const char* k) {
		(*map).set_deleted_key(k);
		(*map).erase(k);
	}
}
