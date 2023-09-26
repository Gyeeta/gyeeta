//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		"gy_stack_container.h"
#include		"gy_folly_stack_map.h"
#include		"gy_malloc_hook.h"

#include		<iostream>
#include 		<malloc.h>


using namespace gyeeta;

template <typename T>
void memuse(const char *prefix_str, const T & arena)
{
	GY_MALLOC_HOOK::gy_print_memuse(prefix_str, true);
	INFOPRINTCOLOR(GY_COLOR_YELLOW, "%s : Arena Stats : %s\n\n", prefix_str, arena.print_stats(STRING_BUFFER<256>().get_str_buf()));
}

void memuse(const char *prefix_str)
{
	GY_MALLOC_HOOK::gy_print_memuse(prefix_str, true);
}


int main()
{
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Starting Tests...\n");

	GY_MALLOC_HOOK::gy_malloc_init("Starting tests", true);

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing Inline Hash Map...\n");

		using Stackmap 		= INLINE_STACK_HASH_MAP<std::string, std::string, (sizeof(std::string) * 2 + 8) * 4096>;

		Stackmap		u(4096 /* initial bucket count */);
		auto			& arena = u.get_arena();

		memuse("After constructor", arena);

		u["RED"] 	= "#FF0000";
		u["GREEN"] 	= "#00FF00";
		u["BLUE"]	= "#0000FF";


		// Iterate and print keys and values of unordered_map
		for ( const auto & n : u ) {
			std::cout << "\tKey:[" << n.first << "] Value:[" << n.second << "]\n";
		}

		memuse("After 3 assigns", arena);

		u.clear();

		memuse("After map::clear", arena);

		u["RED"] 	= "#FF0000";
		u["GREEN"] 	= "#00FF00";
		u["BLUE"]	= "#0000FF";

		memuse("After second 3 assigns", arena);

		u["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

		memuse("After non SSO string", arena);

		u["BLACK"] 	= "#000000";
		u["WHITE"] 	= "#FFFFFF";
		u["NULL"] 	= "#0";

		// Output values by key
		std::cout << "The HEX of color RED is:[" << u["RED"] << "]\n";
		std::cout << "The HEX of color BLACK is:[" << u["BLACK"] << "]\n";

		for ( const auto & n : u ) {
			std::cout << "\tKey:[" << n.first << "] Value:[" << n.second << "]\n";
		}
		std::cout << '\n';

		memuse("Before copy", arena);

		Stackmap		u2(u);

		memuse("After copy and before destruction", arena);

		memuse("Copied Map stats", u2.get_arena());
	}
	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Testing External Arena Hash Map...\n");

		using Stackmap 		= GY_STACK_HASH_MAP<std::string, std::string, (sizeof(std::string) * 2 + 8) * 4096>;
		using Arena		= Stackmap::allocator_type::arena_type;

		Arena			arena;
		Stackmap		u(arena), u2(arena);

		memuse("After constructor", arena);

		u.reserve(4096);

		memuse("After reserve of 4096", arena);

		u["RED"] 	= "#FF0000";
		u["GREEN"] 	= "#00FF00";
		u["BLUE"]	= "#0000FF";


		// Iterate and print keys and values of unordered_map
		for ( const auto & n : u ) {
			std::cout << "\tKey:[" << n.first << "] Value:[" << n.second << "]\n";
		}

		memuse("After 3 assigns", arena);

		/*u.clear();*/
		reinit_with_arena_reset(u, 4096);

		memuse("After map::clear", arena);

		u["RED"] 	= "#FF0000";
		u["GREEN"] 	= "#00FF00";
		u["BLUE"]	= "#0000FF";

		memuse("After second 3 assigns", arena);

		u["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

		memuse("After non SSO string", arena);

		u["BLACK"] 	= "#000000";
		u["WHITE"] 	= "#FFFFFF";
		u["NULL"] 	= "#0";

		// Output values by key
		std::cout << "The HEX of color RED is:[" << u["RED"] << "]\n";
		std::cout << "The HEX of color BLACK is:[" << u["BLACK"] << "]\n";

		for ( const auto & n : u ) {
			std::cout << "\tKey:[" << n.first << "] Value:[" << n.second << "]\n";
		}

		std::cout << "\n\nNow copying map...\n";

		u2 = u;

		for ( const auto & n : u2 ) {
			std::cout << "\tKey:[" << n.first << "] Value:[" << n.second << "]\n";
		}
		std::cout << '\n';

		memuse("Before destruction", arena);
	}

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Stack Hash Set...\n");

		using Stackset 		= INLINE_STACK_HASH_SET<std::string, 4096>;

		Stackset			u;
		auto			 & 	arena = u.get_arena();

		memuse("After construction", arena);

		u.reserve(16);

		memuse("After reserve", arena);

		u.emplace("RED");
		u.emplace("GREEN");
		u.emplace("BLUE");

		u.emplace("RED");	// Will be rejected

		// Iterate and print keys and values of unordered_map
		for ( const auto & n : u ) {
			std::cout << "\t[" << n << "]\n";
		}

		memuse("After assigns", arena);

		u.clear();
		memuse("After clear", arena);

		u.emplace("RED");
		u.emplace("GREEN");
		u.emplace("BLUE");

		u.emplace("RED");	// Will be rejected

		u.emplace("BLACK");
		u.emplace("WHITE");

		for ( const auto & n : u ) {
			std::cout << "\t[" << n << "]\n";
		}
		std::cout << '\n';
		memuse("Before destruction", arena);
	}

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Stack Ordered Set...\n");

		using Stackset 		= INLINE_STACK_SET<int, 1024>;

		Stackset			u;
		auto			 & 	arena = u.get_arena();

		memuse("After construction", arena);

		u.emplace(10);
		u.emplace(20);
		u.emplace(-1);
		u.emplace(24);

		u.emplace(-1);	// Will be rejected

		// Iterate and print 
		for ( const auto & n : u ) {
			std::cout << "\t[" << n << "]\n";
		}

		memuse("After assigns", arena);

		u.clear();
		memuse("After clear", arena);

		for (int i = 9; i >= 0; --i) {
			u.emplace(i);
		}	

		for ( const auto & n : u ) {
			std::cout << "\t[" << n << "]\n";
		}
		std::cout << '\n';

		memuse("Before destruction", arena);
	}

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Stack Hash Map Memory usage ...\n");

		using Stackmap 		= INLINE_STACK_HASH_MAP<__int128_t, __int128_t, 1024 * 2 * sizeof(__int128_t) + 1024 * 3 * sizeof(uint64_t) + 512, GY_JHASHER<__int128_t>>;

		Stackmap			u(1024);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 1024 reserves", arena);

		for (uint64_t i = 0; i < 1024; ++i) {
			u.try_emplace(i, i);
		}	

		memuse("After 1024 emplaces", arena);

		u.clear();
		memuse("After clear", arena);

		u.reserve(1024);

		for (uint64_t i = 0; i < 1024; ++i) {
			u.try_emplace(i, i);
		}	

		memuse("After second 1024 emplaces and before destruction", arena);
	}

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Folly Stack Hash Map Memory usage ...\n");

		using Stackmap 		= INLINE_STACK_F14_MAP<__int128_t, __int128_t, 1024 * 2 * sizeof(__int128_t) + 1024 * 3 * sizeof(uint64_t) + 512, GY_JHASHER<__int128_t>>;

		Stackmap			u(1024);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 1024 reserves", arena);

		for (uint64_t i = 0; i < 1024; ++i) {
			u.try_emplace(i, i);
		}	

		memuse("After 1024 emplaces", arena);

		u.clear();
		memuse("After clear", arena);

		u.reserve(1024);

		for (uint64_t i = 0; i < 1024; ++i) {
			u.try_emplace(i, i);
		}	

		memuse("After second 1024 emplaces and before destruction", arena);
	}
	
	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Stack Hash Map with large Key and Value Memory usage ...\n");

		using Stackmap 		= INLINE_STACK_HASH_MAP<CHAR_BUF<64>, CHAR_BUF<128>, 100 * 1024, CHAR_BUF<64>::CHAR_BUF_HASH>;

		Stackmap			u(100);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 100 reserves", arena);

		for (uint64_t i = 0; i < 300; ++i) {
			u.try_emplace(gy_to_charbuf<64>("Key %lu", i), gy_to_charbuf<128>("Value %lu", i));
		}	

		memuse("After 300 emplaces", arena);

		u.clear();
		memuse("After clear", arena);

		u.reserve(300);

		for (uint64_t i = 0; i < 300; ++i) {
			u.try_emplace(gy_to_charbuf<64>("Key %lu", i), gy_to_charbuf<128>("Value %lu", i));
		}	

		memuse("After second 300 emplaces and before destruction", arena);
	}

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Folly Stack Hash Map with large Key and Value Memory usage ...\n");

		using Stackmap 		= INLINE_STACK_F14_MAP<CHAR_BUF<64>, CHAR_BUF<128>, 100 * 1024, CHAR_BUF<64>::CHAR_BUF_HASH>;

		Stackmap			u(100);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 100 reserves", arena);

		for (uint64_t i = 0; i < 300; ++i) {
			u.try_emplace(gy_to_charbuf<64>("Key %lu", i), gy_to_charbuf<128>("Value %lu", i));
		}	

		memuse("After 300 emplaces", arena);

		u.clear();
		memuse("After clear", arena);

		u.reserve(300);

		for (uint64_t i = 0; i < 300; ++i) {
			u.try_emplace(gy_to_charbuf<64>("Key %lu", i), gy_to_charbuf<128>("Value %lu", i));
		}	

		memuse("After second 300 emplaces and before destruction", arena);

	}

	{
		using folly::StringPiece;

		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Folly Stack Hash Map with Transparent Hashing to avoid temp std::string objects with Memory usage ...\n");

		using Stackmap 		= INLINE_STACK_F14_MAP<std::string, std::string, 100 * 1024, FollyTransparentStringHash, FollyTransparentStringEqual>;

		Stackmap			u(100);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 100 reserves", arena);

		for (uint64_t i = 0; i < 300; ++i) {
			u.try_emplace(gy_to_charbuf<64>("Key %lu", i).get(), gy_to_charbuf<128>("Value %lu", i).get());
		}	

		memuse("After 300 emplaces", arena);

		for (uint64_t i = 0; i < 300; ++i) {
			assert(u.find(StringPiece(gy_to_charbuf<64>("Key %lu", i).get())) != u.end());
		}	

		assert(u.find(StringPiece("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 88)) == u.end());

		memuse("After 300 finds", arena);

		u.clear();

		memuse("After clear", arena);

		u.reserve(300);

		for (uint64_t i = 0; i < 300; ++i) {
			u.try_emplace(gy_to_charbuf<64>("Key %lu", i).get(), gy_to_charbuf<128>("Value %lu", i).get());
		}	

		memuse("After second 300 emplaces and before destruction", arena);

	}

	{
		using folly::StringPiece;

		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Folly Stack Hash Map with Transparent Hashing and pointer objects to avoid temp std::string objects with Memory usage ...\n");

		using Stackmap 		= INLINE_STACK_F14_MAP<const char *, std::string, 8 * 1024, FollyTransparentStringHash, FollyTransparentStringEqual>;

		CHAR_BUF<64>			carr[30];
		Stackmap			u(100);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 100 reserves", arena);

		for (uint64_t i = 0; i < 30; ++i) {
			snprintf(carr[i].get(), sizeof(carr[i]), "Key %lu", i);
		}	

		for (uint64_t i = 0; i < 30; ++i) {
			u.try_emplace(carr[i].get(), gy_to_charbuf<128>("Value %lu", i).get());
		}	

		memuse("After 30 emplaces", arena);

		for (uint64_t i = 0; i < 30; ++i) {
			assert(u.find(StringPiece(gy_to_charbuf<64>("Key %lu", i).get())) != u.end());
		}	

		auto			it1 = u.find("Key 1");
		auto			it2 = u.find("key 1");

		assert(it1 != u.end() && it1->second == "Value 1");
		assert(it2 == u.end());

		assert(u.find(StringPiece("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 88)) == u.end());

		memuse("After 30 finds", arena);

		u.clear();

		memuse("After clear", arena);

		u.reserve(300);

		for (uint64_t i = 0; i < 30; ++i) {
			u.try_emplace(gy_to_charbuf<64>("Key %lu", i).get(), gy_to_charbuf<128>("Value %lu", i).get());
		}	

		memuse("After second 30 emplaces and before destruction", arena);

	}



	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Stack Hash Set Memory usage ...\n");

		using Stackset 		= INLINE_STACK_HASH_SET<std::pair<__int128_t, __int128_t>, 4096 * sizeof(std::pair<__int128_t, __int128_t>) + 3 * sizeof(uint64_t) * 4096 + 4096, 
								GY_JHASHER<std::pair<__int128_t, __int128_t>, true>>;

		Stackset			u(4096);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 4096 reserves", arena);

		for (uint64_t i = 0; i < 4096; ++i) {
			u.emplace(i, i);
		}	

		memuse("After 4096 emplaces", arena);

		u.clear();
		memuse("After clear", arena);

		u.reserve(4096);

		memuse("Before destruction", arena);
	}

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Folly Inline Stack Hash Set Memory usage ...\n");

		using Stackset 		= INLINE_STACK_F14_SET<std::pair<__int128_t, __int128_t>, 4096 * sizeof(std::pair<__int128_t, __int128_t>) + 3 * sizeof(uint64_t) * 4096 + 4096, 
								GY_JHASHER<std::pair<__int128_t, __int128_t>, true>>;

		Stackset			u(4096);
		auto			 & 	arena = u.get_arena();

		memuse("After construction with 4096 reserves", arena);

		for (uint64_t i = 0; i < 4096; ++i) {
			u.emplace(i, i);
		}	

		memuse("After 4096 emplaces", arena);

		u.clear();
		memuse("After clear", arena);

		u.reserve(4096);

		memuse("Before destruction", arena);
	}
	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Inline Stack Vector...\n");

		using Stackvec 			= INLINE_STACK_VECTOR<CHAR_BUF<72>, 10 * sizeof(CHAR_BUF<72>) + 10 * 8>;

		Stackvec			u;
		auto			&	arena = u.get_arena();

		memuse("After construction", arena);

		u.reserve(10);

		memuse("After reserve", arena);

		u.emplace_back("RED");
		u.emplace_back("GREEN");
		u.emplace_back("BLUE");
		u.emplace_back("RED");
		u.emplace_back("WHITE");
		u.emplace_back("CYAN");
		u.emplace_back("YELLOW");
		u.emplace_back("MAGENTA");

		// Iterate and print keys and values of unordered_map
		for ( const auto & n : u ) {
			std::cout << "\t[" << n << "]\n";
		}

		memuse("After all allocated assigned", arena);

		u.clear();

		memuse("After clear", arena);

		u.emplace_back("RED");
		u.emplace_back("GREEN");
		u.emplace_back("BLUE");
		u.emplace_back("RED");
		u.emplace_back("WHITE");
		u.emplace_back("CYAN");
		u.emplace_back("YELLOW");
		u.emplace_back("MAGENTA");


		u.emplace_back("BLACK");
		u.emplace_back("GREY");

		for ( const auto p : u ) {
			std::cout << "\t[" << p << "]\n";
		}
		std::cout << '\n';

		memuse("Before destruction", arena);
	}
	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Hash Map with Key as a Tuple and custom hash...\n");

		using Pairmap 		= GY_STACK_HASH_MAP<std::tuple<uint64_t, uint64_t, uint64_t>, int, 4096, GY_JHASHER<std::tuple<uint64_t, uint64_t, uint64_t>, true>>;
		using Arena		= Pairmap::allocator_type::arena_type;

		Arena			arena;
		Pairmap			u(arena), u2(arena);

		memuse("After construction", arena);

		std::tuple<uint64_t, uint64_t, uint64_t>		sam1 = std::make_tuple(4ul, 410ul, (uint64_t)false);

		u.try_emplace(std::make_tuple(1ul, 100ul, (uint64_t)true), 101);
		u.try_emplace(std::make_tuple(2ul, 200ul, (uint64_t)true), 201);
		u.try_emplace(std::make_tuple(3ul, 301ul, (uint64_t)false), 301);
		u.try_emplace(sam1, 401);

		// Iterate and print keys and values of unordered_map
		for ( const auto & n : u ) {
			std::cout << "\tKey:[{" << std::get<0>(n.first) << ", " << std::get<1>(n.first) << ", " << std::get<2>(n.first) << "}] Value:[" << n.second << "]\n";
		}
		
		std::cout << "\n\n";

		u[std::make_tuple(4ul, 410ul, (uint64_t)false)]++;
		u[std::make_tuple(5ul, 510ul, (uint64_t)false)]++;
		u[std::make_tuple(5ul, 510ul, (uint64_t)true)]++;

		memuse("After all assigns", arena);

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Now copying the map and iterating...\n");

		u2 = u;

		for ( const auto & n : u2 ) {
			std::cout << "\tKey:[{" << std::get<0>(n.first) << ", " << std::get<1>(n.first) << ", " << std::get<2>(n.first) << "}] Value:[" << n.second << "]\n";
		}
		std::cout << '\n';

		memuse("After copy", arena);
	}

	{
		IRPRINT("\n\n");

		INFOPRINTCOLOR(GY_COLOR_CYAN, "Testing Hash Map with Value as a Stack based Vector...\n");


		struct TEST1
		{
			int			num_		{0};
			CHAR_BUF<32>		str_;

			TEST1(int num, const char *str) noexcept 
				: num_(num), str_(str)
			{}	
		};	

		using Vecstack		= GY_STACK_VECTOR<TEST1, 8192>;
		using Arenavector	= Vecstack::allocator_type::arena_type;

		using Vecmap 		= GY_STACK_HASH_MAP<uint64_t, Vecstack, 2048>;
		using Arenamap		= Vecmap::allocator_type::arena_type;

		Arenavector		arenavector;
		memuse("After vec construction", arenavector);

		Arenamap		arenamap;
		Vecmap			map1(arenamap);
		memuse("After map construction", arenamap);

		{
			auto 		[it, success] = map1.try_emplace(1, arenavector);

			auto 		& vec1 = it->second;

			vec1.emplace_back(1, "First");
			vec1.emplace_back(2, "Second");
			vec1.emplace_back(3, "Third");
		}

		{
			auto 		[it, success] = map1.try_emplace(2, arenavector);

			auto 		& vec1 = it->second;

			vec1.emplace_back(4, "Fourth");
			vec1.emplace_back(5, "Fifth");
			vec1.emplace_back(6, "Sixth");
		}


		{
			auto 		[it, success] = map1.try_emplace(3, arenavector);

			auto 		& vec1 = it->second;

			vec1.emplace_back(7, "Seventh");
			vec1.emplace_back(8, "Eighth");
			vec1.emplace_back(9, "Nineth");
		}

		// Iterate and print keys and values of unordered_map
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Iterating over the Map of Vectors...\n");

		for (const auto & epair : map1) {
			std::cout << "\tKey:[" << epair.first << "] Vector Values :[";

			for (const auto & v : epair.second) {
				std::cout << "{\"num_\" : " << v.num_ << ", \"str_\" : \"" << v.str_.get() << "\" }, ";
			}	

			std::cout << "] Vector Capacity is " << epair.second.capacity() << "\n";
		}
		
		std::cout << "\n\n";

		memuse("Vector : After some emplaces", arenavector);
		memuse("Map : After some emplaces", arenamap);

		auto 		[it, success] = map1.try_emplace(4, arenavector);
		auto 		& vec1 = it->second;

		vec1.emplace_back(10, "Tenth");
		vec1.emplace_back(11, "Eleventh");
		vec1.emplace_back(12, "Twelveth");
		vec1.emplace_back(13, "Thirteenth");
		vec1.emplace_back(14, "Fourteenth");
		vec1.emplace_back(15, "Fifteenth");
		vec1.emplace_back(15, "Fifteenth");
		vec1.emplace_back(15, "Fifteenth");
		vec1.emplace_back(15, "Fifteenth");

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Iterating over the Map of Vectors after another add...\n");

		for (const auto & epair : map1) {
			std::cout << "\tKey:[" << epair.first << "] Vector Values :[";

			for (const auto & v : epair.second) {
				std::cout << "{\"num_\" : " << v.num_ << ", \"str_\" : \"" << v.str_.get() << "\" }, ";
			}	

			std::cout << "] Vector Capacity is " << epair.second.capacity() << "\n";
		}

		std::cout << "\n\n";

		memuse("Vector : ", arenavector);
		memuse("Map : ", arenamap);

		INFOPRINTCOLOR(GY_COLOR_GREEN, "Copying the Map of Vectors...\n");

		auto		map2 = map1;

		for (const auto & epair : map2) {
			std::cout << "\tKey:[" << epair.first << "] Vector Values :[";

			for (const auto & v : epair.second) {
				std::cout << "{\"num_\" : " << v.num_ << ", \"str_\" : \"" << v.str_.get() << "\" }, ";
			}	

			std::cout << "] Vector Capacity is " << epair.second.capacity() << "\n";
		}

		std::cout << "\n\n";

		memuse("Vector : before destruction", arenavector);
		memuse("Map : before destruction", arenamap);

		std::cout << "\n\n";

	}
	return 0;

}	
