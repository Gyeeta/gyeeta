//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"
#include		<iostream>
#include		<map>

using namespace gyeeta;

char			buf[256];


template <typename Map>
static void test_map(Map & map1)
{
	map1.try_emplace("First", 	"First Value is : .");
	map1.try_emplace("Second", 	"Second Value is : ..................");
	map1.try_emplace("Third", 	"Third Value is : ........................");
	map1.try_emplace("Fourth", 	"Fourth Value is : ..............................");

	const auto itb = map1.cbegin();

	std::cout << "\tsizeof(SSO_STRING<32>) is " << sizeof(itb->first) << " : sizeof(SSO_STRING<41>) " << sizeof(itb->second) << "\n\n";

	std::cout << "\tMap contents are : \n";

	for (const auto & it : map1) {
		std::cout << "\t[" << it.first << "] : [" << it.second << "] : Value of Length : " << it.second.size() << " : is_heap is " << it.second.is_heap() << '\n';
	}	

	std::cout << "\n\n";

	map1["First"] += "Appended";

	map1["Second"].appendconst("Appended String");

	map1["Third"] += buf;

	map1["Third"].truncate_to(128);

	map1["Fourth"] += "Another Loooooooooooooooooooong Append";

	map1["Fourth"] = map1["Fourth"].data() + 10;

	map1["Fifth"] += map1["Fourth"].data();

	std::cout << "\tMap contents after appending are : \n";

	for (const auto & it : map1) {
		std::cout << "\t[" << it.first << "] : [" << it.second << "] : Value of Length : " << it.second.size() << " : is_heap is " << it.second.is_heap() << '\n';
	}	

	std::cout << "\n\n";

}	


int main()
{
	SSO_STRING<64>		str64("Testing a short string    ");

	SSO_STRING<64>		strheap("Testing a loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong heap string");
	SSO_STRING<28>		str28("new 28 ");
	SSO_STRING<80>		str80("new 80 ");

	std::cout << "str64 is \'" << str64 << "\' : str64.size() = " << str64.size() << " str64.capacity() = " << str64.capacity() << " str64.is_heap() = " << str64.is_heap() << "\n\n";
	std::cout << "strheap is \'" << strheap << "\' : strheap.size() = " << strheap.size() << " strheap.capacity() = " << strheap.capacity() << " strheap.is_heap() = " << strheap.is_heap() << "\n\n";

	str64 = strheap;
	
	std::cout << "str80.buffer() before append = " << (void *)str80.buffer() << " of size " << str80.size() << " and capacity " << str80.capacity() << '\n';;
	str80 += strheap.data();
	std::cout << "str80.buffer() after append = " << (void *)str80.buffer() << " of size " << str80.size() << " and capacity " << str80.capacity() << '\n';;
	str80 += strheap.data();
	std::cout << "str80.buffer() after 2nd append = " << (void *)str80.buffer() << " of size " << str80.size() << " and capacity " << str80.capacity() << "\n\n";;

	assert(strheap == str64);

	std::cout << "After assignment str64 is \'" << str64 << "\' : str64.size() = " << str64.size() << " str64.capacity() = " << str64.capacity() << " str64.is_heap() = " << str64.is_heap() << "\n\n";
	
	strheap = std::move(str64);
	std::cout << "After move assignment strheap is \'" << strheap << "\' : strheap.size() = " << strheap.size() << " strheap.capacity() = " << strheap.capacity() << " strheap.is_heap() = " << strheap.is_heap() << "\n\n";
	
	str64.strset("Another string", 5);
	std::cout << "str64 is \'" << str64 << "\' : str64.size() = " << str64.size() << " str64.capacity() = " << str64.capacity() << " str64.is_heap() = " << str64.is_heap() << "\n\n";

	std::memcpy(buf, "String", 6);
	std::memset(buf + 6, ' ', sizeof(buf) - 7);
	buf[sizeof(buf) - 1] = 0;

	strheap.strset(buf);
	std::cout << "After assignment strheap is \'" << strheap << "\' : strheap.size() = " << strheap.size() << " strheap.capacity() = " << strheap.capacity() << " strheap.is_heap() = " << strheap.is_heap() << "\n\n";

	std::cout << "str28 is \'" << str28 << "\' : str28.size() = " << str28.size() << " str28.capacity() = " << str28.capacity() << " str28.is_heap() = " << str28.is_heap() << "\n\n";

	str28 = std::move(strheap);
	std::cout << "After move assignment str28 is \'" << str28 << "\' : str28.size() = " << str28.size() << " str28.capacity() = " << str28.capacity() << " str28.is_heap() = " << str28.is_heap() << "\n\n";

	strheap = str28;
	std::cout << "After assignment strheap is \'" << strheap << "\' : strheap.size() = " << strheap.size() << " strheap.capacity() = " << strheap.capacity() << " strheap.is_heap() = " << strheap.is_heap() << "\n\n";

	assert(strheap == str28);

	strheap.truncate_to(62, false);
	std::cout << "After truncate strheap is \'" << strheap << "\' : strheap.size() = " << strheap.size() << " strheap.capacity() = " << strheap.capacity() << " strheap.is_heap() = " << strheap.is_heap() << "\n\n";

	char			buf2[512];
	std::memset(buf2, ' ', sizeof(buf2) - 1);
	buf2[sizeof(buf2) - 1] = 0;
	
	strheap.assign(buf2);

	std::cout << "After realloc strheap is \'" << strheap << "\' : strheap.size() = " << strheap.size() << " strheap.capacity() = " << strheap.capacity() << " strheap.is_heap() = " << strheap.is_heap() << "\n\n";

	SSO_STRING<254>		sso250(buf2, 254);

	std::cout << "SSO_STRING<254> is \'" << sso250 << "\' : sso250.size() = " << sso250.size() << " sso250.capacity() = " << sso250.capacity() << " sso250.is_heap() = " << sso250.is_heap() << "\n\n";

	char			tbuf[1024];
	STR_WR_BUF		strbuf(tbuf, sizeof(tbuf));

	char			lbuf1[] = "Testing buffer";
	char			lbuf2[14];

	snprintf(lbuf2, sizeof(lbuf2), "testing");

	SSO_STRING<64>		strliteral(lbuf1), strliteral2(lbuf2);

	std::cout << "Testing char buffers : strliteral is \'" << strliteral << "\' : and strliteral2 is \'" << strliteral2 << "\'\n\n";

	strbuf << "Testing STRING_BUFFER : " << buf << " : Address of strbuf = " << (void *)&strbuf << " Current length is " << strbuf.length() << '\n';

	std::cout << "strbuf contents are : \'" << strbuf.buffer() << "\'\n";

	strbuf.truncate_by(1);

	strbuf << " : Adding lbuf1 : " << lbuf1 << " and now lbuf2 " << lbuf2 << "...";

	strbuf.appendconst(" : From string literal : ");
	strbuf << "Version " << 1.1 << '\n';

	strbuf.infoprint("strbuf contents are : ");

	assert(strheap != str64);

	str64.assign(strbuf);

	std::cout << "\nAfter STR_WR_BUF assign : str64 is \'" << str64 << "\' : str64.size() = " << str64.size() << " str64.capacity() = " << str64.capacity() << " str64.is_heap() = " << str64.is_heap() << "\n\n";

	std::unordered_map<SSO_STRING<32>, SSO_STRING<41>, STR_HASHER<SSO_STRING<32>>>	map1;
	std::map<SSO_STRING<32>, SSO_STRING<41>>	map2;

	std::cout << "\n\nTesting unordered_map()...\n\n";
	test_map(map1);

	std::cout << "\n\nTesting map()...\n\n";
	test_map(map2);

	return 0;
}

