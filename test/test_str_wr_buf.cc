//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gy_common_inc.h"

using namespace		gyeeta;

[[gnu::noinline]] 
STRING_HEAP test1()
{
	STRING_BUFFER<256>	stackbuf;
	STRING_HEAP		heapbuf(256);
	char			sbuf[64], sbuf2[64], *psbuf = sbuf2;
	const char		cbuf[] = "Const Char Buffer : ";

	stackbuf.append("A test string ");		
	stackbuf.appendutf("नमस्ते");				
	stackbuf.appendconst(" This is a string literal ");	
	stackbuf << 3.14159;			

	strcpy(sbuf, " : Local Array string : ");
	strcpy(sbuf2, "Char Pointer Test : ");

	stackbuf << " Testing String View Operator "sv << cbuf << sbuf << psbuf << " : Address of stackbuf = " << (void *)stackbuf.buffer() << " Current length is " << stackbuf.length();
		
	IRPRINT("\n\n");	
	INFOPRINT("stackbuf buffer is \'%s\'\n\n", stackbuf.buffer());

	IRPRINT("\n\n");	
	INFOPRINT("heapbuf buffer is \'%s\'\n\n", heapbuf.buffer());

	heapbuf.append("A test string ");		
	heapbuf.appendutf("नमस्ते");				
	heapbuf.appendconst(" This is a string literal ");	
	heapbuf.append(3.1);			
	heapbuf << " Testing STRING_HEAP"sv << " : Address of heapbuf = "sv << (void *)heapbuf.buffer() << " Current length is "sv << heapbuf.length();
		
	IRPRINT("\n\n");	
	INFOPRINT("heapbuf buffer is \'%s\'\n\n", heapbuf.buffer());

	STRING_HEAP		heap2(heapbuf);

	assert(heap2 == heapbuf);

	STRING_HEAP		heap3(std::move(heap2)), heap4(256); 

	assert(!(heap2 == heapbuf));

	heap4 = std::move(heap3);

	INFOPRINT("heap4 buffer is \'%s\'\n\n", heap4.buffer());

	heap4.reset();

	heap4.append(heap4.buffer() + 8, 10);

	INFOPRINT("heap4 buffer after self append is \'%s\'\n\n", heap4.buffer());

	char			ctest[512];

	std::memset(ctest, '.', sizeof(ctest) - 1);
	ctest[sizeof(ctest) - 1] = 0;

	const auto ovf = [](const char * pstr, size_t szstr, bool istrunc, bool newupdates) -> bool
	{
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Overflow of Buffer seen : String before overflow = \'%s\' of length %lu and istrunc = %d\n\n", pstr, szstr, istrunc);
		return true;
	};

	INFOPRINT("Testing Overflow callbacks...\n\n");

	ctest[200] = 0;

	heapbuf.appendfmtcb(ovf, "Testing non truncated Overflow : %s\n", ctest);
	
	INFOPRINT("heapbuf after non truncated overflow = \'%s\' of length %lu\n\nTesting Truncated Overflow callback...\n\n", heapbuf.buffer(), heapbuf.length());

	ctest[200] = '.';

	heap4.appendcb(ovf, ctest, strlen(ctest));

	INFOPRINT("heap4 after truncated overflow = \'%s\' of length %lu\n\n", heap4.buffer(), heap4.length());

	heap4.reset();

	ctest[255] = 0;

	heap4.appendcb(ovf, ctest, strlen(ctest));

	INFOPRINT("heap4 after exact bytes overflow = \'%s\' of length %lu\n\n", heap4.buffer(), heap4.length());

	heap4.reset();

	heap4 << "Address of heap4 = " << (void *)heap4.buffer() << " Length = " << heap4.length();

	return heap4;

}

[[gnu::noinline]] 
BIN_HEAP_BUF testu8()
{
	BIN_BUFFER<256>		stackbuf;
	BIN_HEAP_BUF		heapbuf(512);
	char			sbuf[64], sbuf2[64], *psbuf = sbuf2, c;
	const char		cbuf[] = "Const Char Buffer : ";
	int64_t			i64 = 0xAABBCCDDEEFF0011l, n64;
	int			i32 = 0xAABBCCDD, n32;
	int16_t			s16;

	stackbuf.appendconst("A test string : ");		
	stackbuf.appendutf("नमस्ते");				
	
	stackbuf.appendconst("\nDouble : ");	
	stackbuf << 3.14159;			
	
	stackbuf.appendconst("\nint32 : ");	
	stackbuf << i32;
	
	stackbuf.appendconst("\nint64 : ");	
	stackbuf << i64;
	
	std::tuple<int, char, uint16_t, float> t(0x11111111, 'Z', 0xFFFF, -3.14159);
	stackbuf << "\nTuple <int, char, uint16_t, float> : "sv;
	stackbuf << t;

	gy_print_buf(STDOUT_FILENO, stackbuf.buffer(), stackbuf.size(), 1, "Intermediate BIN_BUFFER print :");

	stackbuf.reset();

	stackbuf << 'A' << i32 << i64;

	// Test STR_RD_BIN 

	STR_RD_BIN(stackbuf.buffer(), stackbuf.size()) >> c >> n32 >> n64;

	assert(c == 'A' && n32 == i32 && n64 == i64);

	stackbuf.reset();

	STR_RD_BIN("\x00\x01\x02\x03\x04\xFF"sv) >> n32 >> s16;

	assert(ntohl(n32) == 0x00010203 && ntohs(s16) == 0x04FF);

	struct { int i; char c[4]; float f; } s;
	
	STR_RD_BIN("\x00\x01\x02\x03\x41\x42\x43\x44\x00\x00\x00\x00"sv) >> s;

	assert(ntohl(s.i) == 0x00010203 && s.c[0] == 'A' && s.c[3] == 'D' && s.f == 0);
	
	SSO_STRING<64>		sso("Test SSO String");
	
	stackbuf << "\nTesting SSO_STRING Binary Struct ... : "sv;
	stackbuf << sso;
	
	stackbuf << "\nString view : "sv;
	stackbuf << sso.get_view();

	struct ss
	{
		uint64_t		u64_		{~0ul};
		uint16_t		u16_		{0xFFFF};
		char			c_		{'V'};

		ss() noexcept		= default;

		ss(uint64_t u64, uint16_t u16, char c) noexcept
			: u64_(u64), u16_(u16), c_(c)
		{}
	};	

	ss			s1;

	stackbuf << "\nTesting Binary Struct ... : "sv;
	stackbuf << s1 << ss(1, 1, 'A');
	
	gy_print_buf(STDOUT_FILENO, stackbuf.buffer(), stackbuf.size(), 1, "Intermediate BIN_BUFFER print :");

	heapbuf.append(stackbuf);

	heapbuf.append("\n\n\nnA test string ");		
	heapbuf.appendutf("नमस्ते");				
	heapbuf.appendconst(" This is a string literal ");	

	heapbuf--;

	return heapbuf;
}

using TStringHeapVec = std::vector<std::optional<STRING_HEAP>>;

// Callback Overflow tests
void testcbstrs(TStringHeapVec & dbstrvec)
{
	STRING_HEAP			*pdbstr = std::addressof(dbstrvec.at(dbstrvec.size() - 1).value());
	char				*poutstr;
	size_t				lastdbstrsz = 16;
	bool				retrystr = false, stmtstart = false;

	// String Overflow callback
	const auto dbstrovf = [&](const char * pstr, size_t szstr, bool istrunc, bool newupdates) -> bool
	{
		if (istrunc == false) {
			INFOPRINTCOLOR(GY_COLOR_YELLOW, "Overflow of Str Buffer %p seen. Allocating new element #%lu : \n", 
					pstr, dbstrvec.size() + 1);

			retrystr 	= !newupdates;
		}
		else {
			INFOPRINTCOLOR(GY_COLOR_YELLOW, "Overflow of Str Buffer %p seen as too large. Resetting element #%lu and retrying in a new buffer : \n", pstr, dbstrvec.size());

			retrystr 	= true;
			lastdbstrsz 	+= 8;

			pdbstr->reset();

			GY_CC_BARRIER();

			pdbstr->get_unique_ptr().reset();

			GY_CC_BARRIER();
		}	

		auto			& optelem = dbstrvec.emplace_back(std::in_place, lastdbstrsz); 

		pdbstr = std::addressof(optelem.value());

		return false;
	};

	for (int i = 0; i < 16; ++i) {
retry1 :		
		if (i < 4) {
			poutstr = pdbstr->appendfmtcb(dbstrovf, "Testing %d ", i);
		}
		else {
			poutstr = pdbstr->appendfmtcb(dbstrovf, "Testing string %d --------------------- ", i);
		}	

		if (poutstr == nullptr) {
			if (retrystr) {
				retrystr = false;
				goto retry1;
			}	
		}
	}
}		

int main()
{
	gdebugexecn = 1;

	auto			heap4 = test1();

	INFOPRINT("heap4 after move = \'%s\' of length %lu : heap4.buffer() = %p\n\n", heap4.buffer(), heap4.length(), heap4.buffer());

	auto			u8heap = testu8();

	INFOPRINT("u8heap after move is of length %lu : u8heap.buffer() is shown below : \n\n", u8heap.length());
	gy_print_buf(STDOUT_FILENO, u8heap.buffer(), u8heap.size(), 1, "");

	IRPRINT("\n\n");

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing STR_WR_BUF overflow callback vector tests...\n\n");

	TStringHeapVec		dbstrvec;

	dbstrvec.reserve(5);
	dbstrvec.emplace_back(std::in_place, 16); 

	testcbstrs(dbstrvec);
	testcbstrs(dbstrvec);

	INFOPRINTCOLOR(GY_COLOR_GREEN, "The output of vectors is : \n");

	for (size_t i = 0; i < dbstrvec.size(); ++i) {
		const auto 		& optstr = dbstrvec[i];

		if (bool(optstr) && optstr->buffer() && optstr->length() > 0) {
			IRPRINT("Buffer is : \'%s\', length = %lu, Address = %p, Bytes Remaining %lu, Index %lu\n", 
					optstr->buffer(), optstr->length(), optstr->buffer(), optstr->bytes_left(), i);
		}	
	}	
}	

