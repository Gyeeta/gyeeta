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

	stackbuf << " Testing STRING_BUFFER " << cbuf << sbuf << psbuf << " : Address of stackbuf = " << (void *)stackbuf.buffer() << " Current length is " << stackbuf.length();
		
	IRPRINT("\n\n");	
	INFOPRINT("stackbuf buffer is \'%s\'\n\n", stackbuf.buffer());

	IRPRINT("\n\n");	
	INFOPRINT("heapbuf buffer is \'%s\'\n\n", heapbuf.buffer());

	heapbuf.append("A test string ");		
	heapbuf.appendutf("नमस्ते");				
	heapbuf.appendconst(" This is a string literal ");	
	heapbuf.append(3.1);			
	heapbuf << " Testing STRING_HEAP" << " : Address of heapbuf = " << (void *)heapbuf.buffer() << " Current length is " << heapbuf.length();
		
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

using TStringHeapVec = std::vector<std::optional<STRING_HEAP>>;

void testcbstrs(TStringHeapVec & dbstrvec)
{
	STRING_HEAP			*pdbstr = std::addressof(dbstrvec.at(dbstrvec.size() - 1).value());
	char				*poutstr;
	size_t				lastdbstrsz = 16;
	bool				retrystr = false, stmtstart = false;

	// DB String Overflow callback
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

	auto			heap4 = std::move(test1());

	INFOPRINT("heap4 after move = \'%s\' of length %lu : heap4.buffer() = %p\n\n", heap4.buffer(), heap4.length(), heap4.buffer());

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Now testing callback vector tests...\n\n");

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

