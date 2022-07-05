
#include 		"gy_common_inc.h"
#include 		"gy_file_api.h"
#include 		"gy_misc.h"
#include		<bitset>

using namespace gyeeta;

using GY_BITSET	= std::bitset<128>;	

int my_set_bitset_from_buffer(GY_BITSET &bset, const char *buf)
{
	/*
	 * Input string is in following format : <Range1>,<Range2>... where Range is in format <Num1-Num2> with nospace allowed 
	 * e.g. "0,2-4,6-8,10,31,60"
	 */
	const char		*pstart = buf, *pend = buf + strlen(buf);
	char			*ptmp = const_cast<char *>(pstart), *pnxt;
	uint64_t		ulval, ulstart;
	const size_t		maxbits = bset.size();
	bool			isrange = false;

	do {
		pnxt = nullptr;

		ulval = strtoul(ptmp, &pnxt, 10);
		if ((ulval == ULONG_MAX) && (errno == ERANGE)) {
			break;
		}	
		else if (ulval > maxbits) {
			return 1;
		}
		else if (ulval == 0 && (pnxt == ptmp)) {

		}	
		else {

			if (isrange == false) {
				bset[ulval] = true;
			}
			else {
				isrange = false;

				for (uint64_t i = ulstart; i <= ulval; i++) {
					bset[i] = true;
				}	
			}
		}

		if (pnxt && *pnxt) {
			if (*pnxt == ',') {
				ptmp = pnxt + 1;
				continue;
			}	
			else if (*pnxt == '-') {
				ptmp = pnxt + 1;

				isrange = true;
				ulstart = ulval;
				continue;
			}	
			else if (isspace(*pnxt)) {
				ptmp = pnxt;
				do {
					ptmp++;
				} while ((ptmp < pend) && (isspace(*ptmp)));	
			}
			else return 1;
		}	
		else {
			break;
		}	
	} while (ptmp < pend);	

	return 0;
}	


int main(int argc, char **argv)
{
	if (argc != 2) {
		IRPRINT("Usage : %s <Bit string e.g. \"0,2-4,6-8,10,12,120\">\n\n", argv[0]);
		return EXIT_FAILURE;
	}	

	GY_BITSET		bset, bcopyset;
	int			ret;
	std::string		sb;

/* 	ret = my_set_bitset_from_buffer(bset, argv[1]); */
	ret = set_bitset_from_buffer(bset, argv[1], strlen(argv[1]));

	sb = bset.to_string();

	if (ret != 0) {
		ERRORPRINT("Failed to completely parse bitset string %s : Parsed bitset is %s\n\n", argv[1], sb.c_str());
	}
	else {
		INFOPRINT("Parsed input bitstring %s : Output bitset is %s\n\n", argv[1], sb.c_str());
	}	

	bcopyset = bset;

	assert(bcopyset == bset);

	sb = bcopyset.to_string();

	INFOPRINT("Parsed input bitstring %s : Output bcopyset is %s\n\n", argv[1], sb.c_str());

	return 0;
}	
