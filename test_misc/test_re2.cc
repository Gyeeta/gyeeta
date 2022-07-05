
#include		"gy_common_inc.h"

#define			GY_DISABLE_MALLOC_HOOK

#include		"gy_malloc_hook.h"

#include 		"re2/re2.h"

using namespace		gyeeta;

int match_filter(const char *pregex, const char *poper, int precreate)
{
	GY_MALLOC_HOOK::gy_malloc_init("Starting re2 tests", true /* print_individual */);

	GY_MALLOC_HOOK::gy_print_memuse("Starting Tests now...", true);

	std::optional<RE2>		re2;
	char				inputbuf[512];
	uint64_t			t1, t2;
	bool				oper, bret;

	if (precreate) {
		INFOPRINT("Compiling regex string \'%s\' \n", pregex);

		t1 = get_nsec_clock();

		RE2::Options 		opt;

		opt.set_max_mem(1 << 20);
		opt.set_log_errors(false);

		re2.emplace((const char *)pregex, opt);
	
		t2 = get_nsec_clock();

		INFOPRINT("Regex Object created : Time taken = %lu nsec (%lu usec)\n", t2 - t1, (t2 - t1)/1000);

		GY_MALLOC_HOOK::gy_print_memuse("After re2 object construct...", true);

		if ((re2->ok()) == false) {
			ERRORPRINT("Could not compile regular expression %s : Error is \'%s\'\n", pregex, re2->error().c_str());
			return -1;
		}
	}
	

	IRPRINT("\n\n");
	
	if ((strcasecmp(poper, "LIKE")) == 0) {
		oper = true;
	}
	else if ((strcasecmp(poper, "NOTLIKE")) == 0) {
		oper = false;
	}
	else {
		ERRORPRINT("Invalid Operator %s\n\n", poper);
		return -1;
	}

	do {
		INFOPRINT("Enter Test String : ");
		scanf("%500[^\n]", inputbuf);
		getchar();

		t1 = get_nsec_clock();

		if (precreate) {
			bret = RE2::PartialMatch((const char *)inputbuf, re2.value());
		}
		else {
			bret = RE2::PartialMatch((const char *)inputbuf, pregex);
		}	

		t2 = get_nsec_clock();

		INFOPRINT("Regex Match : Time taken = %lu nsec (%lu usec)\n", t2 - t1, (t2 - t1)/1000);

		if (bret == oper) {
			INFOPRINT("String \'%s\' MATCHES regex : %s \'%s\' : Time taken for match = %lu nsec (%lu usec)\n\n", inputbuf, poper, pregex, t2 - t1, (t2 - t1)/1000);
		}
		else {
			INFOPRINT("String \'%s\' DOES NOT MATCH regex : %s \'%s\' : Time taken for match = %lu nsec (%lu usec)\n\n", inputbuf, poper, pregex, t2 - t1, (t2 - t1)/1000);
		}

		GY_MALLOC_HOOK::gy_print_memuse("After re2 regex test ...", true);

	} while (1);

	return 1;
}


int main(int argc, char **argv)
{
	if (argc < 2) {
		IRPRINT("\nERROR : Usage %s <Regex String> <Operator : LIKE/NOTLIKE> <Precreate RE2 object 0/1 default 1>\n\n", argv[0]);
		return -1;	
	}	

	return match_filter(argv[1], argc > 2 ? argv[2] : "like", argc > 3 ? atoi(argv[3]) : 1);
}

