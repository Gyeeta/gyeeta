
#include "gy_common_inc.h"

using namespace gyeeta;

int main(int argc, char *argv[])
{
	STRING_BUFFER<1024>	strbuf;

	strbuf.appendconst("Testing ASCII string and then UTF8 string : ");
	strbuf.append(" First ASCII : ");
	strbuf.appendutf(" Then UTF8 : नमस्ते, दुनिया");
	strbuf.appendutf(" : Now ASCII again typecasted as UTF8");
	strbuf.appendutf(" : Now UTF8 again : 你好, 世界");

	INFOPRINTCOLOR(GY_COLOR_GREEN, "The UTF8 string is \'%.*s\' of strlen %lu : utf8 chars %lu\n", 
			strbuf.sizeint(), strbuf.buffer(), strbuf.length(), gy_utf8_len(strbuf.buffer()));

	const char		*pinput = strbuf.buffer(), *ptmp, *ptmp2;
	size_t			sz = strbuf.length();

	int			sep, ret;
	bool			bret;

	(void)gy_utf8_codepoint("म", &sep);

	// Now test various utf8 string functions 
	ptmp = (const char *)gy_utf8_chr(pinput, sep);

	assert(ptmp);

	INFOPRINT(GY_COLOR_CYAN "String after the UTF8 char म is %s\n", ptmp);  
	
	ret = gy_utf8_ncasecmp(ptmp, "मस्ते, दुनिय", strlen("मस्ते, दुनिय"));

	assert(ret == 0);
	
	ret = ::strncasecmp(ptmp, "मस्ते, दुनिय", strlen("मस्ते, दुनिय"));

	assert(ret == 0);

	ptmp2 = (const char *)gy_utf8_casestr(pinput, "你好,");
	
	assert(ptmp2);

	bret = is_whole_word_in_utf8_str(pinput, "मस्ते", nullptr, false, sz);

	assert(bret == false);

	bret = is_whole_word_in_utf8_str(pinput, "你好", nullptr, false, sz);

	assert(bret == true);

	return 0;

}


