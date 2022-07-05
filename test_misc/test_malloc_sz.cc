
#include		"gy_common_inc.h"
#include		"gy_memory.h"

using namespace gyeeta;

void testmalloc(size_t sz)
{
	char		*ptmp = (char *)malloc_or_throw(sz);
	size_t		act_sz = gy_malloc_usable_size(ptmp, sz);

	INFOPRINT("Malloc Test : sz %lu : Actual sz %lu : Extra Bytes %ld\n", sz, act_sz, act_sz - sz);

	for (size_t i = 0; i < act_sz; ++i) {
		ptmp[i] = 0;
	}	
	
	::free(ptmp);
}

void testrealloc(size_t sz1, size_t sz2)
{
	char		*ptmp1 = (char *)malloc_or_throw(sz1);

	GY_CC_BARRIER();
	
	char		*ptmp = (char *)realloc(ptmp1, sz2);
	size_t		act_sz = gy_malloc_usable_size(ptmp, sz2);

	INFOPRINT("Realloc Test : sz1 %lu : sz2 %lu : Actual sz %lu : Extra Bytes %ld\n", sz1, sz2, act_sz, act_sz - sz2);

	for (size_t i = 0; i < act_sz; ++i) {
		ptmp[i] = 0;
	}	
	
	::free(ptmp);
}


int main()
{
	const size_t		szarr[] {1, 8, 14, 20, 35, 48, 64, 70, 90, 128, 510, 601, 732, 910, 999, 1001, 1211, 1777, 2010, 2555, 4096, 4109, 5100, 6000, 8192, 17120, 
				24012, 32767, 65500, 101000, 128 * 1024, 155 * 1024, 200 * 1024, 256 * 1024, 1024 * 1024 + 8, 2 * 1024 * 1024};

	for (size_t i = 0; i < GY_ARRAY_SIZE(szarr); ++i) {
		testmalloc(szarr[i]);
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(szarr) - 1; ++i) {
		testrealloc(szarr[i], szarr[i + 1]);
	}	

}	

