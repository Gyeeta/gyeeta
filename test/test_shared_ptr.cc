
#include 	"gy_common_inc.h"
#include	"folly/memory/EnableSharedFromThis.h"

#include	"folly/concurrency/AtomicSharedPtr.h" 

using namespace gyeeta;

struct ShrTest;

folly::atomic_shared_ptr<ShrTest>	gatomicshr;
std::atomic<uint32_t>			gncopy_missed(0);

struct ShrTest : public folly::enable_shared_from_this<ShrTest>
{
	char				*pname;
	size_t				maxsz;
	std::atomic<uint32_t>		ncopies;

	ShrTest(const char *pnamein)
	{
		GY_MT_COLLECT_PROFILE(1000'000, "construct");
		
		maxsz = std::max(1024lu, strlen(pnamein));
		pname = new char[maxsz];
		
		strcpy(pname, pnamein);
		ncopies.store(0);
	}

	~ShrTest()
	{
		GY_MT_COLLECT_PROFILE(1000'000, "destroy");
		delete [] pname;	
	}

	int copy_string(const char *pnamein)
	{
		GY_MT_COLLECT_PROFILE(1000'000, "copy");

		auto shrp = this->shared_from_this();
		if (!shrp) {
			gncopy_missed.fetch_add(1);
			return -1;
		}	

		GY_STRNCPY(pname, pnamein, maxsz);
		ncopies.fetch_add(1);
		return 0;
	}	
};

int test_read(void *arg)
{
	std::weak_ptr<ShrTest>		weakp;

	for (int i = 0; i < 1000; i++) {
		for (int j = 0; j < 1000; j++) {
			std::shared_ptr<ShrTest>	lshr(gatomicshr.load(std::memory_order_relaxed));

			if (!lshr) {
				continue;
			}	
			auto praw = lshr.get();

			if (!praw) {
				continue;
			}	

			char		buf[512];

			snprintf(buf, sizeof(buf), "iteration %d", i * j);
			praw->copy_string(buf);

			weakp = praw->weak_from_this();

			if (0 == (i % 10)) 
			{
				lshr.reset(new ShrTest("new load test"));
				gatomicshr.store(std::move(lshr), std::memory_order_relaxed);

				auto shr_from_weak = weakp.lock();

				if (shr_from_weak) {
					GY_MT_COLLECT_PROFILE(1000'000, "copy from thread");

					(*shr_from_weak).copy_string("From weak ");
				}	
			}	
		}	

		gy_nanosleep(0, GY_NSEC_PER_MSEC);
	}	

	return 0;
}	
MAKE_PTHREAD_FUNC_WRAPPER(test_read);

int test_write(void *arg)
{
	gy_nanosleep(0, GY_NSEC_PER_MSEC);

	for (int i = 0; i < 1000; i++) {
		std::shared_ptr<ShrTest>	lshrn(new ShrTest("new test"));

		gatomicshr.store(std::move(lshrn), std::memory_order_relaxed);

		gy_nanosleep(0, GY_NSEC_PER_USEC);
	}	

	std::shared_ptr<ShrTest>	lshr;
	ShrTest				*praw = nullptr;

	while (!lshr || !praw) {
		gy_nanosleep(0, GY_NSEC_PER_MSEC);

		lshr = gatomicshr.load(std::memory_order_relaxed);

		praw = lshr.get();
	}	
	
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Shared Ptr Writer exiting : Total copy failures = %u : current copy count = %u\n", 
		gncopy_missed.load(), praw->ncopies.load());
	
	return 0;
}	
MAKE_PTHREAD_FUNC_WRAPPER(test_write);

int main(int argc, char **argv)
{
	gdebugexecn	= 10;

	GY_SIGNAL_HANDLER::init_singleton(argv[0]);

	gatomicshr.exchange(std::make_shared<ShrTest>("first test"));

	{
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Use count of atomic_shared_ptr is %lu\n", gatomicshr.load(std::memory_order_relaxed).use_count());

		auto		tmpshr = gatomicshr.load(std::memory_order_relaxed);

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Use count of atomic_shared_ptr after load to a local is %lu\n", tmpshr.use_count());

		tmpshr = std::make_shared<ShrTest>("first test");

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Use count of tmpshr after new store is %lu\n", tmpshr.use_count());

		gatomicshr.store(tmpshr);

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Use count of tmpshr after store to atomic_shared_ptr is %lu\n", tmpshr.use_count());
	}

	pthread_t 			rdthr[4], wrthr;
	
	for (size_t i = 0; i < GY_ARRAY_SIZE(rdthr); i++) {
		gy_create_thread(rdthr + i, GET_PTHREAD_WRAPPER(test_read), nullptr);
	}	
	
	gy_create_thread(&wrthr, GET_PTHREAD_WRAPPER(test_write), nullptr);

	for (size_t i = 0; i < GY_ARRAY_SIZE(rdthr); i++) {
		pthread_join(rdthr[i], nullptr);
	}	

	pthread_join(wrthr, nullptr);
	
	return 0;
}

