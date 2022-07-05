
#pragma			once

#pragma 		GCC diagnostic push
#pragma 		GCC diagnostic ignored "-Wdeprecated-declarations"

#include		"gy_common_inc.h"

#include 		<malloc.h>

/*
 * To Capture malloc stats, apps should call gyeeta::GY_MALLOC_HOOK::gy_malloc_init() once after main()
 * and then periodically call gyeeta::GY_MALLOC_HOOK::gy_print_memuse().
 * To clear Interval Malloc stats, users can call gyeeta::GY_MALLOC_HOOK::gy_reset_memuse();
 * To cleanup all hooks and restore to original state, users can call gyeeta::GY_MALLOC_HOOK::gy_malloc_cleanup()
 * after which all gy_print_memuse() will not print anything till another gy_malloc_init() done.
 */

namespace gyeeta {

class GY_MALLOC_HOOK
{
public :
	struct MSTATS
	{
		size_t			bytesmemory {0}, nalloc {0}, reallocbytes {0}, memalignbytes {0}, nfree {0};
		struct mallinfo		origmallinfo {};
	};	

	GY_MUTEX		mutex_;	
	MSTATS			mstats_;

	bool			updstats_ 		{false};
	bool			print_individual_	{false};

	void * 			(*old_malloc_hook)(size_t, const void *)		{nullptr};
	void * 			(*old_realloc_hook)(void *, size_t, const void *)	{nullptr};
	void * 			(*old_memalign_hook)(size_t, size_t, const void *)	{nullptr};
	void 			(*old_free_hook) (void*, const void *)			{nullptr};


	GY_MALLOC_HOOK() noexcept	= default;

	~GY_MALLOC_HOOK()
	{
		my_malloc_cleanup();
	}	

	void my_reset_memuse() noexcept
	{
		SCOPE_GY_MUTEX		slock(&mutex_);

		mstats_.bytesmemory = 0;
		mstats_.nalloc = 0;
		mstats_.nfree = 0;
		mstats_.reallocbytes = 0;
		mstats_.memalignbytes = 0;
	}	

	void my_print_memuse(const char *prefix_str) noexcept
	{
		STRING_BUFFER<512>	strbuf;

		SCOPE_GY_MUTEX		slock(&mutex_);

		auto			minfo = ::mallinfo();
		auto			oldstats = mstats_;

		mstats_.origmallinfo 	= minfo;

		slock.unlock();
		
		// snprintf can call malloc...
		strbuf.appendfmt("Heap calls : Interval # Malloc Bytes %lu : # Allocs %lu : # Frees %lu : # Realloc Bytes %lu : # Memalign Bytes %lu : # mmaps %d : # mmap bytes %d"
			"\n\t\tTotal Malloc Arena Bytes %d (%d MB) : Total Free Blocks Bytes %d (%d MB) : Total mmap Bytes %d (%d MB)\n\n",
			oldstats.bytesmemory, oldstats.nalloc, oldstats.nfree,
			oldstats.reallocbytes, oldstats.memalignbytes, minfo.hblks - oldstats.origmallinfo.hblks, minfo.hblkhd - oldstats.origmallinfo.hblkhd,
			minfo.arena, GY_DOWN_MB(minfo.arena), minfo.fordblks, GY_DOWN_MB(minfo.fordblks), minfo.hblkhd, GY_DOWN_MB(minfo.hblkhd));

		INFOPRINTCOLOR(GY_COLOR_YELLOW, "%s :\n\t\t%s\n", prefix_str, strbuf.buffer());
	}

	void my_malloc_init(const char *print_string) noexcept
	{
		SCOPE_GY_MUTEX		slock(&mutex_);

		if (true == updstats_) {
			return;
		}
		updstats_ = true;

		slock.unlock();
		
		my_save_hooks();
		my_new_hooks();

		INFOPRINTCOLOR(GY_COLOR_BLUE, "[Malloc Hook] Initialized : %s\n", print_string);

		my_reset_memuse();

		init_singleton(60);
	}

	bool is_init() const noexcept
	{
		return updstats_;
	}	

	void my_malloc_cleanup() noexcept
	{
		SCOPE_GY_MUTEX		slock(&mutex_);

		if (updstats_ == false) {
			return;
		}

		my_restore_hooks();

		updstats_ = false;

		slock.unlock();

		my_reset_memuse();
	}	
	
	void * my_malloc_hook (size_t size, const void *caller) noexcept
	{
		SCOPE_GY_MUTEX		slock(&mutex_);

		void 			*result;

		my_restore_hooks();

		result = ::malloc (size);

		my_save_hooks();

		if (updstats_) {
			mstats_.bytesmemory += size;
			++mstats_.nalloc;
			
			if (print_individual_) {
				INFOPRINTCOLOR(GY_COLOR_YELLOW, "[Malloc Hook]: malloc : Allocated %lu bytes Addr %p\n", size, result);
			}
		}

		my_new_hooks();

		return result;
	}

	void * my_realloc_hook(void *ptr, size_t size, const void *caller) noexcept
	{
		SCOPE_GY_MUTEX		slock(&mutex_);

		void 			*result;

		my_restore_hooks();

		result = realloc(ptr, size);

		my_save_hooks();

		if (updstats_) {
			mstats_.reallocbytes += size;
			++mstats_.nalloc;

			if (print_individual_) {
				INFOPRINTCOLOR(GY_COLOR_YELLOW, "[Malloc Hook]: realloc : Allocated %lu bytes Addr %p\n", size, result);
			}
		}

		my_new_hooks();

		return result;
	}

	void * my_memalign_hook(size_t alignment, size_t size, const void *caller) noexcept
	{
		SCOPE_GY_MUTEX		slock(&mutex_);
		void 			*result;

		my_restore_hooks();

		result = memalign(alignment, size);

		my_save_hooks();

		if (updstats_) {
			mstats_.memalignbytes += size;
			++mstats_.nalloc;

			if (print_individual_) {
				INFOPRINTCOLOR(GY_COLOR_YELLOW, "[Malloc Hook]: memalign : Allocated %lu bytes Addr %p\n", size, result);
			}
		}

		my_new_hooks();

		return result;
	}


	void my_free_hook (void *ptr, const void *caller) noexcept
	{
		SCOPE_GY_MUTEX		slock(&mutex_);

		my_restore_hooks();

		free (ptr);

		if (ptr && updstats_) {
			++mstats_.nfree;

			if (print_individual_) {
				INFOPRINTCOLOR(GY_COLOR_YELLOW, "[Malloc Hook]: free : Freeing Addr %p\n", ptr);
			}
		}

		my_save_hooks();

		my_new_hooks();;	
	}

	void my_print_individual(bool to_print) noexcept
	{
		print_individual_ = to_print;
	}

	static void gy_malloc_init(const char *print_string, bool print_individual = false) noexcept __attribute__((weak));

	static void gy_print_memuse(const char *prefix_str = "Printing Malloc Stats", bool reset_after_print = false) noexcept __attribute__((weak));

	static void gy_reset_memuse() noexcept __attribute__((weak));

	static void gy_malloc_cleanup() noexcept __attribute__((weak));

	static void * gy_malloc_hook (size_t size, const void *caller) noexcept	__attribute__((weak));

	static void * gy_realloc_hook(void *ptr, size_t size, const void *caller) noexcept __attribute__((weak));

	static void * gy_memalign_hook(size_t alignment, size_t size, const void *caller) noexcept __attribute__((weak));

	static void gy_free_hook (void *ptr, const void *caller) noexcept __attribute__((weak));

	static void gy_print_individual(bool to_print) noexcept;

	static int init_singleton(int secs_duration = 60) __attribute__((weak));

private :
	void my_save_hooks() noexcept
	{
		old_malloc_hook 	= __malloc_hook;
		old_realloc_hook	= __realloc_hook;
		old_memalign_hook	= __memalign_hook;
		old_free_hook 		= __free_hook;
	}	

	void my_restore_hooks() noexcept
	{
		__malloc_hook		= old_malloc_hook;
		__realloc_hook		= old_realloc_hook;
		__memalign_hook		= old_memalign_hook;
		__free_hook		= old_free_hook;
	}	

	void my_new_hooks() noexcept
	{
		__malloc_hook 		= gy_malloc_hook;
		__realloc_hook		= gy_realloc_hook;
		__memalign_hook		= gy_memalign_hook;
		__free_hook 		= gy_free_hook;
	}	
};	

GY_MALLOC_HOOK 			gmalloc_hook	__attribute__((weak));

void * GY_MALLOC_HOOK::gy_malloc_hook (size_t size, const void *caller) noexcept
{
	return gmalloc_hook.my_malloc_hook(size, caller);
}

void * GY_MALLOC_HOOK::gy_realloc_hook(void *ptr, size_t size, const void *caller) noexcept
{
	return gmalloc_hook.my_realloc_hook(ptr, size, caller);
}

void * GY_MALLOC_HOOK::gy_memalign_hook(size_t alignment, size_t size, const void *caller) noexcept
{
	return gmalloc_hook.my_memalign_hook(alignment, size, caller);
}


void GY_MALLOC_HOOK::gy_free_hook (void *ptr, const void *caller) noexcept 
{
	gmalloc_hook.my_free_hook(ptr, caller);
}


void GY_MALLOC_HOOK::gy_malloc_init(const char *print_string, bool print_individual) noexcept
{
#ifndef GY_DISABLE_MALLOC_HOOK
	gmalloc_hook.my_malloc_init(print_string);

	if (print_individual) {
		GY_MALLOC_HOOK::gy_print_individual(true);
	}	
#endif	
}

void GY_MALLOC_HOOK::gy_print_memuse(const char *prefix_str, bool reset_after_print) noexcept
{
#ifndef GY_DISABLE_MALLOC_HOOK
	gmalloc_hook.my_print_memuse(prefix_str);

	if (reset_after_print) {
		gmalloc_hook.my_reset_memuse();
	}	
#endif	
}

void GY_MALLOC_HOOK::gy_reset_memuse() noexcept
{
	gmalloc_hook.my_reset_memuse();
}

void GY_MALLOC_HOOK::gy_malloc_cleanup() noexcept
{
	gmalloc_hook.my_malloc_cleanup();
}

void GY_MALLOC_HOOK::gy_print_individual(bool to_print) noexcept
{
	gmalloc_hook.my_print_individual(to_print);
}	

#ifndef GY_MALLOC_HOOKED

int GY_MALLOC_HOOK::init_singleton(int secs_duration)
{
	return 0;
}

#endif

#pragma 		GCC diagnostic pop

} // namespace gyeeta

