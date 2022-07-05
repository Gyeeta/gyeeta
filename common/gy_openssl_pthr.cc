
#include		"gy_common_inc.h"
#include 		<openssl/err.h>


#if OPENSSL_VERSION_NUMBER < 0x10100000

/*
 * The SSL Initialization must be called from each separate process.
 * This explains the static below
 */
static pthread_mutex_t 		*pssl_lock_cs = nullptr;

struct CRYPTO_dynlock_value 
{
	pthread_mutex_t		mutex;
};

static unsigned long pthreads_thread_id(void) 
{
	return (unsigned long)pthread_self();
}

static void pthreads_locking_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(pssl_lock_cs[type]));
	}
	else {
		pthread_mutex_unlock(&(pssl_lock_cs[type]));
	}
}

static struct CRYPTO_dynlock_value* dyn_ssl_create_func(const char *file, int line)
{
	struct CRYPTO_dynlock_value 	*value;
	
	value = (struct CRYPTO_dynlock_value *) malloc(sizeof(struct CRYPTO_dynlock_value));
	if (value == nullptr) {
		PERRORPRINT("malloc failed for dyn lock for ssl");
		return nullptr;
	}
	
	pthread_mutex_init(&value->mutex, nullptr);
	return value;
}

static void dyn_ssl_destroy_func(struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	pthread_mutex_destroy(&l->mutex);
	free(l);
}

static void dyn_ssl_lock_func(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
	if(mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&l->mutex);
	} 
	else {
		pthread_mutex_unlock(&l->mutex);
	}
}

namespace gyeeta {

static int ssl_setup_pthreads() noexcept
{
	int 		i;

	pssl_lock_cs = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if (pssl_lock_cs == nullptr) {
		ERRORPRINT("Could not allocate memory for ssl pthreads\n");
		return -1;
	}	
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(pssl_lock_cs[i]), nullptr);
	}

	CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
	CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))pthreads_locking_callback);

	CRYPTO_set_dynlock_create_callback(dyn_ssl_create_func);
	CRYPTO_set_dynlock_lock_callback(dyn_ssl_lock_func);
	CRYPTO_set_dynlock_destroy_callback(dyn_ssl_destroy_func);

	return 0;
}

static void ssl_cleanup_pthreads() noexcept
{
	int 		i;

	if (pssl_lock_cs == nullptr) {
		return;	
	}
			
	CRYPTO_set_locking_callback(nullptr);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(pssl_lock_cs[i]));
	}
	OPENSSL_free(pssl_lock_cs);
	pssl_lock_cs = nullptr;

	CRYPTO_set_id_callback(nullptr);
	CRYPTO_set_dynlock_create_callback(nullptr);
	CRYPTO_set_dynlock_lock_callback(nullptr);
	CRYPTO_set_dynlock_destroy_callback(nullptr);
}

} // namespace gyeeta

#endif

namespace gyeeta {

void gy_ssl_pthread_init() noexcept
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	static bool is_init = false;

	if (!is_init) {
		is_init = true;
		ssl_setup_pthreads();
	}
#endif
}	

void gy_ssl_pthread_cleanup() noexcept
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	static bool is_fini = false;

	if (!is_fini) {
		is_fini = true;
		ssl_cleanup_pthreads();
	}	
#endif
}	

} // namespace gyeeta
