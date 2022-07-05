
#pragma 		once

#include 		"gy_common_inc.h"

namespace gyeeta {

/*
 * Single Producer & Single Consumer semi lockless queue along with optional
 * Multi-process handling and automatic dynamic buffer addition/reallocation/drops if needed. 
 * Use only for Single Producer case, supports multi producers by mutex locking internally
 * but will really limit throughput for multi producer case.
 */ 

typedef int 			(*PKTPOOL_CHK_FP)(void *);
typedef int 			(*PKTPOOL_DUMP_FP)(int, char *, unsigned int);

typedef void * 			(*PKTPOOL_BUF_ALLOC_FP)(size_t size);
typedef void 			(*PKTPOOL_BUF_FREE_FP)(void *pbuf);

enum PKT_RET_E {
	PKT_RET_SUCCESS 	= 0,
	PKT_BLOCKING 		= -1,
	PKT_DEADLOCK_LIKELY	= -2,
	PKT_RET_SIGNAL		= -3,	
	PKT_RET_ERROR 		= -4,	
};

class GY_PKT_POOL final
{
public :
	static constexpr uint32_t	PKT_POOL_MAGIC	= 0xFEED5678u;
	static constexpr uint32_t	MAX_PKT_TCP_READER_LAG = 3;
		
	struct PKT_ELEM;

	pthread_mutex_t			mutex				__attribute__((aligned(128)));	
	int				multi_process			{0};

	PKT_ELEM			*pktpool			{nullptr};
	pthread_cond_t			cond;	
	int				is_wr_blocking			{0};
	int				is_rd_blocking			{0};

	uint32_t			cmagic				{0};
	int 				is_pktpool_used			{0};
	uint32_t			bufcnt				{0};
	uint32_t			maxbuflen			{0};

	uint32_t			max_dyn_buf_size		{0};
	uint32_t			cur_dyn_buf_size		{0};
	uint32_t			drop_dyn_sec			{0};
	
	int				do_realloc			{0};
	
	size_t				size_pbuf			{0};
	size_t				size_pktpool			{0};

	std::atomic <size_t>		wr_				{0};

	uint64_t			pkts_written			{0};
	uint64_t			tot_pkts_written		{0};

	uint64_t			pkts_dyn_written		{0};
	uint64_t			tot_pkts_dyn_written		{0};
	uint64_t			pkts_dyn_dropped		{0};
	uint64_t			tot_pkts_dyn_dropped		{0};
	uint64_t			pkts_wr_waits			{0};
	uint64_t			tot_pkts_wr_waits		{0};
	uint64_t			pkts_wr_under_lock		{0};
	uint64_t			tot_pkts_wr_under_lock		{0};

	uint64_t			lock_resets			{0};
	uint64_t			tot_lock_resets			{0};

	uint64_t			last_cond_wr_cnt		{0};

	uint64_t			dummyrd1 	  		__attribute__((aligned(128)))	{0};

	std::atomic <size_t>		rd_				{0};

	uint64_t			pkts_read			{0};
	uint64_t			tot_pkts_read			{0};
	uint64_t			pkts_dyn_read			{0};
	uint64_t			tot_pkts_dyn_read		{0};
	uint64_t			pkts_rd_under_lock		{0};
	uint64_t			tot_pkts_rd_under_lock		{0};

	int				to_reset			{0};
	int				wr_exited			{0};
	int				rd_exited			{0};

	uint32_t			dummy3  			__attribute__((aligned(128)))	{0};

	std::atomic <int>		use_lock_			{0};

	PKTPOOL_CHK_FP			chkfp				{nullptr};	// Func Ptr to check if deadlock would occur. Used during writing to pool
	void				*param				{nullptr};	// Passed by the callee

	int				use_atomic			{0};
	bool				is_reader_rcu_thread		{false};
	bool				is_writer_rcu_thread		{false};

	PKTPOOL_BUF_ALLOC_FP		pext_bufalloc_fp		{nullptr};	// Func Ptr for an external buffer allocator 
	PKTPOOL_BUF_FREE_FP		pext_buf_free_fp		{nullptr};	// Func Ptr for an external buffer free 
	
	size_t				size_obj			{0};

	char				poolstr[64]			{};

	struct PKT_DYN_ELEM 
	{
		off_t				foff;
		uint8_t				*pbuf;
		PKT_DYN_ELEM			*next;
		uint32_t			len;
		uint8_t				is_external_buf;
	};

	struct PKT_ELEM 
	{
		char				*pbuf;
		uint32_t			len;
		uint32_t			dlen;
		std::atomic <int>		isvalid;
		int				cur_dyn_pkts;
		int				cur_dyn_buf_size;
		PKT_DYN_ELEM			*pdynhead;
		PKT_DYN_ELEM			*pdyntail;
	};

	/*
	 * bufcnt 			=> Number of Pool buffers
	 * maxbuflen 			=> Max Len of a single buffer
	 * max_dyn_buf_size		=> Max dynamic buffer allocation size in bytes used when the writer blocks as no buffers available (Ignored for multi_process)
	 * drop_dyn_sec			=> Seconds after which the writer may drop dynamic buffers (only used if max_dyn_buf_size > 0) in case it is blocking (0 => no drops)
	 * multi_process		=> Is this pool shared across processes
	 * is_single_writer		=> For single writers, atomic (semi lockfree) symantics will be used for the pool.
	 * pool_name			=> Pool Name / Identifier
	 * is_reader_rcu_thread		=> If true, each call to pool_read_buffer will first result in a rcu_thread_offline
	 * is_writer_rcu_thread		=> If true, each call to pool_write_buffer will first result in a rcu_thread_offline
	 * do_realloc			=> In case a pool write buffer size > Max Pool buffer size whether to realloc. Ignored for multi_process
	 * pfp, param			=> Specify Function Pointers which are called in case the pool writer blocks to check for errors.
	 * pext_bufalloc_fp		=> Function Pointer for external dynamic Buffer allocation (used only if max_dyn_buf_size)
	 * pext_buf_free_fp		=> Function Pointer for freeing the shared buffer.
	 */ 
	GY_PKT_POOL(uint32_t bufcnt, uint32_t maxbuflen,  uint32_t max_dyn_buf_size, uint32_t drop_dyn_sec, 
			int multi_process, int is_single_writer, const char *pool_name, bool is_reader_rcu_thread = false, 
			bool is_writer_rcu_thread = false, int do_realloc = 0, PKTPOOL_CHK_FP pfp = nullptr, void *chk_param = nullptr,
			PKTPOOL_BUF_ALLOC_FP pext_bufalloc_fp = nullptr, PKTPOOL_BUF_FREE_FP pext_buf_free_fp = nullptr);

	~GY_PKT_POOL();
		
	GY_PKT_POOL(const GY_PKT_POOL &other)			= delete;
	GY_PKT_POOL & operator= (const GY_PKT_POOL &other)	= delete;

	GY_PKT_POOL(GY_PKT_POOL && other)			= delete;
	GY_PKT_POOL & operator= (GY_PKT_POOL && other)		= delete;

	/*
	 * Write a single record from an iovec or a buffer with optional non blocking.
	 * The record to write can be split up from multiple buffers using the iovec.
	 *
	 * count is the max size of the record written to the pool. For e.g., 
	 * if the do_realloc is 1 in the constructor and the total record count is greater than
	 * maxbuflen, then a realloc is done to accomodate this record.
	 */ 
	PKT_RET_E 	pool_write_buffer(const struct iovec *piov, int iovcnt, uint32_t *count, int is_non_block) noexcept; 
	PKT_RET_E 	pool_write_buffer(const uint8_t *pbuf, uint32_t szbuf, uint32_t *count, int is_non_block) noexcept; 

	/*
	 * Read a single record into passed buf[] optional non-blocking. size is the max size of buf and count is the actual size of the
	 * record.
	 * max_wait_msec is considered only if is_non_block == 0
	 */ 
	PKT_RET_E 	pool_read_buffer(uint8_t *buf, uint32_t size, uint32_t *count, int is_non_block, uint32_t max_wait_msec = 0) noexcept;

	/*
	 * Zero copy (non-blocking) (but with mutex locking) version of pool write. Use this instead of 
	 * pool_write_buffer() in case you want to avoid an extra memcpy(). Users can get the
	 * pool buffer using pool_get_write_buf(), manipulate the buffer contents, and then
	 * call pool_save_write_buf() from the *same* thread to commit the record. If even the pthread mutex lock must not 
	 * block, specify is_non_block as true.
	 *
	 * XXX Note that the pool is locked once a valid buffer is returned till save is called. 
	 *
	 * NOTE : pool_save_write_buf() must be called only if PKT_RET_SUCCESS was returned in the get call.
	 *
	 * After calling pool_save_write_buf(), the buffer must NOT be
	 * modified externally. Also, the save method must be called only if
	 * get return PKT_RET_SUCCESS and from the same thread which invoked the get method. 
	 *
	 * The get method is non-blocking. Callers must check the return status. 
	 * In case PKT_BLOCKING is returned, caller would need to call 
	 * pool_write_buffer() instead if they need to have the pool updated.
	 */
	PKT_RET_E 	pool_get_write_buf(uint8_t **ppdatabuf, size_t *pbufsize, bool is_non_block = false) noexcept;
	PKT_RET_E 	pool_save_write_buf(uint8_t *pdatabuf, size_t nbytes) noexcept;

	/*
	 * Use either of the methods to signal to the pool reader to stop waiting for new data or 
	 * to signal to the writer to stop adding new data.
	 */ 
	void 		pool_set_wr_exited() noexcept;
	void 		pool_set_reset_signal() noexcept;

	/*
	 * pool_reset() should be called if you need to reset all buffers and start anew with/without
	 * reallocating. If the realloc_buf parameter is specified as 1, will cause existing buffers
	 * to be reallocated to newsz as well.
	 * If realloc_buf is 1 and this is a multi_process pool, then the new buffers reallocated
	 * will be visible to a child process started subsequently only...
	 */ 
	int 		pool_reset(int realloc_buf, uint32_t newsz) noexcept;
	
	/*
	 * This method is to be called only under special circumstances like a multi process pool
	 * and where one of the child processes does not need this pkt pools buffer info.
	 */ 
	int 		pool_release_mmap_buffers(void) noexcept;

	/*
	 * Print stats across 1 or more pool_resets()
	 */ 
	void 		print_cumul_stats(int is_unlocked) noexcept;

	bool		is_init() const noexcept
	{
		return (cmagic == PKT_POOL_MAGIC);
	}	

	/*
	 * Not atomic
	 */ 
	uint64_t	pending_records_for_read(void) const noexcept
	{
		int64_t diff1 = pkts_written - pkts_read;

		if (diff1 > 0) return diff1;
		return 0;
	}	

	static GY_PKT_POOL * alloc_shared_proc_pool(uint32_t bufcnt, uint32_t maxbuflen, bool is_single_writer, const char *pnamepool);
	
	static void dealloc_shared_proc_pool(GY_PKT_POOL * pshmpool, bool call_destructor = true, bool clear_internal_mem = true);	
};

} // namespace gyeeta

