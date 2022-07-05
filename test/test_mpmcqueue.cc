
#include 		"gy_common_inc.h"
#include 		"gy_buf_serial.h"
#include 		"gy_msg_comm.h"
#include 		"gy_pkt_pool.h"
#include 		"gy_shmpool.h"

#pragma 		GCC diagnostic push
#pragma 		GCC diagnostic ignored "-Wsign-compare"

#include		"folly/MPMCQueue.h"
#include		"folly/concurrency/DynamicBoundedQueue.h"
#include		"folly/concurrency/UnboundedQueue.h"

#pragma 		GCC diagnostic pop

using namespace gyeeta;

static constexpr size_t		TMAX_ELEM = 1000, TMULTI = 100000;

using MPMCQ_COMM		= folly::MPMCQueue<COMM_MSG_C>;
using SPSCQUEUE			= folly::DynamicBoundedQueue<COMM_MSG_C, true, true, true>;
using MPSCQUEUE			= folly::DMPSCQueue<COMM_MSG_C, true>;
using MPMCQUEUE			= folly::DMPMCQueue<COMM_MSG_C, true>;
using USPSCQUEUE		= folly::USPSCQueue<COMM_MSG_C, true>;
using UMPSCQUEUE		= folly::UMPSCQueue<COMM_MSG_C, false, 4>;

class serial_str
{
	char		buf[128];
	size_t		slen		{0};
	
public :

	serial_str() noexcept		= default;

	serial_str(const std::string & str, const uint32_t max_sz, uint32_t & currsz) noexcept
	{
		slen = std::min((uint32_t)str.size(), max_sz);

		if (slen >= sizeof(buf)) {
			slen = sizeof(buf) - 1;
		}

		std::memcpy(buf, str.data(), slen);
		buf[slen] = '\0';

		currsz = slen + 1;
	}	

	serial_str(const uint8_t *pbuf, const uint32_t currsz) noexcept
	{
		slen = std::min(currsz, (uint32_t)sizeof(buf) - 1);
		std::memcpy(buf, pbuf, slen);
		buf[slen] = '\0';

		CONDEXEC(
			INFOPRINTCOLOR(GY_COLOR_GREEN, "serial_str from varbuf is %s\n", buf);
		);	
	}	

	const char *	get_buffer() const noexcept
	{
		return buf;
	}	

	size_t get_strlen() const noexcept
	{
		return slen;
	}	
};	


class SHM_POOL_CB
{
public :	
	uint64_t		skipped_bytes;
	uint8_t			is_peek;

	SHM_POOL_CB()  noexcept : skipped_bytes(0), is_peek(0) {}

	int operator()(char *pin, uint32_t lenin, void *poutarrin, uint32_t maxelem, uint32_t max_elem_size, void *parg, uint32_t *pcopied_elem) noexcept
	{
		uint32_t	origlen = lenin, nouts = 0, clen;
		int		len = (int)lenin;
		char		*porigin = pin, *ptmp, *pend;
		COMM_MSG_C	*poutarr = static_cast<COMM_MSG_C *>(poutarrin);

		ptmp = pin;
		pend = pin + lenin;

		while ((nouts < maxelem) && (len >= (int)sizeof(COMM_MSG_C)) && (ptmp < pend)) {
			memcpy(&poutarr[nouts], ptmp, sizeof(COMM_MSG_C));

			nouts++;
			len -= sizeof(COMM_MSG_C);
			ptmp += sizeof(COMM_MSG_C);
		}

	done :	
		*pcopied_elem = nouts;
		
		if (ptmp > pend) {
			ptmp = pend;
		}

		if (ptmp < pin) {
			ptmp = pin;
		}

		return ptmp - porigin;
	}
};

using TSHM_POOL				= SHM_POOL<SHM_POOL_CB>;

void * pool_thread(void * arg)
{
	GY_THREAD			*pthread = (GY_THREAD *)arg;
	GY_PKT_POOL			*pfuncpool = (GY_PKT_POOL *)pthread->get_opt_arg1();
	alignas (8) uint8_t		comm[sizeof(COMM_MSG_C)];
	COMM_MSG_C			*pcomm;
	PKT_RET_E 			retp;
	uint32_t			count;
	int				ret;
	min_max_counter<false>		tcounter;
	uint64_t			totalres, minres, maxres, iterval, tcurrnsec;
	double				avgres;

	do {
		retp = pfuncpool->pool_read_buffer(comm, sizeof(comm), &count, 0 /* is_non_block */);

		if (retp != PKT_RET_SUCCESS) {
			INFOPRINT("Pool Reader Thread %s exiting as writer seems to have exited.\n", pthread->get_description());

			tcounter.get_current(totalres, minres, maxres, iterval, avgres);

			INFOPRINTCOLOR(GY_COLOR_YELLOW, "Pool Reader %s : %lu Iterations completed : Min Response %lu nsec (%lu usec) Max %lu nsec (%lu usec) Avg %.3f nsec (%.3f usec)...\n", 
				pthread->get_description(), iterval, minres, minres/1000, maxres, maxres/1000, avgres, avgres/1000);
			
			break;
		}

		if (count < sizeof(COMM_MSG_C)) {
			ERRORPRINT("Internal Error (%u) : Invalid number of bytes %u from pool read\n", __LINE__, count); 
			continue;
		}

		pcomm = reinterpret_cast<COMM_MSG_C *>(comm);

		tcurrnsec = get_nsec_clock();

		assert(tcurrnsec >= pcomm->arg1_);

		tcounter.add(tcurrnsec - pcomm->arg1_);

	} while (1);

	return nullptr;
}	

void * mpmc_thread(void * arg)
{
	GY_THREAD			*pthread = (GY_THREAD *)arg;
	MPMCQ_COMM			*pfuncpool = (MPMCQ_COMM *)pthread->get_opt_arg1();
	COMM_MSG_C			comm;
	COMM_MSG_C			*pcomm;
	int				ret;
	min_max_counter<false>		tcounter;
	uint64_t			totalres, minres, maxres, iterval, tcurrnsec;
	double				avgres;

	do {
		pfuncpool->blockingRead(comm);

		tcurrnsec = get_nsec_clock();

		assert(tcurrnsec >= comm.arg1_);

		tcounter.add(tcurrnsec - comm.arg1_);

		if (comm.arg2_ == 1) {
			INFOPRINT("Reader Thread %s exiting as writer seems to have exited.\n", pthread->get_description());

			tcounter.get_current(totalres, minres, maxres, iterval, avgres);

			INFOPRINTCOLOR(GY_COLOR_YELLOW, "Reader %s : %lu Iterations completed : Min Response %lu nsec (%lu usec) Max %lu nsec (%lu usec) Avg %.3f nsec (%.3f usec)...\n", 
				pthread->get_description(), iterval, minres, minres/1000, maxres, maxres/1000, avgres, avgres/1000);
			
			break;
		}

	} while (1);

	return nullptr;
}	

template <typename T>
void * spsc_thread(void * arg)
{
	GY_THREAD			*pthread = (GY_THREAD *)arg;
	T				*pfuncpool = (T *)pthread->get_opt_arg1();
	COMM_MSG_C			comm;
	COMM_MSG_C			*pcomm;
	int				ret;
	min_max_counter<false>		tcounter;
	uint64_t			totalres, minres, maxres, iterval, tcurrnsec;
	double				avgres;

	do {
		pfuncpool->dequeue(comm);

		tcurrnsec = get_nsec_clock();

		assert(tcurrnsec >= comm.arg1_);

		tcounter.add(tcurrnsec - comm.arg1_);

		if (comm.arg2_ == 1) {
			INFOPRINT("Reader Thread %s exiting as writer seems to have exited.\n", pthread->get_description());

			tcounter.get_current(totalres, minres, maxres, iterval, avgres);

			INFOPRINTCOLOR(GY_COLOR_YELLOW, "Reader %s : %lu Iterations completed : Min Response %lu nsec (%lu usec) Max %lu nsec (%lu usec) Avg %.3f nsec (%.3f usec)...\n", 
				pthread->get_description(), iterval, minres, minres/1000, maxres, maxres/1000, avgres, avgres/1000);
			
			break;
		}

	} while (1);

	return nullptr;
}	

void * shm_thread(void * arg)
{
	GY_THREAD			*pthread = (GY_THREAD *)arg;
	TSHM_POOL			*pfuncpool = (TSHM_POOL *)pthread->get_opt_arg1();
	constexpr size_t		max_comms = 16;
	COMM_MSG_C			comm[16];
	COMM_MSG_C			*pcomm;
	int				ret;
	min_max_counter<false>		tcounter;
	uint64_t			totalres, minres, maxres, iterval, tcurrnsec, nrec = 0;
	uint32_t			ncopied, nbytes;
	double				avgres;

	do {
		ret = pfuncpool->read_pool(comm, max_comms, sizeof(*comm), nullptr, &ncopied, &nbytes);

		tcurrnsec = get_nsec_clock();

		if (ret != 0) {
			WARNPRINT("Shmpool Reader Thread read failed...\n");
			goto done;
		}

		for (uint32_t i = 0; i < ncopied; ++i) {
			assert(nrec++ == comm[i].arg3_);
			assert(tcurrnsec >= comm[i].arg1_);

			tcounter.add(tcurrnsec - comm[i].arg1_);

			if (comm[i].arg2_ == 1) {
				INFOPRINT("Reader Thread %s exiting as writer seems to have exited.\n", pthread->get_description());
				goto done;
			}
		}

	} while (1);

done :
	tcounter.get_current(totalres, minres, maxres, iterval, avgres);

	INFOPRINTCOLOR(GY_COLOR_YELLOW, "Reader %s : %lu Iterations completed : Min Response %lu nsec (%lu usec) Max %lu nsec (%lu usec) Avg %.3f nsec (%.3f usec)...\n", 
		pthread->get_description(), iterval, minres, minres/1000, maxres, maxres/1000, avgres, avgres/1000);
	
	return nullptr;
}	


int init_test()
{
	using VarBuf		= BUF_SERIALIZE<256>;
	using MPMCQ_SER		= folly::MPMCQueue<VarBuf>;

	MPMCQ_SER		que(10);
	
	char			buf1[128];
	bool			data_avail;
	std::string		t1("Init test of BUF_SERIALIZE");
	VarBuf			vbuf(t1, (serial_str *)nullptr);

	que.blockingWrite<const uint8_t *, size_t>(vbuf.get_data(), vbuf.get_curr_size());

	for (int i = 0; i < 20; i++) {
		
		snprintf(buf1, sizeof(buf1), "Iteration %d", i);

		std::string		s1(buf1);
		serial_str		*pdummy1 = nullptr;

		if (i < 5) {
			que.template blockingWrite<std::string, serial_str *>(std::move(s1), std::move(pdummy1));
		}
		else {
			data_avail = que.template write<std::string, serial_str *>(std::move(s1), std::move(pdummy1));
		}	

		assert(s1.size() == strlen(buf1));
	}

	int j = 0;

	do {

		BUF_SERIALIZE<256>	r1;
		
		if (j++ < 5) {
			que.blockingRead(r1);
			data_avail = true;
		}
		else {
			data_avail = que.read(r1);
		}
		if (data_avail) {
			serial_str		ser1(r1.get_data(), r1.get_curr_size());
		}	

	} while (data_avail);	

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now benchmarking GY_PKT_POOL single producer performance with writer blocks...\n");

		GY_PKT_POOL		spsc(TMAX_ELEM, sizeof(COMM_MSG_C), 0, 0, 0, 1 /* is_single_writer */, "spsc queue");
		GY_THREAD		pooltid("GY_PKT_POOL SPSC reader thread", pool_thread, &pooltid, &spsc);

		pooltid.set_thread_stop_function(
			[](void *arg) 
			{
				GY_PKT_POOL	*pspsc = (GY_PKT_POOL *)arg;

				pspsc->pool_set_wr_exited();
			}, &spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI; ++i) {
			COMM_MSG_C		tmsg;
			struct iovec		iov[1] = {{&tmsg, sizeof(tmsg)}};
			uint32_t		count;	
			PKT_RET_E		retp;

			tmsg.arg1_ = get_nsec_clock();

			retp = spsc.pool_write_buffer(iov, 1, &count, false /* is_nonblock */); 
			assert (retp == PKT_RET_SUCCESS);
		}	
	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Now benchmarking GY_PKT_POOL multi producer performance with writer blocks...\n");

		GY_PKT_POOL		mpsc(TMAX_ELEM, sizeof(COMM_MSG_C), 0, 0, 0, 0 /* is_single_writer */, "mpsc queue");
		GY_THREAD		pooltid("GY_PKT_POOL Multi producer reader thread", pool_thread, &pooltid, &mpsc);

		pooltid.set_thread_stop_function(
			[](void *arg) 
			{
				GY_PKT_POOL	*pmpsc = (GY_PKT_POOL *)arg;

				pmpsc->pool_set_wr_exited();
			}, &mpsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI; ++i) {
			COMM_MSG_C		tmsg;
			struct iovec		iov[1] = {{&tmsg, sizeof(tmsg)}};
			uint32_t		count;	
			PKT_RET_E		retp;

			tmsg.arg1_ = get_nsec_clock();

			retp = mpsc.pool_write_buffer(iov, 1, &count, false /* is_nonblock */); 
			assert (retp == PKT_RET_SUCCESS);
		}	
	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking folly::MPMCQueue 1 consumer performance with writer blocks...\n");

		MPMCQ_COMM		spsc(TMAX_ELEM);
		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI - 1; ++i) {
			COMM_MSG_C		tmsg;

			tmsg.arg1_ = get_nsec_clock();

			spsc.blockingWrite(std::move(tmsg));
		}	
		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(std::move(tmsg));

	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking folly::MPMCQueue 2 consumer performance with writer blocks...\n");

		MPMCQ_COMM		spsc(TMAX_ELEM);
		GY_THREAD		pooltid("MPMCQ_COMM folly::MPMCQueue reader thread", mpmc_thread, &pooltid, &spsc);
		GY_THREAD		pooltid2("MPMCQ_COMM folly::MPMCQueue 2 reader thread", mpmc_thread, &pooltid, &spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI - 1; ++i) {
			COMM_MSG_C		tmsg;

			tmsg.arg1_ = get_nsec_clock();

			spsc.blockingWrite(std::move(tmsg));
		}	
		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.blockingWrite(tmsg);
		spsc.blockingWrite(tmsg);

	}
	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking folly::DynamicBoundedQueue (SPSC) performance with writer blocks...\n");

		SPSCQUEUE		spsc(TMAX_ELEM);
		GY_THREAD		pooltid("SPSCQUEUE folly::DynamicBoundedQueue Pool reader thread", spsc_thread<SPSCQUEUE>, &pooltid, &spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI - 1; ++i) {
			COMM_MSG_C		tmsg;

			tmsg.arg1_ = get_nsec_clock();

			spsc.enqueue(std::move(tmsg));
		}	
		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.enqueue(std::move(tmsg));
	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking folly::DMPSCQueue (MPSC) performance with writer blocks...\n");

		MPSCQUEUE		spsc(TMAX_ELEM);
		GY_THREAD		pooltid("DMPSCQUEUE folly::DynamicBoundedQueue Pool reader thread", spsc_thread<MPSCQUEUE>, &pooltid, &spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI - 1; ++i) {
			COMM_MSG_C		tmsg;

			tmsg.arg1_ = get_nsec_clock();

			spsc.enqueue(std::move(tmsg));
		}	
		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.enqueue(std::move(tmsg));
	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking folly::DMPMCQueue (MPMC 2c) performance with writer blocks...\n");

		MPMCQUEUE		spsc(TMAX_ELEM);
		GY_THREAD		pooltid("DMPMCQUEUE folly::DynamicBoundedQueue Pool reader thread", spsc_thread<MPMCQUEUE>, &pooltid, &spsc);
		GY_THREAD		pooltid2("DMPMCQUEUE 2 folly::DynamicBoundedQueue Pool reader thread", spsc_thread<MPMCQUEUE>, &pooltid, &spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI - 1; ++i) {
			COMM_MSG_C		tmsg;

			tmsg.arg1_ = get_nsec_clock();

			spsc.enqueue(std::move(tmsg));
		}	
		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.enqueue(tmsg);
		spsc.enqueue(std::move(tmsg));
	}

	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking folly::UnboundedQueue (USPSC) performance with writer blocks...\n");

		USPSCQUEUE		spsc;
		GY_THREAD		pooltid("USPSCQUEUE folly::UnboundedQueue Pool reader thread", spsc_thread<USPSCQUEUE>, &pooltid, (void *)&spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI - 1; ++i) {
			COMM_MSG_C		tmsg;

			tmsg.arg1_ = get_nsec_clock();

			spsc.enqueue(std::move(tmsg));
		}	
		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.enqueue(std::move(tmsg));
	}
	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking folly::UnboundedQueue (UMPSC) performance with writer blocks...\n");

		UMPSCQUEUE		spsc;
		GY_THREAD		pooltid("UMPSCQUEUE folly::UnboundedQueue Pool reader thread", spsc_thread<UMPSCQUEUE>, &pooltid, (void *)&spsc);

		for (size_t i = 0; i < TMAX_ELEM * TMULTI - 1; ++i) {
			COMM_MSG_C		tmsg;

			tmsg.arg1_ = get_nsec_clock();

			spsc.enqueue(std::move(tmsg));
		}	
		COMM_MSG_C		tmsg;

		tmsg.arg1_ = get_nsec_clock();
		tmsg.arg2_ = 1;

		spsc.enqueue(std::move(tmsg));
	}
	{
		IRPRINT("\n\n");
		INFOPRINTCOLOR(GY_COLOR_YELLOW, "Now benchmarking Shmpool performance with writer blocks...\n");

	  	uint8_t			*ptmpalloc = nullptr;
	  	int			ret;
	
		// Using placement new as new will not allocate 128 byte aligned memory before C++17
		
		ret = posix_memalign((void **)&ptmpalloc, 128, sizeof(TSHM_POOL) + (TMAX_ELEM + 1) * sizeof(COMM_MSG_C) + 16);

		if (ret || !ptmpalloc) {
			errno = ret;
			GY_THROW_SYS_EXCEPTION("Failed to allocate memory for Shm Pool");
		}

	  	SHM_POOL_CB		fcb;
	 
	  	auto pshmpool = new (ptmpalloc) TSHM_POOL(sizeof(TSHM_POOL) + (TMAX_ELEM + 1) * sizeof(COMM_MSG_C), sizeof(COMM_MSG_C), 0, 0, 1, "shm pool spsc", fcb);
		
		GY_SCOPE_EXIT {
			pshmpool->~TSHM_POOL();
			free(ptmpalloc);
		};	

		GY_THREAD		pooltid("Shmpool reader thread", shm_thread, &pooltid, pshmpool);
		
		for (size_t i = 0; i < TMAX_ELEM * TMULTI; ++i) {
			COMM_MSG_C		tmsg;
			struct iovec		iov[1] = {{&tmsg, sizeof(tmsg)}};
			int			ret;	

			tmsg.arg1_ 	= get_nsec_clock();
			tmsg.arg2_	= (i == TMAX_ELEM * TMULTI ? 1 : 0);
			tmsg.arg3_	= i;
			
			do {
				ret = pshmpool->write_pool(iov, 1);
			} while (ret == 1);	
		}
	}	
	
	return 0;
}


int main(int argc, char **argv)
{
	int		ret;

	gdebugexecn = 10;

	ret = init_test();

	return ret;
}	
