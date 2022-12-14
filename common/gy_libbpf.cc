
#include			"gy_libbpf.h"

#include 			<sys/resource.h>

namespace gyeeta {

static int dflt_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && gdebugexecn == 0) {
		return 0;
	}	
	
	char				stimebuf[64];
	const char			*plevel;

	switch (level) {
	
	case LIBBPF_DEBUG 	:	plevel = "DEBUG"; break;
	case LIBBPF_WARN 	:	plevel = "WARN"; break;
	case LIBBPF_INFO 	:	plevel = "INFO"; break;

	default			:	plevel = "ERROR"; break;
	}	

	fprintf(stderr, "[%s]:[%s]: ", gy_time_print(stimebuf, sizeof(stimebuf)).first, plevel);

	return vfprintf(stderr, format, args);
}

static void perf_cb_fn(void *pctx, int cpu, void *data, uint32_t size) noexcept
{
	GY_PERF_BUFPOOL			*pbufpool = (GY_PERF_BUFPOOL *)pctx;

	if (!pbufpool) {
		return;
	}

	pbufpool->cb_(pbufpool->pcb_cookie_, data, size);
}

static void perf_lost_cb_fn(void *pctx, int cpu, long long unsigned int cnt) noexcept
{
	GY_PERF_BUFPOOL			*pbufpool = (GY_PERF_BUFPOOL *)pctx;

	if (!pbufpool) {
		return;
	}

	pbufpool->nlost_ += cnt;

	if (pbufpool->lost_cb_) {
		(*pbufpool->lost_cb_)(pbufpool->pcb_cookie_, cnt);
	}	
}


static int ring_cb_fn(void *pctx, void *data, uint64_t size) noexcept
{
	GY_RING_BUFPOOL			*pbufpool = (GY_RING_BUFPOOL *)pctx;

	if (!pbufpool) {
		return -1;
	}

	pbufpool->cb_(pbufpool->pcb_cookie_, data, size);

	return 0;
}


GY_BTF_INIT::GY_BTF_INIT(libbpf_print_fn_t printfn)
{
	if (!vmlinux_btf_exists()) {
		GY_THROW_EXCEPTION("BPF BTF Mode not supported");
	}	

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20, /* 512 MB */
		.rlim_max = 512UL << 20, /* 512 MB */
	};

	int			err;
	
	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		GY_THROW_SYS_EXCEPTION("Failed to set ebpf max lock memory");
	}	

	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (printfn == nullptr) {
		printfn = dflt_print_fn;
	}	

	libbpf_set_print(printfn);
}

GY_PERF_BUFPOOL::GY_PERF_BUFPOOL(const char *name, int map_fd, size_t page_cnt, GY_EBPF_CB cb, void *pcb_cookie, GY_EBPF_LOST_CB lost_cb, GY_SCHEDULER * plost_cb_scheduler)
	: cb_(cb), pcb_cookie_(pcb_cookie), lost_cb_(lost_cb), name_(name ? name : "perf buffer pool"), plost_cb_scheduler_(plost_cb_scheduler)
{
	pbufpool_ = perf_buffer__new(map_fd, page_cnt, perf_cb_fn, perf_lost_cb_fn, this, nullptr);

	if (!pbufpool_) {
		GY_THROW_SYS_EXCEPTION("Failed to create %s perf buffer pool", name ? name : "");
	}

	if (plost_cb_scheduler_ && name) {
		plost_cb_scheduler_->add_schedule(10'000, 30'000, 0, name, 
			[this, last_cnt = 0lu]() mutable 
			{
				if (nlost_ != last_cnt) {
					WARNPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "%s Perf Buffer : Missed %lu events in last 30 sec : Total missed count %lu\n",
						name_.data(), nlost_ - last_cnt, nlost_);
					
					last_cnt = nlost_;
				}	
			}, false);	
	}	
}


GY_PERF_BUFPOOL::~GY_PERF_BUFPOOL() noexcept
{
	if (plost_cb_scheduler_ && name_.size()) {
		plost_cb_scheduler_->cancel_schedule(name_.data(), true);
	}	
	
	perf_buffer__free(pbufpool_);
}	


GY_RING_BUFPOOL::GY_RING_BUFPOOL(const char *name, int map_fd, GY_EBPF_CB cb, void *pcb_cookie)
	: cb_(cb), pcb_cookie_(pcb_cookie)
{
	pbufpool_ = ring_buffer__new(map_fd, ring_cb_fn, this, nullptr);

	if (!pbufpool_) {
		GY_THROW_SYS_EXCEPTION("Failed to create %s ring buffer pool", name ? name : "");
	}
}

}

