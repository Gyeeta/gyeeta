//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include			"gy_common_inc.h"
#include			"gy_scheduler.h"

#include 			"bpf/libbpf.h"
#include 			"bpf/bpf.h"

extern "C" {

#include 			"btf_helpers.h"
#include 			"trace_helpers.h"

}

/*
 * C++ wrappers for libbpf
 */

namespace gyeeta {

typedef void (*GY_EBPF_CB)(void *pcb_cookie, void *pdata, uint32_t data_size);
typedef void (*GY_EBPF_LOST_CB)(void *pcb_cookie, uint64_t cnt);

class GY_BTF_INIT
{	
public :
	GY_BTF_INIT(libbpf_print_fn_t printfn = nullptr);
		
};

template <typename T>
class GY_LIBBPF_OBJ
{
public :	
	GY_LIBBPF_OBJ(const char *name, const struct bpf_object_open_opts *opts = nullptr)
		: name_(name)
	{
		LIBBPF_OPTS(bpf_object_open_opts, open_opts);
		
		if (!opts) {
			open_opts_ = open_opts;
		}
		else {
			open_opts_ = *opts;
		}	

		pobj_ = T::open(&open_opts_);

		if (!pobj_) {
			GY_THROW_SYS_EXCEPTION("Failed to open BPF Object %s", name_.data());
		}	
	}

	~GY_LIBBPF_OBJ() noexcept
	{
		T::destroy(pobj_);
		cleanup_core_btf(&open_opts_);
	}	

	T * get() noexcept
	{
		return pobj_;
	}	

	void load_bpf()
	{
		int			ret;

		ret = T::load(pobj_);

		if (ret) {
			GY_THROW_SYS_EXCEPTION("Failed to load BPF Object %s", name_.data());
		}	
	}	

	void attach_bpf()
	{
		int			ret;

		ret = T::attach(pobj_);

		if (ret) {
			GY_THROW_SYS_EXCEPTION("Failed to attach BPF Object %s", name_.data());
		}	
	}	

	void detach_bpf()
	{
		int			ret;

		ret = T::detach(pobj_);

		if (ret) {
			GY_THROW_SYS_EXCEPTION("Failed to detach BPF Object %s", name_.data());
		}	
	}	
	
	static std::string_view elf_bytes() noexcept
	{
		size_t			sz;
		const char		*pbytes = (const char *)T::elf_bytes(&sz);

		return {pbytes, sz};
	}	

	bpf_object_open_opts		open_opts_		{};	
	T				*pobj_			{nullptr};
	std::string			name_;
};	

class GY_PERF_BUFPOOL
{
public :
	GY_PERF_BUFPOOL(const char *name, int map_fd, size_t page_cnt, GY_EBPF_CB cb, void *pcb_cookie = nullptr, GY_EBPF_LOST_CB lost_cb = nullptr, GY_SCHEDULER * plost_cb_scheduler = nullptr);

	~GY_PERF_BUFPOOL() noexcept;

	int poll(int timeout_ms, bool *pis_more_data = nullptr)
	{
		return perf_buffer__poll_more(pbufpool_, timeout_ms, pis_more_data);
	}	

	perf_buffer * get_perf_buffer() const noexcept
	{
		return pbufpool_;
	}	

	size_t get_lost_events() const noexcept
	{
		return nlost_;
	}	

	perf_buffer			*pbufpool_		{nullptr};
	GY_EBPF_CB			cb_			{nullptr};
	void				*pcb_cookie_		{nullptr};
	GY_EBPF_LOST_CB			lost_cb_		{nullptr};
	size_t				nlost_			{0};
	std::string			name_;
	GY_SCHEDULER			*plost_cb_scheduler_	{nullptr};
};	

class GY_RING_BUFPOOL
{
public :
	GY_RING_BUFPOOL(const char *name, int map_fd, GY_EBPF_CB cb, void *pcb_cookie = nullptr);

	~GY_RING_BUFPOOL() noexcept
	{
		ring_buffer__free(pbufpool_);
	}	

	int poll(int timeout_ms, bool *pis_more_data = nullptr)
	{
		return ring_buffer__poll_more(pbufpool_, timeout_ms, pis_more_data);
	}	

	ring_buffer * get_ring_buffer() const noexcept
	{
		return pbufpool_;
	}	

	ring_buffer			*pbufpool_		{nullptr};
	GY_EBPF_CB			cb_			{nullptr};
	void				*pcb_cookie_		{nullptr};
};	



} // namespace gyeeta

