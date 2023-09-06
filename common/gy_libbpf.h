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

typedef void (*GY_EBPF_CB)(void *pcb_cookie, void *pdata, int data_size) noexcept;
typedef void (*GY_EBPF_LOST_CB)(void *pcb_cookie, uint64_t cnt) noexcept;

class GY_BTF_INIT
{	
public :
	GY_BTF_INIT(libbpf_print_fn_t printfn = nullptr);
		
};

template <typename T>
void gy_bpf_type_destroy(T *pdata) noexcept
{
	if constexpr(std::is_same_v<T, bpf_link>) {
		if (pdata) bpf_link__destroy(pdata);
	}
	else if constexpr(std::is_same_v<T, bpf_object_skeleton>) {
		if (pdata) bpf_object__destroy_skeleton(pdata);
	}	
	else if constexpr(std::is_same_v<T, bpf_object_subskeleton>) {
		if (pdata) bpf_object__destroy_subskeleton(pdata);
	}	
}	

using UNIQ_BPF_LINK_PTR 	= FUNC_DELETE_PTR<bpf_link, gy_bpf_type_destroy<bpf_link>>;
using UNIQ_BPF_SKEL_PTR 	= FUNC_DELETE_PTR<bpf_object_skeleton, gy_bpf_type_destroy<bpf_object_skeleton>>;
using UNIQ_BPF_SUBSKEL_PTR 	= FUNC_DELETE_PTR<bpf_object_subskeleton, gy_bpf_type_destroy<bpf_object_subskeleton>>;


template <typename T>
class GY_LIBBPF_OBJ
{
public :	
	GY_LIBBPF_OBJ(const char *name, const struct bpf_object_open_opts *opts = nullptr)
		: name_(name ? name : "libbpf object")
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

	T * get() const noexcept
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
		T::detach(pobj_);
	}	
	
	static std::string_view elf_bytes()
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

	int poll(int timeout_ms, bool *pis_more_data = nullptr) const noexcept
	{
		return perf_buffer__poll_more(pbufpool_, timeout_ms, pis_more_data);
	}	

	// For compatability with bcc
	int poll(int timeout_ms, bool *pis_more_data, pid_t unused) const noexcept
	{
		return this->poll(timeout_ms, pis_more_data);
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
	mutable size_t			nlost_			{0};
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

	int poll(int timeout_ms, bool *pis_more_data = nullptr) const noexcept
	{
		return ring_buffer__poll_more(pbufpool_, timeout_ms, pis_more_data);
	}	

	// For compatability with perf buffer pool
	int poll(int timeout_ms, bool *pis_more_data, pid_t unused) const noexcept
	{
		return this->poll(timeout_ms, pis_more_data);
	}

	ring_buffer * get_ring_buffer() const noexcept
	{
		return pbufpool_;
	}	

	ring_buffer			*pbufpool_		{nullptr};
	GY_EBPF_CB			cb_			{nullptr};
	void				*pcb_cookie_		{nullptr};
};	

/*
 * XXX Do not call bpf_map_delete_elem() in the walk callback. Call delete after the walk is over...
 */
template <typename FCB> 
int walk_bpf_map_keys(int map_fd, uint32_t key_size, const void *invalid_key, FCB & walk) noexcept(noexcept(walk(nullptr, 0)))
{
	alignas(8) uint8_t		key[key_size], next_key[key_size];
	uint32_t			cnt, tcnt = 0, n0 = 0;
	int				err;
	CB_RET_E			cret;

	if (map_fd < 0 || !invalid_key) {
		return -1;
	}

	memcpy(key, invalid_key, key_size);

	while (true) {
		err = bpf_map_get_next_key(map_fd, key, next_key);

		if (err && errno != ENOENT) {
			return -1;
		} 
		else if (err) {
			return tcnt;
		}

		memcpy(key, next_key, key_size);

		cret = walk((void *)key, tcnt++);

		if (cret == CB_BREAK_LOOP) {
			return tcnt;
		}	
	}

	return tcnt;
}

} // namespace gyeeta

