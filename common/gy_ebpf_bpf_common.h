
#ifndef				_GY_EBPF_BPF_COMMON_H
#define				_GY_EBPF_BPF_COMMON_H

#if				defined (BCC_SEC) && !defined (__BCC__)

#define 			__BCC__

#endif

#ifndef 			AF_INET

#define 			AF_INET			2		/* IPv4	*/
#define 			AF_INET6		10		/* IPv6	*/

#endif

typedef uint8_t 		u8;
typedef uint16_t 		u16;
typedef uint32_t 		u32;
typedef uint64_t 		u64;

struct ipv4_tuple_t 
{
	u32 			saddr;
	u32 			daddr;
	u32 			netns;
	u16 			sport;
	u16 			dport;
};

struct ipv6_tuple_t 
{
	unsigned __int128 	saddr;
	unsigned __int128 	daddr;
	u32 			netns;
	u16 			sport;
	u16 			dport;
};

#if				defined (__clang__) && defined (__BPF__)

// TCP Flags 

#define				GY_TH_FIN		0x01
#define				GY_TH_SYN		0x02
#define				GY_TH_RST		0x04
#define				GY_TH_PUSH		0x08
#define				GY_TH_ACK		0x10
#define				GY_TH_URG		0x20
#define				GY_TH_ECE		0x40
#define				GY_TH_CWR		0x80

#endif

#if				defined (__clang__) && defined (__BPF__) && !defined (__BCC__)

#ifdef GY_BPF_DEBUG

#define				gy_bpf_printk(fmt, args...) bpf_printk(fmt, ##args)

#else

#define 			gy_bpf_printk(fmt, args...)

#endif


static int read_ipv4_tuple(struct ipv4_tuple_t *tuple, struct sock *skp)
{
	u32 			net_ns_inum = 0, saddr, daddr;
	struct inet_sock 	*sockp;
	u16 			sport, dport;

	saddr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
	daddr = BPF_CORE_READ(skp, __sk_common.skc_daddr);

	sockp = (struct inet_sock *)skp;

	BPF_CORE_READ_INTO(&sport, sockp, inet_sport);
	BPF_CORE_READ_INTO(&dport, skp, __sk_common.skc_dport);

	if (bpf_core_field_exists(skp->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&net_ns_inum, skp, __sk_common.skc_net.net, ns.inum);
	}

	tuple->saddr = saddr;
	tuple->daddr = daddr;
	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;
	
	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

static int read_ipv6_tuple(struct ipv6_tuple_t *tuple, struct sock *skp)
{
	u32 			net_ns_inum = 0;
	struct inet_sock 	*sockp = (struct inet_sock *)skp;
	u16 			sport;
	u16 			dport;

	BPF_CORE_READ_INTO(&sport, sockp, inet_sport);
	BPF_CORE_READ_INTO(&dport, skp, __sk_common.skc_dport);

	if (bpf_core_field_exists(skp->__sk_common.skc_net)) {
		BPF_CORE_READ_INTO(&net_ns_inum, skp, __sk_common.skc_net.net, ns.inum);
	}

	BPF_CORE_READ_INTO(&tuple->saddr, skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&tuple->daddr, skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32);

	tuple->sport = sport;
	tuple->dport = dport;
	tuple->netns = net_ns_inum;

	// if addresses or ports are 0, ignore
	if (tuple->saddr == 0 || tuple->daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}

	return 1;
}

static __always_inline bool check_family(struct sock *sk, u16 expected_family) 
{
	u16 			family;
	
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	return (family == expected_family);
}

static __always_inline bool is_ipv4_mapped_ipv6(unsigned __int128 ip128_be)
{
	u8 			*pipbuf = (u8 *)&ip128_be;

	if (
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__		
		(0 == (ip128_be >> 64ull))  
#else
		(0 == (ip128_be & ~0ull))  
#endif		
			
		&& (0 == __builtin_memcmp(pipbuf + 8, "\x0\x0\xff\xff", 4))) {

		return true;
	}

	return false;	
}

static __always_inline uint64_t align_up_8(uint64_t nsize)
{
	return ((nsize - 1) & ~7) + 8;
}

#endif // defined (__clang__) && defined (__BPF__)

#endif


