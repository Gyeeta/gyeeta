//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma 			once

#include			"gy_common_inc.h"
#include 			"gy_net_parse.h"

#include 			"pcap/dlt.h"

namespace gyeeta {

static constexpr int		GY_TCPDUMP_MAGIC  = 0xa1b2c3d4;
static constexpr int		GY_PCAP_VERSION_MAJOR = 2;
static constexpr int		GY_PCAP_VERSION_MINOR = 4;

struct PCAP_FILE_HEADER 
{
	uint32_t 		magic;
	uint16_t 		version_major;
	uint16_t 		version_minor;
	int 			thiszone;	/* gmt to local correction */
	uint32_t 		sigfigs;	/* accuracy of timestamps */
	uint32_t 		snaplen;	/* max length saved portion of each pkt */
	uint32_t 		linktype;	/* data link type (LINKTYPE_*) */

} __attribute__((packed));

/*
 * This is a timeval as stored in disk in a dumpfile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'
 */
struct PCAP_TIMEVAL 
{
	int			tv_sec;		/* seconds */
	int			tv_usec;	/* microseconds */
} __attribute__((packed));

struct PCAP_REC_HEADER 
{
	PCAP_TIMEVAL		ts;		/* time stamp */
	uint32_t		caplen;		/* length of portion present */
	uint32_t		len;		/* length this packet (off wire) */

} __attribute__((packed));


class PCAP_READER
{
public :	
	enum {
		HDR_NOT_SWAPPED,
		HDR_SWAPPED,
		HDR_MAYBE_SWAPPED
	};

	char				filepath_[512] 			{};
	FILE				*pfp_pcap_ 			{nullptr};
	int				snaplen_ 			{0};
	int				linktype_ 			{0};
	int				tzoff_ 				{0};		
	int				offset_ 			{0};		/* offset for proper alignment */

	bool				use_unlocked_ 			{false};
	uint8_t				*palloc_buf_ 			{nullptr};
	uint8_t				*preadbuf_ 			{nullptr};

	uint32_t			alignlen_ 			{0};

	int64_t				npkts_read_ 			{0};
	int64_t				nbytes_read_ 			{0};

	bool				hdr_swapped_ 			{false};
	int				length_swapped_ 		{0};

	PCAP_FILE_HEADER		pcap_header_			{};

	static constexpr uint32_t	max_buffer_size_ 		{256 * 1024}; 
	
	explicit PCAP_READER(const char *pfilename, bool use_unlocked_io = true);
	
	~PCAP_READER() noexcept
	{
		DEBUGEXECN(10, INFOPRINTCOLOR(GY_COLOR_GREEN_ITALIC, "pcap read completed for file %s : Total Packets Read %ld Total Bytes Read %ld\n",
			filepath_, npkts_read_, nbytes_read_););

		if (pfp_pcap_) {
			fclose(pfp_pcap_);
			pfp_pcap_ = nullptr;
		}
			
		if (palloc_buf_) {
			free(palloc_buf_);
			palloc_buf_ = nullptr;
		}	
	}	

	uint8_t *  read_next_pcap_pkt(struct timeval & tv_pkt, uint32_t & caplen, uint32_t & origlen, uint8_t *preadbuf = nullptr, uint32_t max_len = 65535) noexcept;

	int set_pcap_file_offset(off_t newoff) noexcept
	{
		return fseeko(pfp_pcap_, newoff, SEEK_SET);
	}
		
	int get_linktype() const noexcept
	{
		return linktype_;
	}				

	FILE * get_pcap_file() noexcept
	{
		return pfp_pcap_;
	}	

	int get_alignlen() const noexcept
	{
		return alignlen_;
	}
		
	int update_rec_hdr(PCAP_REC_HEADER *phdr) const noexcept
	{
		uint32_t 		t;

		if (hdr_swapped_) {
			swap_pkthdr(phdr);
		} 

		/* Swap the caplen and len fields, if necessary. */
		switch (length_swapped_) {

		case HDR_NOT_SWAPPED:
			break;

		case HDR_MAYBE_SWAPPED:
			if (phdr->caplen <= phdr->len) {
				/*
				 * The captured length is <= the actual length, so presumably they weren't swapped.
				 */
				break;
			}
			/* fallthrough */

		case HDR_SWAPPED:
			t = phdr->caplen;
			phdr->caplen = phdr->len;
			phdr->len = t;
			break;
		}

		if (phdr->caplen > max_buffer_size_) {
			return -1;
		}

		return 0;
	}	

	static void swap_pkthdr(PCAP_REC_HEADER *ph) noexcept
	{
		ph->caplen 		= GY_SWAP_32(ph->caplen);
		ph->len 		= GY_SWAP_32(ph->len);
		ph->ts.tv_sec 		= GY_SWAP_32(ph->ts.tv_sec);
		ph->ts.tv_usec 		= GY_SWAP_32(ph->ts.tv_usec);
	}


	static void swap_pcap_hdr(PCAP_FILE_HEADER *hp) noexcept
	{
		hp->magic		= GY_SWAP_32(hp->magic);
		hp->version_major 	= GY_SWAP_16(hp->version_major);
		hp->version_minor 	= GY_SWAP_16(hp->version_minor);
		hp->thiszone 		= GY_SWAP_32(hp->thiszone);
		hp->sigfigs 		= GY_SWAP_32(hp->sigfigs);
		hp->snaplen 		= GY_SWAP_32(hp->snaplen);
		hp->linktype 		= GY_SWAP_32(hp->linktype);
	}
	
};

} // namespace gyeeta
