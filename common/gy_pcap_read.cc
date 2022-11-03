//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_pcap_read.h"

namespace gyeeta {


PCAP_READER::PCAP_READER(const char *pfilename, bool use_unlocked_io)
{
	int 			fd, ret, linklen;

	fd = open(pfilename, O_RDONLY | O_NOATIME);

	if ((fd == -1) && (errno == EPERM)) {
		fd = open(pfilename, O_RDONLY);
	}

	if (fd == -1) {
		GY_THROW_SYS_EXCEPTION("pcap file %s : open failed", pfilename);
	}

	GY_SCOPE_EXIT {
		if (fd > 0) (void)close(fd);
	};

	posix_fadvise(fd, 24, 0L, POSIX_FADV_SEQUENTIAL);
	
	GY_STRNCPY(filepath_, pfilename, sizeof(filepath_));
	
	ret = read(fd, &pcap_header_, sizeof(pcap_header_));

	if (ret != sizeof(pcap_header_)) {
		if (ret >= 0) {
			GY_THROW_EXCEPTION("File %s not in pcap format", pfilename);
		}
		GY_THROW_SYS_EXCEPTION("File %s read failed", pfilename);
	}
	
	nbytes_read_ = sizeof(pcap_header_);

	if ((int)pcap_header_.magic != GY_TCPDUMP_MAGIC) {
		int32_t	tmagic = GY_SWAP_32(pcap_header_.magic);
		
		if (tmagic != GY_TCPDUMP_MAGIC) {
			GY_THROW_EXCEPTION("File %s not in pcap format", pfilename);	
		}		

		hdr_swapped_ = true;
		
		swap_pcap_hdr(&pcap_header_);
	}	

	snaplen_ 	= pcap_header_.snaplen;
	tzoff_		= pcap_header_.thiszone;
	linktype_	= pcap_header_.linktype;
	
	switch (linktype_) {

	case DLT_EN10MB:
		linklen = 14;
		alignlen_ = 2;
		break;

	case DLT_IEEE802 :
	case DLT_NULL:
	case DLT_LOOP :
	case DLT_LINUX_SLL :
	case DLT_RAW :
	case DLT_IPNET :
		linklen = 0;
		alignlen_ = 0;
		break;

	default:
		GY_THROW_EXCEPTION("pcap file %s Link type %d not yet handled", pfilename, linktype_);
		break;
	}

	if (pcap_header_.version_major < GY_PCAP_VERSION_MAJOR) {
		GY_THROW_EXCEPTION("File %s not in an archaic pcap format", pfilename);	
	}	

	pfp_pcap_ = fdopen(fd, "r");
	if (!pfp_pcap_) {
		GY_THROW_SYS_EXCEPTION("pcap file %s fdopen failed", pfilename);
	}	

	use_unlocked_ 	= use_unlocked_io;

	if (use_unlocked_io) {
		__fsetlocking(pfp_pcap_, FSETLOCKING_BYCALLER);
	}

	palloc_buf_ = (uint8_t *)malloc(max_buffer_size_ + sizeof(uint64_t));
	if (!palloc_buf_) {
		int		olderrno = errno;

		fclose(pfp_pcap_);
		errno = olderrno;

		GY_THROW_SYS_EXCEPTION("Failed to allocate memory for pcap read buffer");
	}	

	preadbuf_ = palloc_buf_ + sizeof(uint64_t) - (linklen % sizeof(uint32_t));
	
	switch (pcap_header_.version_major) {

	case 2:
		if (pcap_header_.version_minor < 3) length_swapped_ = HDR_SWAPPED;
		else if (pcap_header_.version_minor == 3) length_swapped_ = HDR_MAYBE_SWAPPED;
		else length_swapped_ = HDR_NOT_SWAPPED;
		break;

	case 543:
		length_swapped_ = HDR_SWAPPED;
		break;

	default:
		length_swapped_ = HDR_NOT_SWAPPED;
		break;
	}

	DEBUGEXECN(1, 
		struct stat		stat1;
		
		fstat(fd, &stat1);

		INFOPRINTCOLOR(GY_COLOR_GREEN_ITALIC, "Starting pcap read for file %s of size %lu (%lu MB)\n",
			filepath_, stat1.st_size, GY_DOWN_MB(stat1.st_size));
	);

	fd = -1;
}	


uint8_t *  PCAP_READER::read_next_pcap_pkt(struct timeval & tv_pkt, uint32_t & caplen, uint32_t & origlen, uint8_t *preadbufin, uint32_t max_len) noexcept
{
	PCAP_REC_HEADER			hdr;
	int				ret;
	uint8_t				*preadbuf;
	uint32_t			nbytes, extra_seek_len;

	if (preadbufin == nullptr) {
		preadbuf = preadbuf_;
	}
	else {
		preadbuf = preadbufin;	
	}		

	if (max_len > max_buffer_size_) max_len = max_buffer_size_;

	ret = fread(&hdr, 1, sizeof(hdr), pfp_pcap_);
	if (ret != sizeof(hdr)) {
		return nullptr;
	}	

	ret = update_rec_hdr(&hdr);
	if (ret != 0) {
		return nullptr;
	}	

	nbytes	= hdr.caplen;

	if (max_len < nbytes) {
		extra_seek_len = nbytes - max_len;
		nbytes 	= max_len;
	}	
	else {
		extra_seek_len = 0;
	}	

	if (nbytes > 0) {
		ret = fread(preadbuf, 1, nbytes, pfp_pcap_);
		if (ret != (int)nbytes) {
			return nullptr;
		}	
	}

	if (extra_seek_len) {
		fseeko(pfp_pcap_, extra_seek_len, SEEK_CUR);
	}	

	caplen 		= nbytes;
	origlen		= hdr.len;

	tv_pkt.tv_sec = hdr.ts.tv_sec;
	tv_pkt.tv_usec = hdr.ts.tv_usec;

	npkts_read_++;
	nbytes_read_ += hdr.caplen;	

	return preadbuf;
}	


} // namespace gyeeta

