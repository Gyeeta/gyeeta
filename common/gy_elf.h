//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

struct Elf;

namespace gyeeta {

class GY_ELF_UTIL
{
public :
	GY_ELF_UTIL(const char *pfile)
	{
		char			errorbuf[256];

		open_elf(pfile, nullptr, errorbuf);
	}

	// Will not throw exception on errors
	GY_ELF_UTIL(const char * pfile, int & retcode, char (&errorbuf)[256])
	{
		open_elf(pfile, &retcode, errorbuf);
	}

	// Will not throw exception on errors
	GY_ELF_UTIL(int fd, int & retcode, char (&errorbuf)[256])
	{
		open_elf_fd(fd, &retcode, errorbuf);
	}	

	~GY_ELF_UTIL() noexcept;
	
	GY_ELF_UTIL(const GY_ELF_UTIL &)			= delete;

	GY_ELF_UTIL & operator= (const GY_ELF_UTIL &)		= delete;

	GY_ELF_UTIL(GY_ELF_UTIL && other) noexcept
		: pelf_(std::exchange(other.pelf_, nullptr)), fd_(std::exchange(other.fd_, -1)),
		filetype_(other.filetype_), nhdrs_(other.nhdrs_), nstrsection_(other.nstrsection_), 
		filename_(std::move(other.filename_))
	{}

	GY_ELF_UTIL & operator= (GY_ELF_UTIL && other) noexcept
	{
		if (&other != this) {
			this->~GY_ELF_UTIL();

			new (this) GY_ELF_UTIL(std::move(other));
		}

		return *this;
	}	

	size_t 				find_func_offsets(const char *funcarr[], size_t nfuncs, off_t offsetarr[]) const;

	CHAR_BUF<256> 			get_buildid() const noexcept;
	
	bool				is_go_binary() const noexcept;
	
	size_t				get_dynamic_libs(STR_WR_BUF & strbuf) const noexcept;

	// Only if file path passed in constructor
	const char *			get_file_path() const noexcept
	{
		return filename_.data();
	}	

protected :

	void 				open_elf(const char *pfile, int *pretcode, char (&errorbuf)[256]);
	int 				open_elf_fd(int fd, int *pretcode, char (&errorbuf)[256], const char *pfile = nullptr);

	static constexpr const char	gnu_buildnote[] 	= ".note.gnu.build-id";
	static constexpr const char	go_buildnote[] 		= ".note.go.buildid";

	struct Elf			*pelf_			{nullptr};
	int				fd_			{-1};
	uint16_t			filetype_		{0};
	size_t				nhdrs_			{0};
	size_t				nstrsection_		{0};
	std::string			filename_;
};	




} // namespace gyeeta

