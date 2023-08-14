//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_elf.h"

#include 			<gelf.h>

namespace gyeeta {

void GY_ELF_UTIL::open_elf(const char *pfile, int *pretcode)
{
	SCOPE_FD		sfd(pfile, O_RDONLY);
	int			fd = sfd.get(), ret;

	if (fd < 0) {
		if (pretcode) {
			*pretcode = -1;
			return;
		}	

		GY_THROW_EXPRESSION("Failed to open ELF file %s", pfile);
	}	
	
	ret = open_elf_fd(fd, pretcode, pfile);
	if (ret != 0) {
		return;
	}	

	fd_ = sfd.release();
}	

int GY_ELF_UTIL::open_elf_fd(int fd, int *pretcode, const char *pfile)
{
	if (elf_version(EV_CURRENT) == EV_NONE) {
		if (pretcode) {
			*pretcode = -1;
			return -1;
		}	
		
		GY_THROW_EXPRESSION("ELF Utils initialization failed");
	}

	Elf			*e;

	e = elf_begin(fd, ELF_C_READ, nullptr);
	if (!e) {
		if (pretcode) {
			*pretcode = -1;
			return -1;
		}

		GY_THROW_EXPRESSION("Failed to create elf struct : %s", elf_errmsg(-1));
	}

	GY_SCOPE_EXIT {
		if (e) {
			elf_end(e);
		}	
	};	

	if (elf_kind(e) != ELF_K_ELF) {
		if (pretcode) {
			*pretcode = -1;
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not a valid elf file", pfile ? pfile : "");
	}

	GElf_Ehdr 		ehdr;
	size_t 			shstrndx, nhdrs;

	if (!gelf_getehdr(e, &ehdr)) {
		if (pretcode) {
			*pretcode = -1;
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not a valid elf file due to mising object file header", pfile ? pfile : "");
	}	

	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		if (pretcode) {
			*pretcode = -1;
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not a valid elf file due to mising sections", pfile ? pfile : "");
	}	

	if (elf_getphdrnum(e, &nhdrs) != 0) {
		if (pretcode) {
			*pretcode = -1;
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not handled as elf file has missing program headers", pfile ? pfile : "");
	}

	if (!(ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN)) {
		if (pretcode) {
			*pretcode = -1;
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not handled as only ELF binaries or Shared Libs handled", pfile ? pfile : "");
	}

	pelf_			= std::exchange(e, nullptr);
	filetype_ 		= ehdr.e_type;
	nstrsection_		= shstrndx;

	if (pfile) {
		filename_	= pfile;
	}	

	return 0;
}	

GY_ELF_UTIL::~GY_ELF_UTIL() noexcept
{
	if (pelf_) {
		elf_end(pelf_);
	}	

	if (fd_ >= 0) {
		close(fd_);
	}	
}	

CHAR_BUF<256> GY_ELF_UTIL::get_buildid() const noexcept
{
	static constexpr const char	buildsection[] = ".note.gnu.build-id";

	CHAR_BUF<256>			barr;
	char				tbuf[256];
	int 				scn_no = 0;
	size_t 				notesz, offset = 0;
	Elf_Data 			*data;
	Elf_Scn 			*scn = nullptr;
	GElf_Shdr 			shdr_data, *shdrp = &shdr_data;

	do {
		GElf_Shdr 		*shdr;
		const char		*pname;

		scn = elf_getscn(pelf_, ++scn_no);
		if (!scn) {
			return barr;
		}	

		shdr = gelf_getshdr(scn, shdrp);
		if (!shdr) {
			continue;
		}	

		pname = elf_strptr(pelf_, nstrsection_, shdr->sh_name);
		if (pname && 0 == strcmp(pname, buildsection)) {
			break;
		}	

	} while (scn != nullptr);

	if (!scn) {
		return barr;
	}	

	data = elf_getdata(scn, nullptr);
	if (!data) {
		return barr;
	}	

	do {
		size_t 				nameoff, descoff, tsz;
		GElf_Nhdr 			nhdr;
		const char 			*name;

		notesz = gelf_getnote(data, offset, &nhdr, &nameoff, &descoff);
		if (!notesz) {
			break;
		}

		offset += notesz;

		if (nhdr.n_type != NT_GNU_BUILD_ID) {
			continue;
		}	

		name = (const char *)data->d_buf + nameoff;
		if (!name || strcmp(name, ELF_NOTE_GNU)) {
			continue;
		}	

		tsz = binary_to_hex_string((const uint8_t *)data->d_buf + descoff, nhdr.n_descsz, tbuf, sizeof(tbuf));

		barr.setbuf(tbuf, tsz);

		break;

	} while (notesz);

	return barr;
}	


} // namespace gyeeta

