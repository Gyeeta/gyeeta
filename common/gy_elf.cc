//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_elf.h"
#include			"gy_folly_stack_map.h"

#include 			<gelf.h>

namespace gyeeta {

void GY_ELF_UTIL::open_elf(const char *pfile, int *pretcode, char (&errorbuf)[256])
{
	SCOPE_FD		sfd(pfile, O_RDONLY);
	int			fd = sfd.get(), ret;

	if (fd < 0) {
		if (pretcode) {
			*pretcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "Failed to open ELF file %s due to : %s", pfile, gy_get_perror().get());
			
			return;
		}	

		GY_THROW_SYS_EXPRESSION("Failed to open ELF file %s", pfile);
	}	
	
	ret = open_elf_fd(fd, pretcode, errorbuf, pfile);
	if (ret != 0) {
		return;
	}	

	fd_ = sfd.release();
}	

int GY_ELF_UTIL::open_elf_fd(int fd, int *pretcode, char (&errorbuf)[256], const char *pfile)
{
	if (elf_version(EV_CURRENT) == EV_NONE) {
		if (pretcode) {
			*pretcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "ELF Utils initialization failed\n");

			return -1;
		}	
		
		GY_THROW_EXPRESSION("ELF Utils initialization failed");
	}

	Elf			*e;

	e = elf_begin(fd, ELF_C_READ, nullptr);
	if (!e) {
		if (pretcode) {
			*pretcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "Failed to create elf struct : %s\n", elf_errmsg(-1));
			
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
			snprintf(errorbuf, sizeof(errorbuf), "File %s not a valid elf file\n", pfile ? pfile : "");
			
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not a valid elf file", pfile ? pfile : "");
	}

	GElf_Ehdr 		ehdr;
	size_t 			shstrndx, nhdrs;

	if (!gelf_getehdr(e, &ehdr)) {
		if (pretcode) {
			*pretcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "File %s not a valid elf file due to mising object file header\n", pfile ? pfile : "");
			
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not a valid elf file due to mising object file header", pfile ? pfile : "");
	}	

	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		if (pretcode) {
			*pretcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "File %s not a valid elf file due to mising sections\n", pfile ? pfile : "");
			
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not a valid elf file due to mising sections", pfile ? pfile : "");
	}	

	if (elf_getphdrnum(e, &nhdrs) != 0) {
		if (pretcode) {
			*pretcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "File %s not handled as elf file has missing program headers\n", pfile ? pfile : "");
			
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not handled as elf file has missing program headers", pfile ? pfile : "");
	}

	if (!(ehdr.e_type == ET_EXEC || ehdr.e_type == ET_DYN)) {
		if (pretcode) {
			*pretcode = -1;
			snprintf(errorbuf, sizeof(errorbuf), "File %s not handled as only ELF binaries or Shared Libs handled\n", pfile ? pfile : "");
		
			return -1;
		}

		GY_THROW_EXPRESSION("File %s not handled as only ELF binaries or Shared Libs handled", pfile ? pfile : "");
	}

	pelf_			= std::exchange(e, nullptr);
	filetype_ 		= ehdr.e_type;
	nhdrs_			= nhdrs;
	nstrsection_		= shstrndx;

	if (pfile) {
		filename_	= pfile;
	}	

	if  (pretcode) {
		*pretcode = 0;
	}

	return 0;
}	

GY_ELF_UTIL::~GY_ELF_UTIL() noexcept
{
	if (pelf_) {
		elf_end(pelf_);
		pelf_ = nullptr;
	}	

	if (fd_ >= 0) {
		close(fd_);
		fd_ = -1;
	}	
}	

size_t GY_ELF_UTIL::find_func_offsets(const char *funcarr[], size_t nfuncs, off_t offsetarr[]) const
{
	using FUNC_MAP			= INLINE_STACK_F14_MAP<const char *, off_t *, 8 * 1024, FollyTransparentStringHash, FollyTransparentStringEqual>;
	using				folly::StringPiece;
	
	FUNC_MAP			fmap;
	size_t				nvalid = 0;

	std::memset(offsetarr, 0, nfuncs * sizeof(*offsetarr));

	for (int i = 0; (unsigned)i < nfuncs; ++i) {
		if (funcarr[i]) {
			fmap.try_emplace(funcarr[i], offsetarr + i);
		}
	}	

	const auto chk_update = [&](const char *pfunc, off_t foff) -> bool
	{
		GElf_Phdr 			phdr;
		bool				found = false;
		off_t				*poff;
		
		auto 				it = fmap.find(StringPiece(pfunc));

		if (it == fmap.end()) {
			return false;
		}	

		poff = it->second;
		
		for (int i = 0; i < (int)nhdrs_; i++) {

			if (!gelf_getphdr(pelf_, i, &phdr)) {
				continue;
			}

			if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X)) {
				continue;
			}

			if ((off_t)phdr.p_vaddr <= foff && foff < off_t(phdr.p_vaddr + phdr.p_memsz)) {
				foff = foff - phdr.p_vaddr + phdr.p_offset;
				found = true;
				break;
			}
		}
		
		if (!found) {
			return false;
		}	

		*poff = foff;

		return true;
	};	

	GElf_Shdr 			shdr[1];
	Elf_Data 			*data;
	GElf_Sym 			sym[1];
	bool				bret;
	off_t				off;
	char 				*pn;
	Elf_Scn 			*scn = nullptr;

	while ((scn = elf_nextscn(pelf_, scn))) {

		if (!gelf_getshdr(scn, shdr)) {
			continue;
		}

		if (!(shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_DYNSYM)) {
			continue;
		}

		data = nullptr;

		while ((data = elf_getdata(scn, data))) {

			for (int i = 0; gelf_getsym(data, i, sym); i++) {

				pn = elf_strptr(pelf_, shdr->sh_link, sym->st_name);
				if (!pn) {
					continue;
				}

				if (sym->st_value == 0) {
					continue;
				}

				if (GELF_ST_TYPE(sym->st_info) != STT_FUNC) {
					continue;
				}

				bret = chk_update(pn, sym->st_value);
				if (bret) {
					++nvalid;

					if (nvalid == nfuncs) {
						goto done;
					}	
				}
			}
		}
	}

done :
	return nvalid;

}

CHAR_BUF<256> GY_ELF_UTIL::get_buildid() const noexcept
{
	CHAR_BUF<256>			barr;
	char				tbuf[256];
	int 				nscn = 0;
	size_t 				notesz, offset = 0;
	Elf_Data 			*data;
	Elf_Scn 			*scn = nullptr;
	GElf_Shdr 			shdr_data, *shdrp = &shdr_data;
	bool				is_go = false;

	do {
		GElf_Shdr 		*shdr;
		const char		*pname;

		scn = elf_getscn(pelf_, ++nscn);
		if (!scn) {
			return barr;
		}	

		shdr = gelf_getshdr(scn, shdrp);
		if (!shdr) {
			continue;
		}	

		if (shdr->sh_type != SHT_NOTE) {
			continue;
		}

		pname = elf_strptr(pelf_, nstrsection_, shdr->sh_name);
		if (!pname) {
			continue;
		}

		if (0 == strcmp(pname, gnu_buildnote)) {
			break;
		}	
		else if (0 == strcmp(pname, go_buildnote)) {
			is_go = true;
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

		if (!is_go) {
			if (nhdr.n_type != NT_GNU_BUILD_ID) {
				continue;
			}	

			name = (const char *)data->d_buf + nameoff;
			if (!name || strcmp(name, ELF_NOTE_GNU)) {
				continue;
			}	
		}

		tsz = binary_to_hex_string((const uint8_t *)data->d_buf + descoff, nhdr.n_descsz, tbuf, sizeof(tbuf));

		barr.setbuf(tbuf, tsz);

		break;

	} while (notesz);

	return barr;
}	

bool GY_ELF_UTIL::is_go_binary() const noexcept
{
	int 				nscn = 0;
	size_t 				notesz, offset = 0;
	Elf_Scn 			*scn = nullptr;
	GElf_Shdr 			shdr_data, *shdrp = &shdr_data;

	do {
		GElf_Shdr 		*shdr;
		const char		*pname;

		scn = elf_getscn(pelf_, ++nscn);
		if (!scn) {
			return false;
		}	

		shdr = gelf_getshdr(scn, shdrp);
		if (!shdr) {
			continue;
		}	

		if (shdr->sh_type != SHT_NOTE) {
			continue;
		}

		pname = elf_strptr(pelf_, nstrsection_, shdr->sh_name);
		if (!pname) {
			continue;
		}

		if (0 == strcmp(pname, go_buildnote)) {
			return true;
		}	

	} while (scn != nullptr);

	return false;
}	

size_t GY_ELF_UTIL::get_dynamic_libs(STR_WR_BUF & strbuf) const noexcept
{
	GElf_Shdr 			shdr[1];
	Elf_Data 			*data;
	GElf_Dyn 			dyn[1];
	size_t				nlibs = 0;
	char 				*pn;
	Elf_Scn 			*scn = nullptr;

	while ((scn = elf_nextscn(pelf_, scn))) {

		if (!gelf_getshdr(scn, shdr)) {
			continue;
		}

		if (shdr->sh_type != SHT_DYNAMIC) {
			continue;
		}

		data = nullptr;

		while ((data = elf_getdata(scn, data))) {

			for (int i = 0; gelf_getdyn(data, i, dyn); i++) {
				
				if (dyn->d_tag != DT_NEEDED) {
					continue;
				}

				pn = elf_strptr(pelf_, shdr->sh_link, dyn->d_un.d_ptr);
				if (!pn) {
					continue;
				}
				
				strbuf << pn << ',';
				nlibs++;
			}
		}
	}

	if (nlibs) strbuf--;

done :
	return nlibs;

}	



} // namespace gyeeta

