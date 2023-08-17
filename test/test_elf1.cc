//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_misc.h"
#include			"gy_elf.h"

using namespace gyeeta;


int main(int argc, char **argv)
{
	if (argc < 3) {
		IRPRINT("\nUsage : %s <File Path> <Func1> <Func2> ...\n\n"
				"e.g. %s /bin/bash SSL_read SSL_write readline tilde_expand\n\n", argv[0], argv[0]);

		return 1;
	}

	try {
		char			errbuf[256];
		STRING_BUFFER<1024>	strbuf;
		size_t			nlibs;
		int			ret;
		auto			tpath = argv[1];
		GY_ELF_UTIL		elf(tpath, ret, errbuf );

		if (ret != 0) {
			ERRORPRINT("%s\n", errbuf);
			return 1;
		}	

		IRPRINT("\n");
		INFOPRINT("Path \'%s\' : BuildID \'%s\' : File is %sa Go Language binary\n\n", tpath, elf.get_buildid().get(), elf.is_go_binary() ? "" : "not ");

		nlibs = elf.get_dynamic_libs(strbuf);

		INFOPRINT("Path \%s\' : Requires %lu Dynamic Libs : %s\n\n", tpath, nlibs, strbuf.get()); 

		off_t			offarr[argc - 2];
		size_t			nret;

		nret = elf.find_func_offsets((const char**)&argv[2], argc - 2, offarr);

		for (int i = 0; i < argc - 2; ++i) {
			if (offarr[i] > 0) {
				IRPRINT("\t\t\tFunction \'%s\' found at offset %lu\n", argv[2 + i], offarr[i]);
			}
			else {
				IRPRINT("\t\t\tFunction \'%s\' Not Found\n", argv[2 + i]);
			}	
		}

		IRPRINT("\n\n");

		return 0;
	}
	GY_CATCH_MSG("ELF Exception seen");

	return 1;
}	

