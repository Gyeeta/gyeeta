//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_common_inc.h"
#include			"gy_http_proto.h"

using namespace gyeeta;

static constexpr const uint8_t httpreq1[] = 
"\x50\x4f\x53\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d" \
"\x0a\x48\x6f\x73\x74\x3a\x20\x6f\x63\x73\x70\x2e\x64\x69\x67\x69" \
"\x63\x65\x72\x74\x2e\x63\x6f\x6d\x0d\x0a\x55\x73\x65\x72\x2d\x41" \
"\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e" \
"\x30\x20\x28\x58\x31\x31\x3b\x20\x4c\x69\x6e\x75\x78\x20\x78\x38" \
"\x36\x5f\x36\x34\x3b\x20\x72\x76\x3a\x34\x35\x2e\x30\x29\x20\x47" \
"\x65\x63\x6b\x6f\x2f\x32\x30\x31\x30\x30\x31\x30\x31\x20\x46\x69" \
"\x72\x65\x66\x6f\x78\x2f\x34\x35\x2e\x30\x0d\x0a\x41\x63\x63\x65" \
"\x70\x74\x3a\x20\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x2c\x61\x70" \
"\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c\x2b" \
"\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f" \
"\x78\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x2a\x2f\x2a\x3b\x71\x3d" \
"\x30\x2e\x38\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67" \
"\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x55\x53\x2c\x65\x6e\x3b\x71" \
"\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70\x74\x2d\x45\x6e\x63" \
"\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70\x2c\x20\x64\x65\x66" \
"\x6c\x61\x74\x65\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x4c\x65" \
"\x6e\x67\x74\x68\x3a\x20\x38\x33\x0d\x0a\x43\x6f\x6e\x74\x65\x6e" \
"\x74\x2d\x54\x79\x70\x65\x3a\x20\x61\x70\x70\x6c\x69\x63\x61\x74" \
"\x69\x6f\x6e\x2f\x6f\x63\x73\x70\x2d\x72\x65\x71\x75\x65\x73\x74" \
"\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x6b\x65" \
"\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d\x0a\x0d\x0a" \
"\x30\x51\x30\x4f\x30\x4d\x30\x4b\x30\x49\x30\x09\x06\x05\x2b\x0e" \
"\x03\x02\x1a\x05\x00\x04\x14\x10\x5f\xa6\x7a\x80\x08\x9d\xb5\x27" \
"\x9f\x35\xce\x83\x0b\x43\x88\x9e\xa3\xc7\x0d\x04\x14\x0f\x80\x61" \
"\x1c\x82\x31\x61\xd5\x2f\x28\xe7\x8d\x46\x38\xb4\x2c\xe1\xc6\xd9" \
"\xe2\x02\x10\x09\x4b\x33\x12\xf2\xdf\x96\x17\x29\x5f\xf8\x2f\x46" \
"\x76\x24\xd0";

static constexpr const uint8_t resp1[] =
"\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x33\x30\x34\x20\x4e\x6f\x74" \
"\x20\x4d\x6f\x64\x69\x66\x69\x65\x64\x0d\x0a\x44\x61\x74\x65\x3a" \
"\x20\x46\x72\x69\x2c\x20\x31\x38\x20\x4e\x6f\x76\x20\x32\x30\x31" \
"\x36\x20\x30\x39\x3a\x35\x33\x3a\x35\x31\x20\x47\x4d\x54\x0d\x0a" \
"\x53\x65\x72\x76\x65\x72\x3a\x20\x41\x70\x61\x63\x68\x65\x0d\x0a" \
"\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x63\x6c\x6f\x73" \
"\x65\x0d\x0a\x45\x54\x61\x67\x3a\x20\x22\x32\x31\x32\x63\x30\x32" \
"\x34\x2d\x36\x39\x37\x65\x2d\x33\x35\x37\x61\x65\x61\x63\x30\x22" \
"\x0d\x0a\x45\x78\x70\x69\x72\x65\x73\x3a\x20\x46\x72\x69\x2c\x20" \
"\x30\x32\x20\x44\x65\x63\x20\x32\x30\x31\x36\x20\x30\x39\x3a\x35" \
"\x33\x3a\x35\x31\x20\x47\x4d\x54\x0d\x0a\x43\x61\x63\x68\x65\x2d" \
"\x43\x6f\x6e\x74\x72\x6f\x6c\x3a\x20\x6d\x61\x78\x2d\x61\x67\x65" \
"\x3d\x31\x32\x30\x39\x36\x30\x30\x0d\x0a\x0d\x0a";

static constexpr const uint8_t httpreq2[] = 
"\x47\x45\x54\x20\x2f\x73\x69\x74\x65\x73\x2f\x61\x6c\x6c\x2f\x6d" \
"\x6f\x64\x75\x6c\x65\x73\x2f\x70\x6f\x6f\x72\x6d\x61\x6e\x73\x63" \
"\x72\x6f\x6e\x2f\x70\x6f\x6f\x72\x6d\x61\x6e\x73\x63\x72\x6f\x6e" \
"\x2e\x6a\x73\x3f\x75\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a" \
"\x48\x6f\x73\x74\x3a\x20\x65\x78\x61\x63\x74\x2d\x73\x6f\x6c\x75" \
"\x74\x69\x6f\x6e\x73\x2e\x63\x6f\x6d\x0d\x0a\x55\x73\x65\x72\x2d" \
"\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35" \
"\x2e\x30\x20\x28\x58\x31\x31\x3b\x20\x4c\x69\x6e\x75\x78\x20\x78" \
"\x38\x36\x5f\x36\x34\x3b\x20\x72\x76\x3a\x34\x35\x2e\x30\x29\x20" \
"\x47\x65\x63\x6b\x6f\x2f\x32\x30\x31\x30\x30\x31\x30\x31\x20\x46" \
"\x69\x72\x65\x66\x6f\x78\x2f\x34\x35\x2e\x30\x0d\x0a\x41\x63\x63" \
"\x65\x70\x74\x3a\x20\x2a\x2f\x2a\x0d\x0a\x41\x63\x63\x65\x70\x74" \
"\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x65\x6e\x2d\x55\x53" \
"\x2c\x65\x6e\x3b\x71\x3d\x30\x2e\x35\x0d\x0a\x41\x63\x63\x65\x70" \
"\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67\x7a\x69\x70" \
"\x2c\x20\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x52\x65\x66\x65\x72" \
"\x65\x72\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f\x65\x78\x61\x63\x74" \
"\x2d\x73\x6f\x6c\x75\x74\x69\x6f\x6e\x73\x2e\x63\x6f\x6d\x2f\x0d" \
"\x0a\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x5f\x5f\x75\x74\x6d\x61\x3d" \
"\x31\x34\x39\x36\x32\x37\x38\x37\x34\x2e\x31\x37\x37\x37\x37\x38" \
"\x36\x32\x30\x39\x2e\x31\x34\x33\x34\x34\x36\x36\x34\x33\x31\x2e" \
"\x31\x34\x35\x38\x32\x30\x39\x36\x39\x35\x2e\x31\x34\x35\x38\x32" \
"\x32\x33\x39\x31\x30\x2e\x33\x3b\x20\x5f\x5f\x75\x74\x6d\x76\x3d" \
"\x31\x34\x39\x36\x32\x37\x38\x37\x34\x2e\x61\x6e\x6f\x6e\x79\x6d" \
"\x6f\x75\x73\x25\x32\x30\x75\x73\x65\x72\x25\x33\x41\x25\x33\x41" \
"\x25\x33\x41\x25\x33\x41\x3b\x20\x53\x45\x53\x53\x32\x33\x36\x64" \
"\x30\x61\x35\x64\x63\x35\x36\x38\x64\x66\x62\x61\x35\x36\x37\x65" \
"\x62\x33\x62\x34\x34\x38\x38\x34\x66\x38\x66\x64\x3d\x75\x6f\x33" \
"\x6e\x75\x67\x69\x76\x66\x30\x67\x39\x73\x70\x75\x38\x34\x65\x63" \
"\x70\x39\x62\x70\x39\x6e\x33\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74" \
"\x69\x6f\x6e\x3a\x20\x6b\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d" \
"\x0a\x49\x66\x2d\x4d\x6f\x64\x69\x66\x69\x65\x64\x2d\x53\x69\x6e" \
"\x63\x65\x3a\x20\x46\x72\x69\x2c\x20\x32\x30\x20\x4a\x75\x6c\x20" \
"\x32\x30\x31\x32\x20\x30\x34\x3a\x31\x33\x3a\x35\x30\x20\x47\x4d" \
"\x54\x0d\x0a\x49\x66\x2d\x4e\x6f\x6e\x65\x2d\x4d\x61\x74\x63\x68" \
"\x3a\x20\x22\x32\x31\x32\x63\x32\x37\x33\x2d\x32\x35\x36\x2d\x31" \
"\x66\x38\x65\x33\x62\x38\x30\x22\x0d\x0a\x0d\x0a";

static constexpr const uint8_t resp2[] =
"\x34\x30\x34\x30\x3b\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x66" \
"\x6c\x6f\x61\x74\x3a\x20\x6c\x65\x66\x74\x3b\x0a\x20\x20\x20\x20" \
"\x20\x20\x20\x20\x20\x6d\x61\x72\x67\x69\x6e\x3a\x20\x38\x70\x78" \
"\x20\x30\x3b\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x61\x78" \
"\x2d\x77\x69\x64\x74\x68\x3a\x20\x33\x30\x25\x3b\x0a\x20\x20\x20" \
"\x20\x20\x20\x20\x20\x20\x6d\x69\x6e\x2d\x77\x69\x64\x74\x68\x3a" \
"\x20\x33\x30\x25\x3b\x0a\x20\x20\x20\x20\x20\x20\x20\x20\x20\x70" \
"\x61\x64\x64\x69\x6e\x67\x3a\x20\x30\x20\x31\x30\x70\x78\x3b\x0a" \
"\x20\x20\x20\x20\x20\x20\x20\x20\x20\x74\x65\x78\x74\x2d\x61\x6c" \
"\x69\x67\x6e\x3a\x20\x6c\x65\x66\x74\x3b\x20\x0a\x20\x20\x20\x20" \
"\x20\x7d\x0a\x20\x20\x20\x20\x20\x2e\x63\x6f\x6e\x66\x69\x67\x52" \
"\x6f\x77\x20\x3e\x20\x70\x20\x7b\x0a\x20\x20\x20\x20\x20\x20\x20" \
"\x63\x6f\x6c\x6f\x72\x3a\x20\x23\x36\x41\x36\x41\x36\x41\x3b\x0a" \
"\x20\x20\x20\x20\x20\x20\x20\x6c\x65\x74\x74\x65\x72\x2d\x73\x70" \
"\x61\x63\x69\x6e\x67\x3a\x20\x31\x70\x78\x3b\x0a\x20\x20\x20\x20" \
"\x20\x20\x20\x6d\x69\x6e\x2d\x77\x69\x64\x74\x68\x3a\x20\x36\x30" \
"\x25\x3b\x0a\x20\x20\x20\x20\x20\x7d\x0a\x0a\x3c\x2f\x73\x74\x79" \
"\x6c\x65\x3e\x0a\x20\x20\x20\x20\x3c\x2f\x62\x6f\x64\x79\x3e\x0a" \
"\x20\x20\x20\x20\x3c\x2f\x68\x74\x6d\x6c\x3e\x0a\x20\x20\x20\x20\x0a";


static constexpr const uint8_t httpreq3[] = 
"\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a" \
"\x48\x6f\x73\x74\x3a\x20\x31\x39\x32\x2e\x31\x36\x38\x2e\x32\x39" \
"\x2e\x31\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20" \
"\x6b\x65\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d\x0a\x55\x70\x67\x72" \
"\x61\x64\x65\x2d\x49\x6e\x73\x65\x63\x75\x72\x65\x2d\x52\x65\x71" \
"\x75\x65\x73\x74\x73\x3a\x20\x31\x0d\x0a\x55\x73\x65\x72\x2d\x41" \
"\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e" \
"\x30\x20\x28\x58\x31\x31\x3b\x20\x4c\x69\x6e\x75\x78\x20\x78\x38" \
"\x36\x5f\x36\x34\x29\x20\x41\x70\x70\x6c\x65\x57\x65\x62\x4b\x69" \
"\x74\x2f\x35\x33\x37\x2e\x33\x36\x20\x28\x4b\x48\x54\x4d\x4c\x2c" \
"\x20\x6c\x69\x6b\x65\x20\x47\x65\x63\x6b\x6f\x29\x20\x43\x68\x72" \
"\x6f\x6d\x65\x2f\x31\x32\x30\x2e\x30\x2e\x30\x2e\x30\x20\x53\x61" \
"\x66\x61\x72\x69\x2f\x35\x33\x37\x2e\x33\x36\x0d\x0a\x41\x63\x63" \
"\x65\x70\x74\x3a\x20\x74\x65\x78\x74\x2f\x68\x74\x6d\x6c\x2c\x61" \
"\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x78\x68\x74\x6d\x6c" \
"\x2b\x78\x6d\x6c\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e" \
"\x2f\x78\x6d\x6c\x3b\x71\x3d\x30\x2e\x39\x2c\x69\x6d\x61\x67\x65" \
"\x2f\x61\x76\x69\x66\x2c\x69\x6d\x61\x67\x65\x2f\x77\x65\x62\x70" \
"\x2c\x69\x6d\x61\x67\x65\x2f\x61\x70\x6e\x67\x2c\x2a\x2f\x2a\x3b" \
"\x71\x3d\x30\x2e\x38\x2c\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f" \
"\x6e\x2f\x73\x69\x67\x6e\x65\x64\x2d\x65\x78\x63\x68\x61\x6e\x67" \
"\x65\x3b\x76\x3d\x62\x33\x3b\x71\x3d\x30\x2e\x37\x0d\x0a\x41\x63" \
"\x63\x65\x70\x74\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x67" \
"\x7a\x69\x70\x2c\x20\x64\x65\x66\x6c\x61\x74\x65\x0d\x0a\x41\x63" \
"\x63\x65\x70\x74\x2d\x4c\x61\x6e\x67\x75\x61\x67\x65\x3a\x20\x65" \
"\x6e\x2d\x55\x53\x2c\x65\x6e\x3b\x71\x3d\x30\x2e\x39\x2c\x68\x69" \
"\x3b\x71\x3d\x30\x2e\x38\x2c\x67\x75\x3b\x71\x3d\x30\x2e\x37\x0d" \
"\x0a\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x72\x65\x63\x6f\x72\x64\x4d" \
"\x6f\x64\x69\x66\x69\x65\x64\x3d\x31\x0d\x0a\x0d\x0a";

static constexpr const uint8_t resp3[] =
"\xf0\x03\x8c\xc7\xcf\x41\x8c\xa3\x99\x9f\x6a\xcb\x08\x00\x45\x00" \
"\x00\xb7\x13\x83\x40\x00\x40\x06\x6a\x8b\xc0\xa8\x1d\x01\xc0\xa8" \
"\x1d\xe1\x00\x50\xa0\x46\x52\x5a\x89\x7e\x98\x6a\x1d\x41\x80\x19" \
"\x01\xd6\x27\xd3\x00\x00\x01\x01\x08\x0a\x02\x35\x81\x74\x08\xeb" \
"\xfa\x70\x70\x20\x7b\x0a\x20\x20\x20\x20\x20\x20\x20\x63\x6f\x6c" \
"\x6f\x72\x3a\x20\x23\x36\x41\x36\x41\x36\x41\x3b\x0a\x20\x20\x20" \
"\x20\x20\x20\x20\x6c\x65\x74\x74\x65\x72\x2d\x73\x70\x61\x63\x69" \
"\x6e\x67\x3a\x20\x31\x70\x78\x3b\x0a\x20\x20\x20\x20\x20\x20\x20" \
"\x6d\x69\x6e\x2d\x77\x69\x64\x74\x68\x3a\x20\x36\x30\x25\x3b\x0a" \
"\x20\x20\x20\x20\x20\x7d\x0a\x0a\x3c\x2f\x73\x74\x79\x6c\x65\x3e" \
"\x0a\x20\x20\x20\x20\x3c\x2f\x62\x6f\x64\x79\x3e\x0a\x20\x20\x20" \
"\x20\x3c\x2f\x68\x74\x6d\x6c\x3e\x0a\x20\x20\x20\x20\x0a\x0d\x0a" \
"\x30\x0d\x0a\x0d\x0a";

static constexpr const uint8_t resp4[] =
"\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x32\x30\x30\x20\x4f\x4b\x0d" \
"\x0a\x43\x61\x63\x68\x65\x2d\x43\x6f\x6e\x74\x72\x6f\x6c\x3a\x20" \
"\x6e\x6f\x2d\x73\x74\x6f\x72\x65\x2c\x20\x6e\x6f\x2d\x63\x61\x63" \
"\x68\x65\x2c\x20\x6d\x75\x73\x74\x2d\x72\x65\x76\x61\x6c\x69\x64" \
"\x61\x74\x65\x2c\x20\x70\x72\x69\x76\x61\x74\x65\x0d\x0a\x43\x6f" \
"\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65\x3a\x20\x61\x70\x70\x6c" \
"\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6a\x73\x6f\x6e\x3b\x20\x63\x68" \
"\x61\x72\x73\x65\x74\x3d\x75\x74\x66\x2d\x38\x0d\x0a\x44\x61\x74" \
"\x65\x3a\x20\x57\x65\x64\x2c\x20\x32\x38\x20\x4a\x75\x6e\x20\x32" \
"\x30\x32\x33\x20\x31\x30\x3a\x34\x39\x3a\x33\x33\x20\x47\x4d\x54" \
"\x0d\x0a\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x6b\x65" \
"\x65\x70\x2d\x61\x6c\x69\x76\x65\x0d\x0a\x4b\x65\x65\x70\x2d\x41" \
"\x6c\x69\x76\x65\x3a\x20\x74\x69\x6d\x65\x6f\x75\x74\x3d\x35\x0d" \
"\x0a\x54\x72\x61\x6e\x73\x66\x65\x72\x2d\x45\x6e\x63\x6f\x64\x69" \
"\x6e\x67\x3a\x20\x63\x68\x75\x6e\x6b\x65\x64\x0d\x0a\x0d\x0a"
"\x31\x0d\x0a\x5b\x0d\x0a\x32\x30\x34\x0d\x0a\x7b\x22\x73\x68\x79" \
"\x61\x6d\x61\x69\x64\x22\x3a\x22\x34\x37\x35\x61\x65\x32\x39\x36" \
"\x39\x37\x30\x30\x66\x62\x61\x61\x22\x2c\x22\x73\x68\x79\x61\x6d" \
"\x61\x6e\x61\x6d\x65\x22\x3a\x22\x73\x68\x79\x61\x6d\x61\x31\x22" \
"\x2c\x22\x6e\x6d\x61\x64\x68\x61\x76\x61\x22\x3a\x31\x2c\x22\x6e" \
"\x6d\x61\x64\x61\x63\x74\x69\x76\x65\x22\x3a\x31\x2c\x22\x6d\x69" \
"\x6e\x6d\x61\x64\x68\x61\x76\x61\x22\x3a\x31\x2c\x22\x6e\x70\x61" \
"\x72\x74\x68\x61\x22\x3a\x34\x2c\x22\x6e\x77\x65\x62\x73\x65\x72" \
"\x76\x65\x72\x22\x3a\x31\x2c\x22\x6e\x61\x63\x74\x69\x6f\x6e\x68" \
"\x64\x6c\x72\x22\x3a\x31\x2c\x22\x73\x76\x63\x68\x6f\x73\x74\x22" \
"\x3a\x22\x67\x79\x65\x65\x74\x61\x2d\x75\x73\x65\x61\x73\x74\x2d" \
"\x31\x2d\x33\x22\x2c\x22\x73\x76\x63\x70\x6f\x72\x74\x22\x3a\x31" \
"\x30\x30\x33\x37\x2c\x22\x73\x68\x79\x61\x6d\x61\x6e\x61\x6d\x65" \
"\x22\x3a\x22\x73\x68\x79\x61\x6d\x61\x31\x22\x2c\x22\x72\x65\x67" \
"\x69\x6f\x6e\x22\x3a\x22\x22\x2c\x22\x7a\x6f\x6e\x65\x22\x3a\x22" \
"\x22\x2c\x22\x64\x62\x68\x6f\x73\x74\x22\x3a\x22\x67\x79\x65\x65" \
"\x74\x61\x2d\x75\x73\x65\x61\x73\x74\x2d\x31\x2d\x33\x22\x2c\x22" \
"\x64\x62\x70\x6f\x72\x74\x22\x3a\x31\x30\x30\x34\x30\x2c\x22\x64" \
"\x62\x64\x61\x79\x73\x22\x3a\x37\x2c\x22\x64\x62\x64\x69\x73\x6b" \
"\x6d\x62\x22\x3a\x34\x34\x2c\x22\x64\x62\x6c\x6f\x67\x6d\x6f\x64" \
"\x65\x22\x3a\x22\x61\x6c\x77\x61\x79\x73\x22\x2c\x22\x64\x62\x63" \
"\x6f\x6e\x6e\x22\x3a\x74\x72\x75\x65\x2c\x22\x70\x72\x6f\x63\x73" \
"\x74\x61\x72\x74\x22\x3a\x22\x32\x30\x32\x33\x2d\x30\x36\x2d\x32" \
"\x33\x54\x30\x36\x3a\x31\x38\x3a\x35\x32\x5a\x22\x2c\x22\x6b\x65" \
"\x72\x6e\x76\x65\x72\x73\x74\x72\x22\x3a\x22\x35\x2e\x31\x35\x2e" \
"\x30\x2d\x37\x35\x2d\x67\x65\x6e\x65\x72\x69\x63\x22\x2c\x22\x76" \
"\x65\x72\x73\x69\x6f\x6e\x22\x3a\x22\x30\x2e\x34\x2e\x31\x22\x2c" \
"\x22\x64\x62\x76\x65\x72\x73\x69\x6f\x6e\x22\x3a\x22\x31\x32\x2e" \
"\x32\x22\x2c\x22\x77\x65\x62\x76\x65\x72\x73\x69\x6f\x6e\x22\x3a" \
"\x22\x30\x2e\x34\x2e\x30\x22\x2c\x22\x61\x63\x74\x69\x6f\x6e\x76" \
"\x65\x72\x73\x69\x6f\x6e\x22\x3a\x22\x30\x2e\x32\x2e\x30\x22\x2c" \
"\x22\x68\x6f\x73\x74\x6e\x61\x6d\x65\x22\x3a\x22\x67\x79\x65\x65" \
"\x74\x61\x2d\x75\x73\x65\x61\x73\x74\x2d\x31\x2d\x33\x22\x7d\x0d" \
"\x0a\x31\x0d\x0a\x5d\x0d\x0a\x30\x0d\x0a\x0d\x0a";


int main()
{
	static constexpr std::string_view	reqarr[] = {
		"GET /home HTTP/1.1\r\nHost: example.com\r\nCookie: \r\n\r\n",
		"GET /hoge HTTP/1.1\r\nHost: example.com\r\nUser-Agent: \343\201\262\343/1.0\r\n\r\n",
		"GET https://datatracker.ietf.org/doc/html/rfc7230?paramdummy1=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\nHost: datatracker.ietf.org\r\nUser-Agent: \343\201\262\343/1.0\r\n\r\n",
	};	

	for (auto sv : reqarr) {
		assert(true == HTTP1_PROTO::is_valid_req((const uint8_t *)sv.data(), sv.size(), sv.size()));
	}	

	if (true) {
		auto			[isend, pend] = HTTP1_PROTO::is_req_resp_end_heuristic(httpreq1, sizeof(httpreq1) - 1, DirPacket::DirInbound);

		assert(isend == true);
	}

	if (true) {
		auto			[isend, pend] = HTTP1_PROTO::is_req_resp_end_heuristic(resp1, sizeof(resp1) - 1, DirPacket::DirOutbound);

		assert(isend == true);
	}

	if (true) {
		auto			[isend, pend] = HTTP1_PROTO::is_req_resp_end_heuristic(httpreq2, sizeof(httpreq2) - 1, DirPacket::DirInbound);

		assert(isend == true);
	}

	if (true) {
		auto			[isend, pend] = HTTP1_PROTO::is_req_resp_end_heuristic(resp2, sizeof(resp2) - 1, DirPacket::DirOutbound);

		assert(isend == false);
	}

	if (true) {
		auto			[isend, pend] = HTTP1_PROTO::is_req_resp_end_heuristic(httpreq3, sizeof(httpreq3) - 1, DirPacket::DirInbound);

		assert(isend == true);
	}

	if (true) {
		auto			[isend, pend] = HTTP1_PROTO::is_req_resp_end_heuristic(resp3, sizeof(resp3) - 1, DirPacket::DirOutbound);

		assert(isend == true);
	}

	if (true) {
		auto			[isend, pend] = HTTP1_PROTO::is_req_resp_end_heuristic(resp4, sizeof(resp4) - 1, DirPacket::DirOutbound);

		assert(isend == true);
	}

}	


