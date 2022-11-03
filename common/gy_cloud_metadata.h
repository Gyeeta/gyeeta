//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"

namespace gyeeta {

enum CloudType : uint16_t
{
	CloudAWS			= 0,
	CloudGCP,
	CloudAzure,

	CloudOnPrem,
	CloudUnknown,
};	

static CHAR_BUF<64> get_region_from_zone(const char *zone) noexcept;
static CloudType get_cloud_from_string(const char *cloud_type) noexcept;

class CLOUD_METADATA
{
public :
	CLOUD_METADATA(CloudType cloudtype)
		: cloudtype_(cloudtype)
	{
		set_cloud_metadata();
	}	

	CLOUD_METADATA(const char *cloud_type)
		: cloudtype_(get_cloud_from_string(cloud_type))
	{
		set_cloud_metadata();
	}	

	void set_cloud_metadata();

	const char * get_instance_id() const noexcept
	{
		return instance_id_;
	}

	const char * get_region_name() const noexcept
	{
		return region_name_;
	}	
	
	const char * get_zone_name() const noexcept
	{
		return zone_name_;
	}	

	// Returns {instance_id_, region_name_, zone_name_, cloud_type}
	std::tuple<const char *, const char *, const char *, const char *> get_metadata() const noexcept
	{
		return std::make_tuple(instance_id_, region_name_, zone_name_, get_cloud_type());
	}	

	const char * get_cloud_type() const noexcept
	{
		switch (cloudtype_) {
		
		case CloudAWS		:	return "aws";
		case CloudGCP		:	return "gcp";
		case CloudAzure		:	return "azure";

		case CloudOnPrem	:	return "on-prem";

		case CloudUnknown	:
		default			:	
						return "unknown";
		}
	}	

	static constexpr size_t		MAX_INSTANCE_ID_LEN			{128};
	static constexpr size_t		MAX_ZONE_LEN				{64};

	char				instance_id_[MAX_INSTANCE_ID_LEN]	{};
	char				region_name_[MAX_ZONE_LEN]		{};
	char				zone_name_[MAX_ZONE_LEN]		{};
	CloudType			cloudtype_				{CloudUnknown};
	time_t				tlast_					{0};

protected :
	void set_aws_metadata();
	void set_gcp_metadata();
	void set_azure_metadata();
};	


/*
 * If zone is say, asia-south1-a will return asia-south1
 */
static CHAR_BUF<64> get_region_from_zone(const char *zone) noexcept
{
	const char			*pstart = zone, *pend = zone ? zone + strlen(zone) - 1 : nullptr, *ptmp = pend;
	CHAR_BUF<64>			cbuf;
	
	while (ptmp > pstart && *ptmp != '-') {
		ptmp--;
	}	

	if (ptmp == pstart) {
		return cbuf;
	}	
		
	cbuf.setbuf(pstart, ptmp - pstart);

	return cbuf;
}	

static CloudType get_cloud_from_string(const char *cloud_type) noexcept
{
	if (!cloud_type) {
		return CloudUnknown;
	}	

	if ((0 == strcasecmp(cloud_type, "aws")) || (0 == strcasecmp(cloud_type, "ec2")) || (0 == strncasecmp(cloud_type, "amazon", GY_CONST_STRLEN("amazon"))) || (0 == strcasecmp(cloud_type, "eks"))) {
		return CloudAWS;
	}	
	else if ((0 == strcasecmp(cloud_type, "gcp")) || (0 == strcasecmp(cloud_type, "gce")) || (0 == strncasecmp(cloud_type, "google", GY_CONST_STRLEN("google"))) || (0 == strcasecmp(cloud_type, "gke"))) {
		return CloudGCP;
	}	
	else if ((0 == strcasecmp(cloud_type, "azure")) || (0 == strncasecmp(cloud_type, "microsoft", GY_CONST_STRLEN("microsoft"))) || (0 == strcasecmp(cloud_type, "aks"))) {
		return CloudAzure;
	}	
	else if ((0 == strcasecmp(cloud_type, "onprem")) || (0 == strcasecmp(cloud_type, "on-prem")) || (0 == *cloud_type)) {
		return CloudOnPrem;
	}

	return CloudUnknown;
}

} // namespace gyeeta

