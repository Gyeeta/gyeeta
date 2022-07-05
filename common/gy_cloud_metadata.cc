
#include			"gy_cloud_metadata.h"
#include			"gy_libcurl.h"
#include			"gy_rapidjson.h"

namespace gyeeta {


void CLOUD_METADATA::set_cloud_metadata()
{
	switch (cloudtype_) {
	
	case CloudAWS 		:	set_aws_metadata(); break;		
	case CloudGCP 		:	set_gcp_metadata(); break;		
	case CloudAzure 	:	set_azure_metadata(); break;		
	
	default			:	
					INFOPRINT("Ignoring Cloud Instance Metadata as Unknown Cloud Type / On-Prem specified\n");
					break;
	}	

	tlast_ = time(nullptr);
}	

void CLOUD_METADATA::set_aws_metadata()
{
	/* 
	 * Refer to : https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
	 *
	 * TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token `
	 * curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/dynamic/instance-identity/document
	 * 
	 * XXX Currently we use the availabilityZone from dynamic metdata and NOT availability-zone-id 
	 * (availability-zone-id will be AZ consistent across AWS accounts)
	 * 
	 * Sample Output JSON :
		
		{
			"devpayProductCodes" : null,
			"marketplaceProductCodes" : [ "1abc2defghijklm3nopqrs4tu" ], 
			"availabilityZone" : "us-west-2b",
			"privateIp" : "10.158.112.84",
			"version" : "2017-09-30",
			"instanceId" : "i-1234567890abcdef0",
			"billingProducts" : null,
			"instanceType" : "t2.micro",
			"accountId" : "123456789012",
			"imageId" : "ami-5fb8c835",
			"pendingTime" : "2016-11-19T16:32:11Z",
			"architecture" : "x86_64",
			"kernelId" : null,
			"ramdiskId" : null,
			"region" : "us-west-2"
		}		
	*
	*/

	INFOPRINT("Starting AWS Instance Metadata Retrieval...\n");

	GY_CURL_EASY			c1;
	STRING_BUFFER<2048>		hdrtoken;		
	std::string			meta;
	uint64_t			cmsec = get_msec_clock();

	c1.set_url("http://169.254.169.254/latest/api/token").set_user_agent("Gyeeta/1.0").set_http_put().set_timeout_sec(15);

	c1.set_http_header("X-aws-ec2-metadata-token-ttl-seconds: 21600");

	c1.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
		size_t				tsz = size * nmemb;
		STRING_BUFFER<2048>		*phdr = (STRING_BUFFER<2048> *)userp;

		if (phdr && tsz && contents) {
			if (phdr->size() == 0) {
				phdr->appendconst("X-aws-ec2-metadata-token: ");
			}	

			phdr->append((const char *)contents, tsz);
		}	

		return tsz;
	}, &hdrtoken);	
	
	auto			[isok, res, perrstr] = c1.send_request_blocking();
	
	c1.reset_headers();

	if (isok && hdrtoken.size() > 0) {
		c1.set_http_header(hdrtoken.data());
	}	

	c1.set_url("http://169.254.169.254/latest/dynamic/instance-identity/document").set_http_get().set_timeout_sec(30);

	c1.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
		size_t			tsz = size * nmemb;
		std::string		*pmeta = (std::string *)userp;

		if (pmeta && tsz && contents) {
			pmeta->append((const char *)contents, tsz);
		}	

		return tsz;
	}, &meta);	
	
	auto			[isok2, res2, perrstr2] = c1.send_request_blocking();
	
	if (isok2 && meta.size() > 0) {
		JSON_DOCUMENT<2048, 2048>		doc;
		auto					& jdoc = doc.get_doc();

		DEBUGEXECN(1,
			INFOPRINTCOLOR(GY_COLOR_GREEN, "Received Instance Metadata : \'%s\'\n", meta.data());
		);

		if (jdoc.ParseInsitu(meta.data()).HasParseError()) {
			GY_THROW_EXPRESSION("Invalid Instance Metadata JSON : Error is \'%s\'", rapidjson::GetParseError_En(doc.get_doc().GetParseError()));
		}	

		if (!jdoc.IsObject()) {
			GY_THROW_EXPRESSION("Instance Metadata JSON Not in expected Object format : Currently not handled");
		}

		if (auto it = jdoc.FindMember("instanceId"); ((it != jdoc.MemberEnd()) && (it->value.IsString()))) {
			GY_SAFE_STR_MEMCPY(instance_id_, sizeof(instance_id_), it->value.GetString(), it->value.GetStringLength());
		}	

		if (auto it = jdoc.FindMember("region"); ((it != jdoc.MemberEnd()) && (it->value.IsString()))) {
			GY_SAFE_STR_MEMCPY(region_name_, sizeof(region_name_), it->value.GetString(), it->value.GetStringLength());
		}	

		if (auto it = jdoc.FindMember("availabilityZone"); ((it != jdoc.MemberEnd()) && (it->value.IsString()))) {
			GY_SAFE_STR_MEMCPY(zone_name_, sizeof(zone_name_), it->value.GetString(), it->value.GetStringLength());
		}	

		if (*instance_id_ == 0) {
			GY_THROW_EXPRESSION("Invalid AWS Instance Metadata Response seen : No Instance ID seen");
		}	

		uint64_t			cmsec2 = get_msec_clock();

		INFOPRINT("Received AWS Instance Metadata in %lu msec : Instance ID \'%s\' : Region \'%s\' : Zone \'%s\'\n", 
			cmsec2 - cmsec, instance_id_, region_name_, zone_name_);
	}
	else {
		if (!isok2) {
			GY_THROW_EXPRESSION("Failed to get AWS Instance Metadata : HTTP Response %ld : Error \'%s\'", res2, perrstr2 ? perrstr2 : "");
		}

		GY_THROW_EXPRESSION("Empty AWS Instance Metadata Response seen");
	}
}	

void CLOUD_METADATA::set_gcp_metadata()
{
	/*
		Refer to : https://cloud.google.com/compute/docs/metadata/querying-metadata

		Instance ID :
		curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id
		3315546196137475219

		Region & Zone (only zone available) :
		curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/zone
		projects/123452323458/zones/asia-south1-a

	 */

	INFOPRINT("Starting GCP Instance Metadata Retrieval...\n");

	GY_CURL_EASY			c1;
	STRING_BUFFER<2048>		zonebuf;		
	uint64_t			cmsec = get_msec_clock();

	c1.set_url("http://metadata.google.internal/computeMetadata/v1/instance/id").set_user_agent("Gyeeta/1.0").set_timeout_sec(15);

	c1.set_http_header("Metadata-Flavor: Google");

	c1.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
		size_t				tsz = size * nmemb;
		char				*instance_id = (char *)userp;

		if (instance_id && tsz && contents) {
			GY_SAFE_STR_MEMCPY(instance_id, CLOUD_METADATA::MAX_INSTANCE_ID_LEN, (const char *)contents, tsz);
		}	

		return tsz;
	}, instance_id_);	

	auto			[isok, res, perrstr] = c1.send_request_blocking();

	if (!isok) {
		GY_THROW_EXPRESSION("Failed to get GCP Instance Metadata : HTTP Response %ld : Error \'%s\'", res, perrstr ? perrstr : "");
	}	

	if (*instance_id_ == 0) {
		GY_THROW_EXPRESSION("Invalid GCP Instance Metadata Response seen : No Instance ID seen");
	}	

	c1.set_url("http://metadata.google.internal/computeMetadata/v1/instance/zone");

	c1.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
		size_t				tsz = size * nmemb;
		STRING_BUFFER<2048>		*pzone = (STRING_BUFFER<2048> *)userp;

		if (pzone && tsz && contents) {
			pzone->append((const char *)contents, tsz);
		}	

		return tsz;
	}, &zonebuf);	
	
	auto			[isok2, res2, perrstr2] = c1.send_request_blocking();

	if (isok2 && zonebuf.size() > 0) {
		uint64_t		cmsec2 = get_msec_clock();
		const char		*pstart = zonebuf.data(), *pend = pstart + zonebuf.size() - 1, *ptmp = pend;

		while (ptmp > pstart && *ptmp != '/') {
			ptmp--;
		}	

		if (ptmp > pstart) {
			ptmp++;
		}	

		pstart = ptmp;

		GY_STRNCPY(zone_name_, pstart, sizeof(zone_name_));
		
		auto			regbuf = get_region_from_zone(pstart);

		GY_STRNCPY(region_name_, regbuf.get(), sizeof(region_name_));

		INFOPRINT("Received GCP Instance Metadata in %lu msec : Instance ID \'%s\' : Region \'%s\' : Zone \'%s\'\n", 
			cmsec2 - cmsec, instance_id_, region_name_, zone_name_);
	}	
	else {
		if (!isok2) {
			GY_THROW_EXPRESSION("Failed to get GCP Instance Metadata Zone info : HTTP Response %ld : Error \'%s\'", res2, perrstr2 ? perrstr2 : "");
		}

		GY_THROW_EXPRESSION("Empty AWS Instance Metadata Response for Zone seen");
	}	
}

void CLOUD_METADATA::set_azure_metadata()
{
	/*
	 * Refer to : https://docs.microsoft.com/en-us/azure/virtual-machines/linux/instance-metadata-service?tabs=linux
	 *
	 * For Instance ID :
	 * curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text"
	 * Output : 02aab8a4-74ef-476e-8182-f6d2ba4166a6
	 *
	 *
	 * For Region :
	 * curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text" 
	 * Output : eastus
	 *
	 *
	 * For Zone :
	 * curl -s -H Metadata:true --noproxy "*" "http://169.254.169.254/metadata/instance/compute/zone?api-version=2021-02-01&format=text"
	 * Output : 1 (This can be empty if instance spawned in regions with single instance zone).
	 *
	 */

	INFOPRINT("Starting Azure Instance Metadata Retrieval...\n");

	GY_CURL_EASY			c1;
	STRING_BUFFER<2048>		zonebuf;		
	uint64_t			cmsec = get_msec_clock();

	c1.set_url("http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01&format=text").set_user_agent("Gyeeta/1.0").set_timeout_sec(15);

	c1.set_http_header("Metadata: true");

	curl_easy_setopt(c1.get_handle(), CURLOPT_NOPROXY, "*");

	c1.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
		size_t				tsz = size * nmemb;
		char				*instance_id = (char *)userp;

		if (instance_id && tsz && contents) {
			GY_SAFE_STR_MEMCPY(instance_id, CLOUD_METADATA::MAX_INSTANCE_ID_LEN, (const char *)contents, tsz);
		}	

		return tsz;
	}, instance_id_);	

	auto			[isok, res, perrstr] = c1.send_request_blocking();

	if (!isok) {
		GY_THROW_EXPRESSION("Failed to get Azure Instance Metadata : HTTP Response %ld : Error \'%s\'", res, perrstr ? perrstr : "");
	}	

	if (*instance_id_ == 0) {
		GY_THROW_EXPRESSION("Invalid Azure Instance Metadata Response seen : No Instance ID seen");
	}	

	c1.set_url("http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text");

	c1.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
		size_t				tsz = size * nmemb;
		char				*pregion = (char *)userp;

		if (pregion && tsz && contents) {
			GY_SAFE_STR_MEMCPY(pregion, CLOUD_METADATA::MAX_ZONE_LEN, (const char *)contents, tsz);
		}	

		return tsz;
	}, region_name_);	
	
	auto			[isok2, res2, perrstr2] = c1.send_request_blocking();

	if (!isok2) {
		GY_THROW_EXPRESSION("Failed to get Azure Instance Metadata Zone info : HTTP Response %ld : Error \'%s\'", res2, perrstr2 ? perrstr2 : "");
	}	
	else if (0 == *region_name_) {
		GY_THROW_EXPRESSION("Empty Azure Instance Metadata Response for Region seen");
	}	

	c1.set_url("http://169.254.169.254/metadata/instance/compute/zone?api-version=2021-02-01&format=text");

	c1.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
		size_t				tsz = size * nmemb;
		char				*pzone = (char *)userp;

		if (pzone && tsz && contents) {
			GY_STRNCAT(pzone, CLOUD_METADATA::MAX_ZONE_LEN, (const char *)contents, tsz);
		}	

		return tsz;
	}, zone_name_);	
	
	snprintf(zone_name_, sizeof(zone_name_), "%s-", region_name_);

	c1.send_request_blocking();

	uint64_t		cmsec2 = get_msec_clock();

	INFOPRINT("Received Azure Instance Metadata in %lu msec : Instance ID \'%s\' : Region \'%s\' : Zone \'%s\'\n", cmsec2 - cmsec, instance_id_, region_name_, zone_name_);
}



} // namespace gyeeta

