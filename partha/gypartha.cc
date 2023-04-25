//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include		"gypartha.h"
#include 		"gy_paconnhdlr.h"
#include 		"gy_init_proc.h"
#include 		"gy_task_handler.h"
#include 		"gy_cgroup_stat.h"
#include 		"gy_child_proc.h"
#include 		"gy_ebpf.h"
#include 		"gy_ebpf_common.h"
#include		"gy_print_offload.h"
#include		"gy_mount_disk.h"
#include		"gy_sys_hardware.h"
#include 		"gy_socket_stat.h"
#include 		"gy_async_func.h"
#include 		"gy_scheduler.h"
#include		"gy_settings.h"
#include 		"gy_acct_taskstat.h"
#include 		"gy_sys_stat.h"
#include 		"gy_multi_proc_comm.h"
#include		"gy_rapidjson.h"
#include		"gy_query_common.h"
#include		"gy_libcurl.h"

#include 		<sys/utsname.h>

namespace gyeeta {
namespace partha {

static PARTHA_C		*pgpartha;

 
int PARTHA_C::init_all_singletons()
{
	const char		*pext[] = {".log", ".tmp"};

	GY_CURL_EASY::global_init();

	PRINT_OFFLOAD::init_singleton();

	GY_SCHEDULER::init_singletons();

	GY_SCHEDULER::start_rcu_schedules();

	pinitproc_->set_log_file_monitor(pext, GY_ARRAY_SIZE(pext), 30 * 1024 * 1024, 2);

	GY_TIMEZONE::init_singleton();

	init_subsys_maps();

	PROC_CPU_IO_STATS::init_singleton(60, "partha");

	MOUNT_HDLR::init_singleton(true /* mount_proc_if_not */, true /* mount_sys_if_not */, true /* mount_tracefs_if_not */);

	SYS_HARDWARE::init_singleton(false /* ignore_min_kern */, true /* need_root_priv */);

	if (true == SYS_HARDWARE::get_singleton()->is_mount_ns_container()) {
		get_root_mount_ns_info(OS_INFO::get_singleton(), pcmd_child_, SYS_HARDWARE::get_singleton()->is_uts_ns_container());
	}	
	
#if 0	 
	/*
	 * Code to test out multiple partha on a single node
	 */
	CONDEXEC(
		DEBUGEXECN(11,
			if (true) {
				char			testbuf[2048], parbuf[512];

				snprintf(testbuf, sizeof(testbuf), "%s/.__testpartha__.cfg", pinitproc_->get_cfg_dir());

				SCOPE_FD		scopefd(testbuf, O_RDONLY);
				int			fd = scopefd.get(), ret;
				const char		*ptmp, *pend;
				auto			psys = SYS_HARDWARE::get_singleton();
				
				if (fd > 0) {
					ret = read(fd, testbuf, sizeof(testbuf) - 1);
					if (ret > 0) {
						pend = testbuf + ret;

						testbuf[ret] = 0;

						ptmp = strstr(testbuf, "parid=");
						if (ptmp) {
							ptmp += strlen("parid=");
							if (ptmp + 32 <= pend) {
								std::memcpy(parbuf, ptmp, 32);
								parbuf[32] = 0;

								INFOPRINT("Partha Testing : Setting new Partha ID to %s\n", parbuf);
								psys->machine_id_128.set_from_string(parbuf, 32);
							}	
						}	

						ptmp = strstr(testbuf, "host=");
						if (ptmp) {
							ptmp += strlen("host=");

							ret = sscanf(ptmp, "%256[^\n]", parbuf);
							if (ret == 1) {
								INFOPRINT("Partha Testing : Setting new Partha Hostname to %s\n", parbuf);
								GY_STRNCPY(psys->os_info->node_hostname_str, parbuf, 256);
							}	
						}	
					}	
				}	
			}		
		);
	);
#endif	

	ASYNC_FUNC_HDLR::init_singleton();

	pconnhdlr_ = new PACONN_HANDLER(this);

	SYS_HARDWARE::get_singleton()->print_system_info();

	SYSTEM_STATS::init_singleton();

	CGROUP_HANDLE::init_singleton();

	TASK_HANDLER::init_singleton(true /* stats_updated_by_sock */, psettings_->is_kubernetes);
	
	DNS_MAPPING::init_singleton();

	TCP_SOCK_HANDLER::init_singleton(psettings_->response_sampling_percent, psettings_->capture_errcode, psettings_->capture_api_call);

	TASKSTATS_HDLR::init_singleton();

	auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION);
	if (schedshr) {
		schedshr->add_schedule(900, 300'000, 0, "Print Offload print stats", 
		[] { 
			auto poffload = PRINT_OFFLOAD::get_singleton();
			if (poffload) {
				poffload->print_stats();
			}	
		});
	}

	return 0;
}	


/*
 * Current format of tmp/partha_runtime.json :
{
	"debuglevel"			:	10,
	"response_sampling_percent"	:	50,
	"log_use_utc_time"		:	false,
	"is_kubernetes"			:	true
}		 	
 */

int PARTHA_C::update_runtime_cfg(char *pcfg, int sz) noexcept
{
	try {
		JSON_DOCUMENT<2048, 2048>	jdoc;
		auto				& doc = jdoc.get_doc();

		if (doc.ParseInsitu(pcfg).HasParseError()) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
				doc.GetErrorOffset(), rapidjson::GetParseError_En(doc.GetParseError()));
			return -1;
		}	

		if (auto aiter = doc.FindMember("debuglevel"); ((aiter != doc.MemberEnd()) && (aiter->value.IsInt()))) {
			int 		nlvl = aiter->value.GetInt();

			if (gdebugexecn != nlvl) {
				INFOPRINT("Log Debug Level Changes seen : New Debug Level %d : Current Debug Level %d\n\n", nlvl, gdebugexecn);

				gdebugexecn = nlvl;

				pgpartha->log_debug_level_ = nlvl;
			}
		}	

		if (auto aiter = doc.FindMember("log_use_utc_time"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
			bool 		nparam = aiter->value.GetBool();

			if (guse_utc_time != nparam) {

				INFOPRINT("Log Print Timezone Changes seen : New UTC Time Zone to be used? %d : Current is %d\n\n", 
					nparam, guse_utc_time);

				guse_utc_time = nparam;
			}
		}	

		if (auto aiter = doc.FindMember("response_sampling_percent"); ((aiter != doc.MemberEnd()) && (aiter->value.IsInt()))) {
			int 		nparam = aiter->value.GetInt();

			if (nparam >= 0 && nparam <= 100) {
				auto ptcp = TCP_SOCK_HANDLER::get_singleton();
				if (ptcp) {
					if (ptcp->pebpf_) {
						INFOPRINT_OFFLOAD("Response Time Sampling Percent changes are seen : New Run time percent is %hhu%%\n", nparam);
						ptcp->pebpf_->set_sampling_pct(nparam);
					}	
				}
			}
		}	

		/*
		if (auto aiter = doc.FindMember("enable_response_probe"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
			bool 		enable = aiter->value.GetBool();

			auto ptcp = TCP_SOCK_HANDLER::get_singleton();
			if (ptcp) {
				if (ptcp->pebpf_) {
					INFOPRINT_OFFLOAD("Response kprobe runtime changes are seen : Response probes need to be %s\n", enable ? "enabled" : "disabled");
					ptcp->pebpf_->set_resp_probe(enable);
				}	
			}
		}
		*/

		if (auto aiter = doc.FindMember("is_kubernetes"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
			bool 		enable = aiter->value.GetBool();

			auto ptask = TASK_HANDLER::get_singleton();
			if (ptask) {
				ptask->set_is_kubernetes(enable);
			}
		}	

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while parsing partha_runtime.json : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		 
}	

// Mutable pjson
PARTHA_C::PA_SETTINGS_C::PA_SETTINGS_C(char *pjson)
{
	int			ret;
	
	assert(pjson);

	JSON_DOCUMENT<2048, 2048>	jdoc, ejdoc;
	auto				& doc = jdoc.get_doc();
	auto				& edoc = ejdoc.get_doc();

	STACK_JSON_WRITER<8192, 4096>	ewriter;
	const char			*penvjson, *penv;
	
	JSON_MEM_ITER			aiter;

	// First populate config json from env if any : env will override config file options
	ewriter.StartObject();
	
	penv = getenv("CFG_CLUSTER_NAME");
	if (penv) {
		ewriter.KeyConst("cluster_name");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_CLOUD_TYPE");
	if (penv) {
		ewriter.KeyConst("cloud_type");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}	
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_REGION_NAME");
	if (penv) {
		ewriter.KeyConst("region_name");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_ZONE_NAME");
	if (penv) {
		ewriter.KeyConst("zone_name");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_SHYAMA_HOSTS");
	if (penv) {
		ewriter.KeyConst("shyama_hosts");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kArrayType);
	}	

	penv = getenv("CFG_SHYAMA_PORTS");
	if (penv) {
		ewriter.KeyConst("shyama_ports");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kArrayType);
	}	

	penv = getenv("CFG_RESPONSE_SAMPLING_PERCENT");
	if (penv) {
		ewriter.KeyConst("response_sampling_percent");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	penv = getenv("CFG_CAPTURE_ERRCODE");
	if (penv) {
		ewriter.KeyConst("capture_errcode");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);		// kNumberType is just a placeholder
	}	

	penv = getenv("CFG_ENABLE_TASK_DELAYS");
	if (penv) {
		ewriter.KeyConst("enable_task_delays");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);	
	}	

	penv = getenv("CFG_AUTO_RESPAWN_ON_EXIT");
	if (penv) {
		ewriter.KeyConst("auto_respawn_on_exit");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	penv = getenv("CFG_IS_KUBERNETES");
	if (penv) {
		ewriter.KeyConst("is_kubernetes");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	penv = getenv("CFG_LOG_USE_UTC_TIME");
	if (penv) {
		ewriter.KeyConst("log_use_utc_time");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	ewriter.EndObject();

	penvjson = ewriter.get_string();

	INFOPRINT("Partha Config from config file is : \n%s\n\nPartha Config from Environment Variables or Command Line Options is : \n\t%s\n\n", pjson, penvjson); 

	if (doc.ParseInsitu(pjson).HasParseError()) {
		GY_THROW_EXCEPTION("Invalid Partha Config : Not valid JSON : Error at offset %lu : Error is \'%s\'", 
			doc.GetErrorOffset(), rapidjson::GetParseError_En(doc.GetParseError()));
	}	

	if (edoc.Parse(penvjson).HasParseError()) {
		GY_THROW_EXCEPTION("Partha Config Environment Variables set but not valid JSON : Error at offset %lu : Error is \'%s\'", 
			edoc.GetErrorOffset(), rapidjson::GetParseError_En(edoc.GetParseError()));
	}	

	if (false == doc.IsObject()) {
		GY_THROW_EXCEPTION("Invalid Partha Config : Config not in JSON Object format");
	}	

	/*
	 * Current format of cfg/partha_main.json :
	{
		"cluster_name"			:	"cluster1",
		"cloud_type"			:	"aws",
		"region_name"			:	"us-east-1",
		"zone_name"			:	"us-east-1a",

		"shyama_hosts" 			:	[ "shyama1.test1.local", "shyama2.test2.local" ],
		"shyama_ports"			:	[ 10037, 10037 ],

		"response_sampling_percent"	:	100,
		"capture_errcode"		:	true,
		"auto_respawn_on_exit"		:	true,
		"is_kubernetes"			:	true,
		"enable_task_delays"		:	2,
		"log_use_utc_time"		:	false
	}
	 */ 


	if (aiter = edoc.FindMember("cluster_name"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_CLUSTER_NAME_LEN, "Cluster Name from Environment Variable", 
					true /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(cluster_name, aiter->value.GetString(), sizeof(cluster_name));
	}
	else if (aiter = doc.FindMember("cluster_name"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_CLUSTER_NAME_LEN, "Cluster Name from config", true /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(cluster_name, aiter->value.GetString(), sizeof(cluster_name));
	}


	if (aiter = edoc.FindMember("cloud_type"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Cloud Type from Environment Variable", true /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(cloud_type, aiter->value.GetString(), sizeof(cloud_type));
	}
	else if (aiter = doc.FindMember("cloud_type"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Cloud Type from config", true /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(cloud_type, aiter->value.GetString(), sizeof(cloud_type));
	}


	if (aiter = edoc.FindMember("region_name"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Region Name from Environment Variable", false /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(region_name, aiter->value.GetString(), sizeof(region_name));
	}
	else if (aiter = doc.FindMember("region_name"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Region Name from config", false /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(region_name, aiter->value.GetString(), sizeof(region_name));
	}


	if (aiter = edoc.FindMember("zone_name"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Zone Name from Environment Variable", false /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(zone_name, aiter->value.GetString(), sizeof(zone_name));
	}
	else if (aiter = doc.FindMember("zone_name"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Zone Name from config", false /* firstalphaonly */, true /* emptyok */);

		GY_STRNCPY(zone_name, aiter->value.GetString(), sizeof(zone_name));
	}


	if (aiter = edoc.FindMember("shyama_hosts"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsString()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config from Environment Variable : Mandatory Config option \'shyama_hosts\' Array element not of string type");
			}	
			shyama_hosts.emplace_back(aiter->value[i].GetString());
		}
	}
	else if (aiter = doc.FindMember("shyama_hosts"); ((aiter != doc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsString()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'shyama_hosts\' Array element not of string type");
			}	
			shyama_hosts.emplace_back(aiter->value[i].GetString());
		}
	}
	else {
		GY_THROW_EXCEPTION("Invalid Partha Config : Mandatory Config option \'shyama_hosts\' not found or is not an Array Type in config json");
	}	


	if (aiter = edoc.FindMember("shyama_ports"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsUint()) {
				GY_THROW_EXCEPTION("Invalid Partha Config from Environment Variable : Mandatory Config option \'shyama_ports\' is not an Array of Ports");
			}	
			shyama_ports.emplace_back(aiter->value[i].GetUint());
		}
	}
	else if (aiter = doc.FindMember("shyama_ports"); ((aiter != doc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsUint()) {
				GY_THROW_EXCEPTION("Invalid Partha Config : Mandatory Config option \'shyama_ports\' is not an Array of Ports");
			}	
			shyama_ports.emplace_back(aiter->value[i].GetUint());
		}
	}
	else {
		GY_THROW_EXCEPTION("Invalid Partha Config : Mandatory Config option \'shyama_ports\' not found or is not an Array Type in config json");
	}	

	if (shyama_ports.size() != shyama_hosts.size()) {
		GY_THROW_EXCEPTION("Invalid Partha Config : Config option shyama_ports and shyama_hosts have different array sizes");
	}
	else if ((shyama_hosts.size() == 0) || (shyama_hosts.size() > 16)) {
		GY_THROW_EXCEPTION("Invalid Partha Config : Config option shyama_hosts array size %lu not valid : Max allowed 16 elements", shyama_hosts.size());
	}	

	
	if (aiter = edoc.FindMember("response_sampling_percent"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint()))) {
		uint32_t		pct = aiter->value.GetUint();

		if (pct > 100) {
			pct = 100;
		}

		response_sampling_percent = pct;
	}
	else if (aiter = doc.FindMember("response_sampling_percent"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint()))) {
		uint32_t		pct = aiter->value.GetUint();

		if (pct > 100) {
			pct = 100;
		}

		response_sampling_percent = pct;
	}

	if (aiter = edoc.FindMember("capture_errcode"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsBool()))) {
		capture_errcode = aiter->value.GetBool();
	}	
	else if (aiter = doc.FindMember("capture_errcode"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		capture_errcode = aiter->value.GetBool();
	}	

#if 0		
	if (aiter = edoc.FindMember("capture_api_call"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsBool()))) {
		capture_api_call = aiter->value.GetBool();
	}	
	else if (aiter = doc.FindMember("capture_api_call"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		capture_api_call = aiter->value.GetBool();
	}	
#endif


	if (aiter = edoc.FindMember("enable_task_delays"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsInt()))) {
		enable_task_delays = aiter->value.GetInt();
	}	
	else if (aiter = doc.FindMember("enable_task_delays"); ((aiter != doc.MemberEnd()) && (aiter->value.IsInt()))) {
		enable_task_delays = aiter->value.GetInt();
	}	

	if (aiter = edoc.FindMember("auto_respawn_on_exit"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsBool()))) {
		auto_respawn_on_exit = aiter->value.GetBool();
	}	
	else if (aiter = doc.FindMember("auto_respawn_on_exit"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		auto_respawn_on_exit = aiter->value.GetBool();
	}	

	if (aiter = edoc.FindMember("is_kubernetes"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsBool()))) {
		is_kubernetes = aiter->value.GetBool();
	}	
	else if (aiter = doc.FindMember("is_kubernetes"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		is_kubernetes = aiter->value.GetBool();
	}	

	if (aiter = edoc.FindMember("log_use_utc_time"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsBool()))) {
		log_use_utc_time = aiter->value.GetBool();
	}	
	else if (aiter = doc.FindMember("log_use_utc_time"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		log_use_utc_time = aiter->value.GetBool();
	}	
}

static std::atomic<int>		gsig_mon_rcvd(0);	

int handle_signal_mon_proc(int signo)
{
	gsig_mon_rcvd.store(1);

	return signo;
}	

void * child_reader_thread(void * arg)
{
	GY_PKT_POOL			*pfuncpool = (GY_PKT_POOL *)arg;
	alignas (8) uint8_t		comm[sizeof(COMM_MSG_C)];
	COMM_MSG_C			*pcomm;
	PKT_RET_E 			retp;
	uint32_t			count;
	int				ret;

	do {
		retp = pfuncpool->pool_read_buffer(comm, sizeof(comm), &count, 0 /* is_non_block */);

		if (retp != PKT_RET_SUCCESS) {
			INFOPRINT("Child Reader Thread exiting as writer seems to have exited.\n");
			break;
		}

		if (count < sizeof(COMM_MSG_C)) {
			DEBUGEXECN(1,
				ERRORPRINT("Internal Error (%u) : Invalid number of bytes %u from pool read\n", __LINE__, count); 
			);	
			continue;
		}

		pcomm = reinterpret_cast<COMM_MSG_C *>(comm);

		if (pcomm->is_valid_magic()) {
			pcomm->exec_func(nullptr);

		}

	} while (1);

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(child_reader_thread);

void * child_fork_thread(void * arg)
{
	GY_PKT_POOL			*pfuncpool = (GY_PKT_POOL *)arg;
	alignas (8) uint8_t		comm[sizeof(COMM_MSG_C)];
	COMM_MSG_C			*pcomm;
	PKT_RET_E 			retp;
	uint32_t			count;
	int				ret;
	uint64_t			ninvalid = 0, nerrors = 0, nforks = 0, nwaits = 0;
	pid_t				pid;
	time_t				tcurr = time(nullptr), told = tcurr;

	do {
		retp = pfuncpool->pool_read_buffer(comm, sizeof(comm), &count, 0 /* is_non_block */, nforks > nwaits ? 1000 : 0);

		if (nforks > nwaits) {
			// Wait indefinitely if too many child processes spawned
			for (int i = 0; i < 8; i++) {
				pid = waitpid(-1, nullptr, (nforks > nwaits + 8) ? 0 : WNOHANG);

				if (pid > 0) {
					nwaits++;
				}
				else if (pid == 0) {
					break;
				}	
			}
		}	

		if (retp != PKT_RET_SUCCESS) {
			if (retp == PKT_BLOCKING) {
				continue;
			}

			INFOPRINT("Child Reader Thread exiting as writer seems to have exited.\n");
			break;
		}

		if (count < sizeof(COMM_MSG_C)) {
			DEBUGEXECN(1,
				ERRORPRINT("Internal Error (%u) : Invalid number of bytes %u from pool read\n", __LINE__, count); 
			);	
			ninvalid++;
			continue;
		}

		pcomm = reinterpret_cast<COMM_MSG_C *>(comm);

		if (pcomm->is_valid_magic()) {
			pid = fork();

			if (pid > 0) {
				nforks++;
			}	
			else if (pid == 0) {
				pcomm->exec_func(nullptr);
				_exit(EXIT_SUCCESS);
			}
			else {
				nerrors++;
				PERRORPRINT_OFFLOAD("Failed to fork process for child cmd");
			}	
		}
		else {
			ninvalid++;
		}	

		tcurr = time(nullptr);
		if (tcurr - told > 30) {
			told = tcurr;

			INFOPRINT_OFFLOAD("Child Shared Pool executed %lu forked messages, PIDs waited so far is %lu : Fork errors %lu : Invalid Msg %lu\n",
				nforks, nwaits, nerrors, ninvalid);
		}	

	} while (1);

	return nullptr;
}	
MAKE_PTHREAD_FUNC_WRAPPER(child_fork_thread);

static int partha_monitor_proc(int argc, char **argv, CHILD_PROC * pchildproc, bool auto_respawn_on_exit) noexcept
{
	do {
		static pid_t		bpf_parent;
		const char 		* const old_argv0 = strdup(argv[0]), *new_argv0 = "parmon";	
		bool			argv_upd = false, bret;
		int			ret, old_suid_dumpable = -1;	
		char			old_core_pattern[256] {};

		GY_SCOPE_EXIT {
			if (old_argv0) free(const_cast<char *>(old_argv0));
		};	

		if (old_argv0 && (strlen(argv[0]) >= strlen(new_argv0))) { 

			INFOPRINT("Setting process name of partha monitor child process %d to %s\n", getpid(), new_argv0);
			
			size_t 		sz1 = strlen(argv[0]);

			std::memset(argv[0], ' ', sz1);

			strcpy(argv[0], new_argv0);
			prctl(PR_SET_NAME, (unsigned long)argv[0]);

			argv_upd = true;
		}
		
		bpf_parent = pchildproc->ppid_;

		setsid();

		try {
			CONDEXEC(
				if (PARTHA_C::get_singleton()->allow_core_) {
					char			tbuf[256];
					int			oldval, fdv;

					ret = read_file_to_buffer("/proc/sys/kernel/core_pattern", tbuf, sizeof(tbuf) - 1);
					if (ret > 0 && ret != sizeof(tbuf) - 1) {
						tbuf[ret] = '\0';

						if (0 != memcmp(tbuf, "core.", 5)) {
							GY_STRNCPY(old_core_pattern, tbuf, sizeof(old_core_pattern));

							SCOPE_FD	scfd("/proc/sys/kernel/core_pattern", O_WRONLY);
							
							fdv = scfd.get();
							if (fdv >= 0) {
								ret = write(fdv, "core.%p", GY_CONST_STRLEN("core.%p"));
								if (ret <= 0) {
									*old_core_pattern = 0;
								}
							}
						}
					}

					
					ret = read_file_to_buffer("/proc/sys/fs/suid_dumpable", tbuf, sizeof(tbuf) - 1);
					if (ret > 0) {
						tbuf[ret] = '\0';

						bret = string_to_number(tbuf, oldval);
						if (bret && (oldval != 1)) {
							SCOPE_FD	scfd("/proc/sys/fs/suid_dumpable", O_WRONLY);
							
							fdv = scfd.get();
							if (fdv >= 0) {
								ret = write(fdv, "1", 1);
								if (ret > 0) {
									old_suid_dumpable = oldval;
								}
							}
						}
					}
				}
			);

			ASYNC_FUNC_HDLR::init_singleton();
			
			GY_SCHEDULER::init_singletons(false);

			GY_SCHEDULER::cancel_rcu_schedules();	// If singleton was already initialized

			PROC_CPU_IO_STATS::init_singleton(60, "parmon");

			GY_TIMEZONE::init_singleton();

			GY_THREAD			pooltid("Shared Pool reader thread", GET_PTHREAD_WRAPPER(child_reader_thread), pchildproc->get_shared_pool());

			auto poolstop = [](void *arg)
			{
				GY_PKT_POOL		*pfpool = (GY_PKT_POOL *)arg;

				if (pfpool) {
					pfpool->pool_set_wr_exited();
				}	
			};

			pooltid.set_thread_stop_function(poolstop, pchildproc->get_shared_pool());
			
			while (true) {
				COMM_MSG_C		msg;
				uint8_t			tbuf[512];
				int			ret;

				ret = COMM_MSG_C::recv_msg(pchildproc->get_socket(), msg, tbuf, sizeof(tbuf), true /* exec_func */, false /* is_nonblock */); 
				if (ret == -1) {
					if (false == is_socket_still_connected(pchildproc->get_socket())) {
						INFOPRINT("Partha Monitor process %d : Parent process %d seems to be exited. "
								"Cleaning up for kprobes of PID %d...\n", 
							getpid(), pchildproc->ppid_, pchildproc->ppid_);

						clear_bpf_kprobes(pchildproc->ppid_);

						::close(pchildproc->get_socket());
						break;
					}	
				}	
			}	

			CONDEXEC(
				if (0 != *old_core_pattern) {
					SCOPE_FD	scfd("/proc/sys/kernel/core_pattern", O_WRONLY);
					int		fdv = scfd.get();

					if (fdv >= 0) {
						old_core_pattern[sizeof(old_core_pattern) - 1] = 0;

						(void)write(fdv, old_core_pattern, strlen(old_core_pattern));
					}
				}

				if (old_suid_dumpable != -1) {
					SCOPE_FD	scfd("/proc/sys/fs/suid_dumpable", O_WRONLY);
					int		fdv = scfd.get();

					if (fdv >= 0) {
						char		tbuf[32];

						ret = snprintf(tbuf, sizeof(tbuf) - 1, "%d", old_suid_dumpable);

						(void)write(fdv, tbuf, ret);
					}
				}
			);
			
			if ((auto_respawn_on_exit == false) || (false == PARTHA_C::get_singleton()->init_completed_))  {
				INFOPRINT("Partha Monitor process (parmon) exiting now...\n");
				_exit(EXIT_SUCCESS);
			}
				
			if (0 != gsig_mon_rcvd.load()) {
				INFOPRINT("Partha Monitor process (parmon) exiting as signal to exit %d was received earlier...\n", gsig_mon_rcvd.load());
				_exit(EXIT_SUCCESS);
			}	

			for (int i = 0; i < 15; ++i) {
				gy_nanosleep(1, 0);

				if (0 != gsig_mon_rcvd.load()) {
					INFOPRINT("Partha Monitor process exiting as signal %d was received earlier...\n", gsig_mon_rcvd.load());
					_exit(EXIT_SUCCESS);
				}	
			}

			if ((getppid() == pchildproc->ppid_) && (pchildproc->ppid_ != 1)) {
				char			buf1[128];
				struct stat		stat1;

				snprintf(buf1, sizeof(buf1), "/proc/%d/status", pchildproc->ppid_);

				if (0 == stat(buf1, &stat1)) {

					ERRORPRINT("Parent process of partha Monitor PID %d is still running although exit signal was received. Exiting without re-spawning partha\n",
						pchildproc->ppid_);
					_exit(EXIT_FAILURE);
				}
			}
				
			NOTEPRINT("Partha Monitor process : starting new partha process by exec as parent partha process has exited...\n\n");
			
			if (argv_upd && old_argv0) {
				strcpy(argv[0], old_argv0);
			}	
			
			for (int i = 3; i < 32767; ++i) {
				::close(i);
			}
				
			execv(argv[0], argv);
				
			PERRORPRINT("Failed to execv partha binary %s : Exiting without re-execing...", argv[0]);
			_exit(EXIT_FAILURE);

		}
		GY_CATCH_EXCEPTION(	
			ERRORPRINT("Exception caught in partha Monitor handling : %s\n", GY_GET_EXCEPT_STRING);
		);
	}
	while (true);	
	
	return -1;
}	 

static int partha_cmd_proc(CHILD_PROC *pchildproc) noexcept
{
	do {
		try {
			// Set as root
			(void)seteuid(0);

			ASYNC_FUNC_HDLR::init_singleton();
			
			GY_SCHEDULER::init_singletons(false);

			GY_SCHEDULER::cancel_rcu_schedules();	// If singleton was already initialized

			PROC_CPU_IO_STATS::init_singleton(60, "partha_command_proc");

			GY_TIMEZONE::init_singleton();

			// Spawn the Shared Pool reader thread
			GY_THREAD			pooltid("Shared Pool reader thread", GET_PTHREAD_WRAPPER(child_fork_thread), pchildproc->get_shared_pool());

			auto poolstop = [](void *arg)
			{
				GY_PKT_POOL		*pfpool = (GY_PKT_POOL *)arg;

				if (pfpool) {
					pfpool->pool_set_wr_exited();
				}	
			};

			pooltid.set_thread_stop_function(poolstop, pchildproc->get_shared_pool());
			
			while (true) {
				COMM_MSG_C		msg;
				uint8_t			tbuf[512];
				int			ret;

				ret = COMM_MSG_C::recv_msg(pchildproc->get_socket(), msg, tbuf, sizeof(tbuf), true /* exec_func */, false /* is_nonblock */); 
				if (ret == -1) {
					if (false == is_socket_still_connected(pchildproc->get_socket())) {
						INFOPRINT("partha command process %d : Parent process %d seems to be exited.\n",
							getpid(), pchildproc->ppid_);						
						::close(pchildproc->get_socket());
						break;
					}	
				}	
			}	
			
			if ((getppid() == pchildproc->ppid_) && (pchildproc->ppid_ != 1)) {
				char			buf1[128];
				struct stat		stat1;

				snprintf(buf1, sizeof(buf1), "/proc/%d/status", pchildproc->ppid_);

				if (0 == stat(buf1, &stat1)) {

					ERRORPRINT("Parent process of partha command PID %d is still running although exit signal was received. Exiting...\n",
						pchildproc->ppid_);
					_exit(EXIT_FAILURE);
				}
			}

			INFOPRINT("Partha Command process exiting as parent signalled to quit ...\n");

			_exit(EXIT_SUCCESS);
		}
		GY_CATCH_EXCEPTION(	
			ERRORPRINT("Exception caught in partha command process handling : %s\n", GY_GET_EXCEPT_STRING);
		);
	}
	while (true);	
	
	return -1;
}	

int PARTHA_C::verify_caps_kernhdr(bool is_bpf_core, bool trybcc)
{
	constexpr const char	*capstring[] = 				{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_IPC_LOCK", "CAP_KILL",
											"CAP_MAC_ADMIN", "CAP_MKNOD", "CAP_SYS_CHROOT", "CAP_SYS_RESOURCE", "CAP_SETPCAP",
											"CAP_SYS_PTRACE", "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SYS_MODULE", "CAP_SETUID"};
	constexpr cap_value_t	caparr[GY_ARRAY_SIZE(capstring)] = 	{CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,CAP_FSETID, CAP_IPC_LOCK, CAP_KILL,
											CAP_MAC_ADMIN, CAP_MKNOD, CAP_SYS_CHROOT, CAP_SYS_RESOURCE, CAP_SETPCAP,
											CAP_SYS_PTRACE, CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_MODULE, CAP_SETUID};

	for (size_t i = 0; i < GY_ARRAY_SIZE(capstring); ++i) {
		if (false == proc_cap_.is_cap_set(caparr[i])) {
			ERRORPRINT("Required File Capabilities for partha not set : Please set the following capabilities : "
					"CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER,CAP_FSETID, CAP_IPC_LOCK, CAP_KILL, CAP_MAC_ADMIN, CAP_MKNOD, "
					"CAP_SYS_CHROOT, CAP_SYS_RESOURCE, CAP_SETPCAP, CAP_SYS_PTRACE, CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_MODULE, CAP_SETUID\n");

			GY_THROW_EXCEPTION("partha required file capability %s not found : Priviliges missing", capstring[i]);
		}	
	}
		

	struct utsname		uts;	
	char			kernpath[512];
	struct stat		stat1;
	int			ret, bret = 0;

	if (is_bpf_core) {	
		if (host_btf_enabled(true /* check_module */)) {
			return 0;
		}

		if (trybcc) {
			bret = 1;
		}
		else {
			GY_THROW_EXCEPTION("BPF CO-RE Support not detected on this host. Cannot run this binary.");
		}
	}

	ret = uname(&uts);
	if (!ret) {
		snprintf(kernpath, sizeof(kernpath), "/lib/modules/%s/build/", uts.release);

		ret = stat(kernpath, &stat1);
		if (ret == -1) {
			/*
			 * Check if BTF available without modules
			 */
			if ((host_btf_enabled(false /* check_module */)) && (0 != stat("/proc/net/ip_vs_conn", &stat1))) {
				return 0;
			}

			GY_THROW_EXCEPTION("Missing Kernel Headers Package : These are required by partha : Please install your Distribution Kernel Headers package");
		}
	}	

	return bret;
}	

/*
 * Kernel 5.14+ task delays related checks...
 */
void PARTHA_C::check_task_stats() noexcept
{
	if (psettings_->enable_task_delays > 0) {
		char			tbuf[32];
		int			val, fdv, ret;
		bool			bret;

		ret = read_file_to_buffer("/proc/sys/kernel/task_delayacct", tbuf, sizeof(tbuf) - 1, -1, false /* read_syscall_till_err */);
		if (ret > 0 && ret != sizeof(tbuf) - 1) {
			tbuf[ret] = '\0';

			bret = string_to_number(tbuf, val);

			if (bret && val == 0) {
				uid_t			olduid = geteuid();

				if (olduid != 0) {
					
					ret = seteuid(0);

					if (ret) {
						PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to set effective uid for Task Delays setting");
					}	
				}

				fdv = ::open("/proc/sys/kernel/task_delayacct", O_RDWR);
				if (fdv >= 0) {
					ret = ::write(fdv, "1\n", 2);
					if (ret < 0) {
						WARNPRINT("Task Delays not enabled. Failed to enable delays...\n");	
					}
					else {
						INFOPRINT("Task Delays not enabled by default. Enabling Task Delays for newer processes as per config param %d\n", 
							psettings_->enable_task_delays);
					}	

					::close(fdv);
				}
				else {
					PERRORPRINTCOLOR(GY_COLOR_RED, "Failed to open Task Delays file for setting delays");
				}	

				if (fdv > 0 && psettings_->enable_task_delays > 1) {
					constexpr const char	strsys[] = "\nkernel.task_delayacct = 1\n";

					fdv = ::open("/proc/1/root/etc/sysctl.conf", O_RDWR);
					if (fdv >= 0) {
						lseek(fdv, 0, SEEK_END);
						
						ret = ::write(fdv, strsys, sizeof(strsys) - 1);
						if (ret > 0) {
							INFOPRINT("Enabling Task Delays after boot as per config param %d\n", psettings_->enable_task_delays);
						}	
					}
					
					::close(fdv);
				}	
			}
			else {
				INFOPRINT("Task Delays are enabled by default...\n");
			}	
		}
	}
}


PARTHA_C::PARTHA_C(int argc, char **argv, bool nolog, const char *logdir, const char *cfgdir, const char *tmpdir, bool allow_core, bool trybcc)
	: proc_cap_(getpid()), log_debug_level_(gdebugexecn), allow_core_(allow_core)
{
	pid_t			childpid1, childpid2;
	char			logpath[GY_PATH_MAX], descbuf[128];
	int			ret;
	bool			is_bpf_core = GY_EBPF::is_bpf_core();

	ret = verify_caps_kernhdr(is_bpf_core, trybcc);

	if (ret && trybcc && is_bpf_core) {
		/*
		 * Need to execv the partha-bcc binary
		 */

		char			*pname;
		struct stat		stat1;

		if ((pname = string_ends_with(argv[0], "partha-bpf"))) {
			memcpy(pname, "partha-bcc", GY_CONST_STRLEN("partha-bcc"));

			ret = stat(argv[0], &stat1);
			if (ret) {
				GY_THROW_EXCEPTION("BPF CO-RE not supported and partha-bcc binary not found at \'%s\'", argv[0]);
			}	

			execv(argv[0], argv);

			PERRORPRINT("BPF CO-RE not supported and failed to execv partha-bcc binary %s : Exiting...", argv[0]);
			_exit(EXIT_FAILURE);
		}

		GY_THROW_EXCEPTION("BPF CO-RE not supported and partha-bpf binary name not seen in execeuted process name \'%s\'", argv[0]);
	}	

	snprintf(descbuf, sizeof(descbuf), "partha - Gyeeta's Host Agent (using %s) : Version %s", is_bpf_core ? "BPF CO-RE" : "BCC", get_version_str());
		
	pgpartha = this;

	pinitproc_ = new INIT_PROC(argc, argv, true /* handle_signals */, false /* exit_on_parent_kill */, true /* chown_if_root */,	
		nolog ? nullptr : logdir, "partha.log", "partha.log", 0 /* log_wrap_size */, false /* rename_old_log */,
		descbuf, !allow_core, true /* set_sessionid */, cfgdir, tmpdir, "partha.lock",
		true /* close_stdin */, 2 * 1024 * 1024 /* max_stacksize */, 2 * 1024 * 1024 /* min_stacksize */, 65535 /* min_openfiles */, 2048 /* min_nproc */, false /* throw_if_ulimit */, 
		guse_utc_time, true /* unbuffered_stdout */);
	
	pinitproc_->is_chown_uid_gid(chown_uid_, chown_gid_);

	if (chown_uid_ || chown_gid_) {
		INFOPRINT("All new files created will have their ownership set to UID %d GID %d\n", chown_uid_, chown_gid_);
	}
		
	if (true) {
		char			cfgfile[GY_PATH_MAX], *preadbuf = nullptr;
		const char		*penv;
		struct stat		stat1;
		size_t			readsz = 0;

		// First check if CFG_JSON_FILE env set
		penv = getenv("CFG_JSON_FILE");
		if (penv) {
			GY_STRNCPY(cfgfile, penv, sizeof(cfgfile));

			INFOPRINT("Using %s as the partha Config file as per environment variable CFG_JSON_FILE ...\n", cfgfile);
		}
		else {
			snprintf(cfgfile, sizeof(cfgfile), "%s/partha_main.json", pinitproc_->get_cfg_dir());
		}
			
		ret = stat(cfgfile, &stat1);
		if (ret != 0) {
			if (!penv) {
				WARNPRINT("Partha Config file not found : %s : Will try to get config from environment variables...\n", cfgfile);
				preadbuf = strdup("{}");
			}
		}
		else {
			preadbuf = read_file_to_alloc_buffer(cfgfile, &readsz, 512 * 1024);
		}

		if (!preadbuf) {
			GY_THROW_SYS_EXCEPTION("Failed to read global partha config file %s%s", cfgfile, penv ? " as per CFG_JSON_FILE env" : "");
		}	

		GY_SCOPE_EXIT {
			free(preadbuf);
		};	

		psettings_ = new PA_SETTINGS_C(preadbuf); 
	}

	if (psettings_->log_use_utc_time) {
		INFOPRINT("All subsequent log timestamps will be in UTC timezone...\n\n");
		guse_utc_time = psettings_->log_use_utc_time;
	}

	if (pinitproc_->is_log_to_file()) {
		// Set the SIGSEGV callback to log the stack strace to a separate log file
		auto sigcb = [](int signo) noexcept -> int
		{
			try {
				if (false == GY_SIGNAL_HANDLER::is_signal_fatal(signo)) {
					return 0;	
				}	  
			
				char			path[GY_PATH_MAX];

				snprintf(path, sizeof(path), "%s/partha_crash.log", PARTHA_C::get_singleton()->pinitproc_->get_log_dir());

				truncate_file_wrap_last(path, 1024 * 1024, 256 * 1024);

				char			buf[2048];
				int			fdo, nbytes = 0;
				ssize_t			sret;
				off_t			curroff, loff;

				fdo = open(path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0660);
				if (fdo == -1) {
					PERRORUNLOCKPRINT("Failed to open crash log file %s : Exiting immediately...", path);
					return 0;
				}
					
				loff = lseek(STDERR_FILENO, 0, SEEK_CUR);

				if (loff > 65535) {
					curroff = loff - 65535;
				}
				else {
					curroff = 0;
				}	

				while (1) {
					sret = pread(STDERR_FILENO, buf, sizeof(buf), curroff);
					if (sret <= 0) {
						break;
					}	

					curroff	+= sret;

					(void)write(fdo, buf, sret);

					if (curroff > loff)  {
						break;
					}	
				}

				ERRORFDUNLOCKPRINT(fdo, "partha process was signalled a fatal signal %s as per the above stack trace\n", gy_signal_str(signo));
				close(fdo);
				
				return 0; 
			}
			catch(...) {
				return -1;
			}		
		};	

		GY_SIGNAL_HANDLER::get_singleton()->set_signal_param(nullptr, sigcb, true);
	}
	
	// Spawn the multi process buffer handler
	MULTI_COMM_SINGLETON::init_singleton();

	INFOPRINT("Spawning the partha monitor \'parmon\' and command handler processes ...\n"); 

	if (!nolog) {
		snprintf(logpath, sizeof(logpath), "%s/parmon.log", logdir);
	}
	else {
		*logpath = '\0';	
	}		

	pcleanup_child_ = new CHILD_PROC(nolog, logpath, logpath, false /* exit_on_parent_kill */, true /* use_socket_pair */, 
				true /* use_shared_pool */, 128, sizeof(COMM_MSG_C), handle_signal_mon_proc, true /* signal_callback_will_exit */);

	childpid1 = pcleanup_child_->fork_child("parmon", true /* set_thr_name */, "partha cleanup and monitor process", O_APPEND,
					3, 1024, chown_uid_, chown_gid_); 
	if (childpid1 == 0) {
		// Within child
		partha_monitor_proc(argc, argv, pcleanup_child_, psettings_->auto_respawn_on_exit);

		_exit(EXIT_FAILURE);
	}

	if (!nolog) {
		snprintf(logpath, sizeof(logpath), "%s/partha_cmd_child.log", logdir);
	}
	else {
		*logpath = '\0';	
	}		

	pcmd_child_ = new CHILD_PROC(nolog, logpath, logpath, true /* exit_on_parent_kill */, true /* use_socket_pair */, 
			true /* use_shared_pool */, 128, sizeof(COMM_MSG_C), nullptr, false /* signal_callback_will_exit */);

	childpid2 = pcmd_child_->fork_child("partha_cmd_child", false /* set_thr_name */, "partha command exec process", O_APPEND, 3, 1024, chown_uid_, chown_gid_); 

	if (childpid2 == 0) {
		// Within child
		partha_cmd_proc(pcmd_child_);

		_exit(EXIT_FAILURE);
	}

	COMM_MSG_C			troot;
	
	troot.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		// Set all system init
		PARTHA_C::get_singleton()->check_task_stats();
		return 0;
	};	

	ret = COMM_MSG_C::send_msg_locked(pcmd_child_->get_socket(), pcmd_child_->get_mutex(), troot, nullptr, false /* is_nonblock */); 
	assert (ret == 0);

	// Exec this after the child processes have been spawned
	init_all_singletons();

	init_completed_ = true;

	COMM_MSG_C			tmsg;
	
	tmsg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		PARTHA_C::get_singleton()->init_completed_ = true;
		return 0;
	};	

	ret = COMM_MSG_C::send_msg_locked(pcleanup_child_->get_socket(), pcleanup_child_->get_mutex(), tmsg, nullptr, false /* is_nonblock */); 
	assert (ret == 0);
	
	INFOPRINT("Partha Initialization Completed Successfully...\n\n");
}	

int PARTHA_C::update_server_status(const char *status) noexcept
{
	if (!(pinitproc_->get_tmp_dir() && *pinitproc_->get_tmp_dir())) {
		return -1;
	}

	char			dirbuf[GY_PATH_MAX];

	snprintf(dirbuf, sizeof(dirbuf), "%s/server_conn_status.log", pinitproc_->get_tmp_dir());

	SCOPE_FD		scopefd(dirbuf, O_RDWR | O_CREAT | O_TRUNC, 0640);
	int			fd, ret;

	fd = scopefd.get();
	if (fd < 0) {
		return -1;
	}	

	ret = ::write(fd, status, strlen(status));

	return ret;
}

PARTHA_C * PARTHA_C::get_singleton() noexcept
{
	return pgpartha;
}	

} // namespace partha
} // namespace gyeeta


using namespace 	gyeeta;
using namespace 	gyeeta::partha;

static void partha_usage(const char *pname) noexcept
{
	IRPRINT("\nUsage : %s \n"	/* Keep this \n as the runpartha.sh skips the first line */
			"\t\t--nolog (Use if no separate log files : Will directly write to stdout/stderr : Will override --logdir if specified)\n"
			"\t\t--logdir <Directory where log files are created> (Optional : Default ./log)\n"
			"\t\t--tmpdir <Directory where temporary files will be created> (Optional : Default ./tmp)\n"
			"\n\n", pname);
}	

static int start_partha(int argc, char **argv)
{
	int			ret, i, log_console = 0, setcore = 0;	
	void			*pbuf;	
	size_t			szbuf;
	char			logdir[GY_PATH_MAX], cfgdir[GY_PATH_MAX], tmpdir[GY_PATH_MAX];
	bool			nolog = false, allow_core = false, trybcc = false;

	tzset();

	umask(0006);

	strcpy(logdir, "./log");
	strcpy(cfgdir, "./cfg");
	strcpy(tmpdir, "./tmp");

	if (argc > 1) {
		if ((0 == strcmp(argv[1], "-v")) || (0 == strcmp(argv[1], "--version"))) {
			IRPRINT("\n%s : Version %s\n\n", argv[0], get_version_str());
			fflush(stdout);
			exit(EXIT_SUCCESS);
		}	
		else if (0 == strcmp(argv[1], "--help")) {
			partha_usage(argv[0]);
			fflush(stdout);
			_exit(EXIT_SUCCESS);
		}	
		else if (0 == strcmp(argv[1], "--exepath")) {
			ssize_t			sret, sretp;
			char			cdir[GY_PATH_MAX], pdir[GY_PATH_MAX];
			int			ret;
			pid_t			pid;
			bool			bret;

			sret = get_task_exe_path(getpid(), cdir, sizeof(cdir));

			if (sret >= (int)GY_CONST_STRLEN("partha-bpf")) {
				sret -= 3;	// Ignore bpf or bcc part
			}	

			for (int i = 2; i < argc; ++i) {
				bret = string_to_number(argv[i], pid);

				if (bret) {
					sretp = get_task_exe_path(pid, pdir, sizeof(pdir));
					
					if (sretp >= (int)GY_CONST_STRLEN("partha-bpf")) {
						sretp -= 3;	// Ignore bpf or bcc part
					}	

					if ((sretp == sret) && (0 == memcmp(cdir, pdir, sret))) {
						IRPRINT("%d ", pid);
					}
				}	
			}	

			fflush(stdout);
			_exit(EXIT_SUCCESS);
		}	
		else if (0 == strcmp(argv[1], "--validdomain")) {
			bool			bret = false;
			char			error_buf[256];

			*error_buf = '\0';

			if (argc == 3) {
				bret = settings::valid_hostname_ip(argv[2], nullptr, 0, error_buf, sizeof(error_buf));
				if (bret == false) {
					IRPRINT("%s", error_buf);
				}	
			}
			else {
				IRPRINT("ERROR : More than 1 domain/IP specified");
			}	

			fflush(stdout);
			_exit(!bret);
		}	

		static constexpr uint32_t	hash_nolog		= fnv1_consthash("--nolog"), 		hash_logdir 		= fnv1_consthash("--logdir"),
						hash_cfgdir		= fnv1_consthash("--cfgdir"), 		hash_tmpdir		= fnv1_consthash("--tmpdir"),
						hash_debuglevel		= fnv1_consthash("--debuglevel"), 	hash_core		= fnv1_consthash("--core"),
						hash_logutc		= fnv1_consthash("--logutc"),
						hash_trybcc		= fnv1_consthash("--trybcc"),

						// Config Options

						hash_cfg_cluster_name	= fnv1_consthash("--cfg_cluster_name"),	hash_cfg_cloud_type	= fnv1_consthash("--cfg_cloud_type"),
						hash_cfg_region_name	= fnv1_consthash("--cfg_region_name"),	hash_cfg_zone_name	= fnv1_consthash("--cfg_zone_name"),
						hash_cfg_shyama_hosts	= fnv1_consthash("--cfg_shyama_hosts"),	hash_cfg_shyama_ports	= fnv1_consthash("--cfg_shyama_ports"),
						hash_cfg_response_sampling_pct	= fnv1_consthash("--cfg_response_sampling_percent"),
						hash_cfg_capture_errcode	= fnv1_consthash("--cfg_capture_errcode"),
						hash_cfg_enable_task_delays	= fnv1_consthash("--cfg_enable_task_delays"),
						hash_cfg_auto_respawn_on_exit	= fnv1_consthash("--cfg_auto_respawn_on_exit"),
						hash_cfg_is_kubernetes		= fnv1_consthash("--cfg_is_kubernetes"),
						hash_cfg_log_use_utc_time	= fnv1_consthash("--cfg_log_use_utc_time"),
						hash_cfg_json_file		= fnv1_consthash("--cfg_json_file");

		for (int i = 1; i < argc; ++i) {

			const uint32_t		arghash = fnv1_hash(argv[i], strlen(argv[i]));
	
			switch (arghash) {

			case hash_nolog :
				nolog = true;
				break;

			case hash_logdir :
				if (i + 1 < argc) {
					GY_STRNCPY(logdir, argv[i + 1], sizeof(logdir));
					i++;
				}
				else {
					partha_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_cfgdir :
				if (i + 1 < argc) {
					GY_STRNCPY(cfgdir, argv[i + 1], sizeof(cfgdir));
					i++;
				}
				else {
					partha_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_tmpdir :
				if (i + 1 < argc) {
					GY_STRNCPY(tmpdir, argv[i + 1], sizeof(tmpdir));
					i++;
				}
				else {
					partha_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_debuglevel :
				if (i + 1 < argc) {
					gdebugexecn = atoi(argv[i + 1]);
					i++;
				}
				break;

			case hash_core :
				allow_core = true;
				break;

			case hash_logutc :
				guse_utc_time = true;
				break;

			case hash_trybcc :
				trybcc = true;
				break;


			
			case hash_cfg_cluster_name :
				if (i + 1 < argc) {
					setenv("CFG_CLUSTER_NAME", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_cloud_type :
				if (i + 1 < argc) {
					setenv("CFG_CLOUD_TYPE", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_region_name :
				if (i + 1 < argc) {
					setenv("CFG_REGION_NAME", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_zone_name :
				if (i + 1 < argc) {
					setenv("CFG_ZONE_NAME", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_shyama_hosts :
				if (i + 1 < argc) {
					setenv("CFG_SHYAMA_HOSTS", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_shyama_ports :
				if (i + 1 < argc) {
					setenv("CFG_SHYAMA_PORTS", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_response_sampling_pct :
				if (i + 1 < argc) {
					setenv("CFG_RESPONSE_SAMPLING_PERCENT", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_capture_errcode :
				if (i + 1 < argc) {
					setenv("CFG_CAPTURE_ERRCODE", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_enable_task_delays :
				if (i + 1 < argc) {
					setenv("CFG_ENABLE_TASK_DELAYS", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_auto_respawn_on_exit :
				if (i + 1 < argc) {
					setenv("CFG_AUTO_RESPAWN_ON_EXIT", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_is_kubernetes :
				
				if (i + 1 < argc) {
					setenv("CFG_IS_KUBERNETES", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_log_use_utc_time :
				
				if (i + 1 < argc) {
					setenv("CFG_LOG_USE_UTC_TIME", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_json_file :
				
				if (i + 1 < argc) {
					setenv("CFG_JSON_FILE", argv[i + 1], 1);
					i++;
				}
				break;

			default :
				ERRORPRINTCOLOR(GY_COLOR_RED, "Unknown option %s\n", argv[i]);
				partha_usage(argv[0]);

				_exit(EXIT_FAILURE);
			}	
		
		}
	}

	time_t			tlast_debug = time(nullptr);
	char			tdebugfile[GY_PATH_MAX], tbuf[4096];
	struct stat		stat1;
	int			nlvl;

	try {
		(void) new PARTHA_C(argc, argv, nolog, logdir, cfgdir, tmpdir, allow_core, trybcc);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to initialize partha : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);

		_exit(EXIT_FAILURE);	
	);
	
	/*
	 * Now that things are on auto-pilot, we just keep checking if run time changes such as debug level are needed
	 */
	
	if (gdebugexecn > 0) {
		INFOPRINT("Current Log Debug Level %d\n\n", gdebugexecn);
	}	

	snprintf(tdebugfile, sizeof(tdebugfile), "%s/partha_runtime.json", pgpartha->pinitproc_->get_tmp_dir());
		
	while (true) {
		gy_nanosleep(2, 0);

		ret = stat(tdebugfile, &stat1);
		if (ret != 0) {
			continue;
		}	

		if (stat1.st_mtime <= tlast_debug) {
			continue;
		}	

		tlast_debug = stat1.st_mtime;

		ret = read_file_to_buffer(tdebugfile, tbuf, sizeof(tbuf) - 1);
		if (ret > 0) {
			tbuf[ret] = '\0';
			
			pgpartha->update_runtime_cfg(tbuf, ret);
		}	
	}	

	return 0;
}	



int main(int argc, char **argv)
{
	return start_partha(argc, argv);
}	

