
#include		"gymadhava.h"
#include 		"gy_socket_stat.h"
#include 		"gy_init_proc.h"
#include 		"gy_child_proc.h"
#include		"gy_print_offload.h"
#include		"gy_mount_disk.h"
#include		"gy_sys_hardware.h"
#include 		"gy_async_func.h"
#include 		"gy_scheduler.h"
#include 		"gy_settings.h"
#include 		"gy_acct_taskstat.h"
#include 		"gy_sys_stat.h"
#include 		"gy_multi_proc_comm.h"
#include		"gy_rapidjson.h"
#include		"gy_query_common.h"
#include		"gy_libcurl.h"

namespace gyeeta {
namespace madhava {

static MADHAVA_C	*pgmadhava;

int MADHAVA_C::init_all_singletons()
{
	const char		*pext[] = {".log", ".tmp"};
	char			path[GY_PATH_MAX];

	GY_CURL_EASY::global_init();

	PRINT_OFFLOAD::init_singleton();

	GY_SCHEDULER::init_singletons();

	GY_SCHEDULER::start_rcu_schedules();

	pinitproc_->set_log_file_monitor(pext, GY_ARRAY_SIZE(pext), 30 * 1024 * 1024, 2);

	GY_TIMEZONE::init_singleton();

	init_subsys_maps();

	PROC_CPU_IO_STATS::init_singleton(60, "madhava");

	MOUNT_HDLR::init_singleton(false /* mount_proc_if_not */, false /* mount_sys_if_not */, false /* mount_tracefs_if_not */);

	SYS_HARDWARE::init_singleton(false /* ignore_min_kern */, false /* need_root_priv */);

	if (true == SYS_HARDWARE::get_singleton()->is_mount_ns_container()) {
		get_root_mount_ns_info(OS_INFO::get_singleton(), pcmd_child_, SYS_HARDWARE::get_singleton()->is_uts_ns_container());
	}	

	ASYNC_FUNC_HDLR::init_singleton();

	/*
	 * Now start the listener and connect to Shyama
	 */
	pconnhdlr_ = new MCONN_HANDLER(this);

	SYS_HARDWARE::get_singleton()->print_system_info();

	SYS_CPU_STATS::init_singleton();

	TASKSTATS_HDLR::init_singleton();

	auto schedshr = GY_SCHEDULER::get_singleton(GY_SCHEDULER::SCHEDULER_LONG_DURATION);
	schedshr->add_schedule(900, 300'000, 0, "Print Offload print stats", 
	[] { 
		auto poffload = PRINT_OFFLOAD::get_singleton();
		if (poffload) {
			poffload->print_stats();
		}	
	});

	return 0;
}	


/*
 * Current format of tmp/madhava_runtime.json :
{
	"debuglevel"			:	10,
	"log_use_utc_time"		:	false
}		 	
 */

int MADHAVA_C::update_runtime_cfg(char *pcfg, int sz) noexcept
{
	try {
		JSON_DOCUMENT<2048, 2048>		jdoc;
		auto					& doc = jdoc.get_doc();

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

				pgmadhava->log_debug_level_ = nlvl;
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

		return 0;
	}
	GY_CATCH_EXCEPTION(
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while parsing madhava_runtime.json : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		 
}	

// Mutable pjson
MA_SETTINGS_C::MA_SETTINGS_C(char *pjson)
{
	JSON_DOCUMENT<2048, 2048>	jdoc, ejdoc;
	auto				& doc = jdoc.get_doc();
	auto				& edoc = ejdoc.get_doc();

	STACK_JSON_WRITER<8192, 4096>	ewriter;
	const char			*penvjson, *penv;
	
	JSON_MEM_ITER			aiter;
	int				ret;

	assert(pjson);

	// First populate config json from env if any : env will override config file options 
	ewriter.StartObject();
	
	penv = getenv("CFG_LISTENER_DOMAINS");
	if (penv) {
		ewriter.KeyConst("listener_domains");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kArrayType);
	}	

	penv = getenv("CFG_LISTENER_PORTS");
	if (penv) {
		ewriter.KeyConst("listener_ports");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kArrayType);
	}	

	penv = getenv("CFG_SERVICE_HOSTNAME");
	if (penv) {
		ewriter.KeyConst("service_hostname");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_SERVICE_PORT");
	if (penv) {
		ewriter.KeyConst("service_port");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	penv = getenv("CFG_MADHAVA_NAME");
	if (penv) {
		ewriter.KeyConst("madhava_name");

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

	penv = getenv("CFG_SHYAMA_SECRET");
	if (penv) {
		ewriter.KeyConst("shyama_secret");

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

	penv = getenv("CFG_POSTGRES_HOSTNAME");
	if (penv) {
		ewriter.KeyConst("postgres_hostname");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_POSTGRES_PORT");
	if (penv) {
		ewriter.KeyConst("postgres_port");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	penv = getenv("CFG_POSTGRES_USER");
	if (penv) {
		ewriter.KeyConst("postgres_user");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_POSTGRES_PASSWORD");
	if (penv) {
		ewriter.KeyConst("postgres_password");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_POSTGRES_STORAGE_DAYS");
	if (penv) {
		ewriter.KeyConst("postgres_storage_days");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	penv = getenv("CFG_DB_LOGGING");
	if (penv) {
		ewriter.KeyConst("db_logging");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
	}	

	penv = getenv("CFG_AUTO_RESPAWN_ON_EXIT");
	if (penv) {
		ewriter.KeyConst("auto_respawn_on_exit");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	penv = getenv("CFG_LOG_USE_UTC_TIME");
	if (penv) {
		ewriter.KeyConst("log_use_utc_time");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
	}	

	ewriter.EndObject();

	penvjson = ewriter.get_string();

	INFOPRINT("Madhava Config from config file is : \n%s\n\nMadhava Config from Environment Variables is : \n%s\n\n", pjson, penvjson); 

	if (doc.ParseInsitu(pjson).HasParseError()) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Not valid JSON : Error at offset %lu : Error is \'%s\'", 
			doc.GetErrorOffset(), rapidjson::GetParseError_En(doc.GetParseError()));
	}	

	if (edoc.Parse(penvjson).HasParseError()) {
		GY_THROW_EXCEPTION("Madhava Config Environment Variables set but not valid JSON : Error at offset %lu : Error is \'%s\'", 
			edoc.GetErrorOffset(), rapidjson::GetParseError_En(edoc.GetParseError()));
	}	

	if (false == doc.IsObject()) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Config not in JSON Object format");
	}	

	/*
	 * Current format of cfg/madhava_main.json :
	{
		"listener_domains"	 	:	["192.168.0.1", "127.0.0.1"],
		"listener_ports"		:	[10038, 10038],
		"madhava_name"			:	"madhava-us-east-1a-1",
		"service_hostname"		:	"madhava.test1.local",
		"service_port"			:	10038,

		"shyama_hosts" 			:	[ "shyama1.test1.local", "shyama2.test2.local" ],
		"shyama_ports"			:	[ 10037, 10037 ],
		"shyama_secret"			:	"This is a secret",

		"cloud_type"			:	"aws",
		"region_name"			:	"us-east-1",
		"zone_name"			:	"us-east-1a",

		"postgres_hostname"		:	"localhost",
		"postgres_port"			:	10040,
		"postgres_user"			:	"gyeeta",
		"postgres_password"		:	"gyeeta",
		"postgres_storage_days"		:	15,
		"db_logging"			:	"always",
		
		"auto_respawn_on_exit"		:	true,
		"log_use_utc_time"		:	false
	}
	 */ 
 

	if (aiter = edoc.FindMember("listener_domains"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsString()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config from Environment Variable : Mandatory Config option \'listener_domains\' array element not of String type");
			}	
			listener_domains.emplace_back(aiter->value[i].GetString());
		}
	}
	else if (aiter = doc.FindMember("listener_domains"); ((aiter != doc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsString()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'listener_domains\' array element not of String type");
			}	
			listener_domains.emplace_back(aiter->value[i].GetString());
		}
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'listener_domains\' not found or is not an Array Type in config json");
	}	

	if (aiter = edoc.FindMember("listener_ports"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsUint()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config from Environment Variable : Mandatory Config option \'listener_ports\' array element not of integer type");
			}	
			listener_ports.emplace_back(aiter->value[i].GetUint());
		}
	}
	else if (aiter = doc.FindMember("listener_ports"); ((aiter != doc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsUint()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'listener_ports\' array element not of integer type");
			}	
			listener_ports.emplace_back(aiter->value[i].GetUint());
		}
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'listener_ports\' not found or is not an Array Type in config json");
	}	

	if (listener_ports.size() != listener_domains.size()) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Config option listener_ports and listener_domains have different array sizes");
	}
	else if ((listener_domains.size() == 0) || (listener_domains.size() > 16)) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Config option listener_domains array size %lu invalid : Max allowed 16 elements", listener_domains.size());
	}	

	if (aiter = edoc.FindMember("madhava_name"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_db_name(aiter->value.GetString(), aiter->value.GetStringLength(), sizeof(madhava_name), "Madhava Name from Environment Variable");
		
		GY_STRNCPY(madhava_name, aiter->value.GetString(), sizeof(madhava_name));
	
	}	
	else if (aiter = doc.FindMember("madhava_name"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_db_name(aiter->value.GetString(), aiter->value.GetStringLength(), sizeof(madhava_name), "Madhava Name from config");
		
		GY_STRNCPY(madhava_name, aiter->value.GetString(), sizeof(madhava_name));
	
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'madhava_name\' not found or is not a String Type in config json");
	}	

	if (0 != memcmp(madhava_name, "madhava", GY_CONST_STRLEN("madhava"))) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Config option madhava_name \'%s\' invalid : Must start with keyword \'madhava\' for example \'madhava_useast1\'", 
			madhava_name);
	}

	if (aiter = edoc.FindMember("service_hostname"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), sizeof(service_hostname), "Service Hostname from Environment Variable", false /* firstalphaonly */);

		GY_STRNCPY(service_hostname, aiter->value.GetString(), sizeof(service_hostname));
	}	
	else if (aiter = doc.FindMember("service_hostname"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), sizeof(service_hostname), "Service Hostname from config", false /* firstalphaonly */);

		GY_STRNCPY(service_hostname, aiter->value.GetString(), sizeof(service_hostname));
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'service_hostname\' not found or is not a String Type in config json");
	}	

	if (aiter = edoc.FindMember("service_port"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint()))) {
		service_port = aiter->value.GetUint();
	}	
	else if (aiter = doc.FindMember("service_port"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint()))) {
		service_port = aiter->value.GetUint();
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'service_port\' not found or is not an Integer Type in config json");
	}	

	if (aiter = edoc.FindMember("shyama_hosts"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsString()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config from Environment Variable : Mandatory Config option \'shyama_hosts\'  array element not of String Type");
			}	
			shyama_hosts.emplace_back(aiter->value[i].GetString());
		}
	}
	else if (aiter = doc.FindMember("shyama_hosts"); ((aiter != doc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsString()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'shyama_hosts\' array element not of String type");
			}	
			shyama_hosts.emplace_back(aiter->value[i].GetString());
		}
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'shyama_hosts\' not found or is not an Array Type in config json");
	}	

	if (aiter = edoc.FindMember("shyama_ports"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsUint()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config from Environment Variable : Mandatory Config option \'shyama_ports\' array element not of integer type");
			}	
			shyama_ports.emplace_back(aiter->value[i].GetUint());
		}
	}
	else if (aiter = doc.FindMember("shyama_ports"); ((aiter != doc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			if (false == aiter->value[i].IsUint()) {
				GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'shyama_ports\' array element not of integer type");
			}	
			shyama_ports.emplace_back(aiter->value[i].GetUint());
		}
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'shyama_ports\' not found or is not an Array Type in config json");
	}	

	if (shyama_ports.size() != shyama_hosts.size()) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Config option shyama_ports and shyama_hosts have different array sizes");
	}
	else if ((shyama_hosts.size() == 0) || (shyama_hosts.size() > 16)) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Config option shyama_hosts array size %lu invalid : Max allowed 16 elements", shyama_hosts.size());
	}	

	if (aiter = edoc.FindMember("shyama_secret"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		if (aiter->value.GetStringLength() >= sizeof(shyama_secret) || aiter->value.GetStringLength() == 0) {
			GY_THROW_EXCEPTION("Invalid Madhava Config from Environment Variable : Config option shyama_secret size %u invalid : Must be between 1 and 63 bytes", 
				aiter->value.GetStringLength());
		}	

		GY_STRNCPY(shyama_secret, aiter->value.GetString(), sizeof(shyama_secret));
	}	
	else if (aiter = doc.FindMember("shyama_secret"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		if (aiter->value.GetStringLength() >= sizeof(shyama_secret) || aiter->value.GetStringLength() == 0) {
			GY_THROW_EXCEPTION("Invalid Madhava Config : Config option shyama_secret size %u invalid : Must be between 1 and 63 bytes", aiter->value.GetStringLength());
		}	

		GY_STRNCPY(shyama_secret, aiter->value.GetString(), sizeof(shyama_secret));
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'shyama_secret\' not found or is not a String Type in config json");
	}	

	if (aiter = edoc.FindMember("region_name"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Region Name from Environment Variable", false /* firstalphaonly */);

		GY_STRNCPY(region_name, aiter->value.GetString(), sizeof(region_name));
	}
	else if (aiter = doc.FindMember("region_name"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Region Name from config", false /* firstalphaonly */);

		GY_STRNCPY(region_name, aiter->value.GetString(), sizeof(region_name));
	}

	if (aiter = edoc.FindMember("zone_name"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Zone Name from Environment Variable", false /* firstalphaonly */);

		GY_STRNCPY(zone_name, aiter->value.GetString(), sizeof(zone_name));
	}
	else if (aiter = doc.FindMember("zone_name"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_json_name(aiter->value.GetString(), aiter->value.GetStringLength(), comm::MAX_ZONE_LEN, "Zone Name from config", false /* firstalphaonly */);

		GY_STRNCPY(zone_name, aiter->value.GetString(), sizeof(zone_name));
	}

	if (aiter = edoc.FindMember("postgres_hostname"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_hostname, aiter->value.GetString(), sizeof(postgres_hostname));
	}
	else if (aiter = doc.FindMember("postgres_hostname"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_hostname, aiter->value.GetString(), sizeof(postgres_hostname));
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'postgres_hostname\' not found or of invalid type in config json");
	}	

	if (0 == *postgres_hostname) {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'postgres_hostname\' must not be an empty string in config json");
	}

	if (aiter = edoc.FindMember("postgres_port"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint()))) {
		postgres_port = aiter->value.GetUint();
	}		
	else if (aiter = doc.FindMember("postgres_port"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint()))) {
		postgres_port = aiter->value.GetUint();
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option postgres_port not found or of invalid type in config json");
	}	

	if (aiter = edoc.FindMember("postgres_user"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_user, aiter->value.GetString(), sizeof(postgres_user));
	}		
	else if (aiter = doc.FindMember("postgres_user"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_user, aiter->value.GetString(), sizeof(postgres_user));
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'postgres_user\' not found or of invalid type in config json");
	}	

	if (0 == *postgres_user) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'postgres_user\' must not be an empty string in config json");
	}	

	if (aiter = edoc.FindMember("postgres_password"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_password, aiter->value.GetString(), sizeof(postgres_password));
	}	
	else if (aiter = doc.FindMember("postgres_password"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_password, aiter->value.GetString(), sizeof(postgres_password));
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'postgres_password\' not found or of invalid type in config json");
	}	

#if 0		 
	/* 
	 * Currently we do not supprt spawning DB
	 */
	if (aiter = doc.FindMember("spawn_postgres_db"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		spawn_postgres_db = aiter->value.GetBool();
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'spawn_postgres_db\' not found or of invalid type in config json");
	}	

	if (spawn_postgres_db) {

		if (aiter = doc.FindMember("postgres_conf_path"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
			GY_STRNCPY(postgres_conf_path, aiter->value.GetString(), sizeof(postgres_conf_path));
		}	
		else {
			GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'postgres_conf_path\' not found or of invalid type in config json");
		}	

		if (aiter = doc.FindMember("postgres_data_dir"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
			GY_STRNCPY(postgres_data_dir, aiter->value.GetString(), sizeof(postgres_conf_path));
		}	
		else {
			GY_THROW_EXCEPTION("Invalid Madhava Config : Mandatory Config option \'postgres_data_dir\' not found or of invalid type in config json");
		}	

		if (0 != access(postgres_conf_path, R_OK)) {
			GY_THROW_SYS_EXCEPTION("Failed to read Postgres config file %s", postgres_conf_path);
		}	

		struct stat		dstat;

		ret = stat(postgres_data_dir, &dstat);
		if ((ret != 0) || (false == S_ISDIR(dstat.st_mode))) {
			GY_THROW_SYS_EXCEPTION("Invalid Postgres Data Directory %s", postgres_data_dir);
		}	
	}	
#endif		

	if (aiter = edoc.FindMember("postgres_storage_days"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint()))) {
		postgres_storage_days = aiter->value.GetUint();
	}	
	else if (aiter = doc.FindMember("postgres_storage_days"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint()))) {
		postgres_storage_days = aiter->value.GetUint();
	}	
	else {
		postgres_storage_days = 3;
	}	

	if (postgres_storage_days < 3) postgres_storage_days = 3;
	if (postgres_storage_days > 60) postgres_storage_days = 60;

	if (aiter = edoc.FindMember("db_logging"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		db_logging = get_db_logging_level(aiter->value.GetString());
	}	
	else if (aiter = doc.FindMember("db_logging"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		db_logging = get_db_logging_level(aiter->value.GetString());
	}	

	if (aiter = edoc.FindMember("auto_respawn_on_exit"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsBool()))) {
		auto_respawn_on_exit = aiter->value.GetBool();
	}	
	else if (aiter = doc.FindMember("auto_respawn_on_exit"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		auto_respawn_on_exit = aiter->value.GetBool();
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


static int madhava_monitor_proc(int argc, char **argv, CHILD_PROC * pchildproc, bool auto_respawn_on_exit) noexcept
{
	do {
		static pid_t		ma_parent;
		const char 		* const old_argv0 = strdup(argv[0]), *new_argv0 = "madhmon";	
		auto			*pmadhava = MADHAVA_C::get_singleton();
		bool			argv_upd = false;
		int			ret;	

		GY_SCOPE_EXIT {
			if (old_argv0) free(const_cast<char *>(old_argv0));
		};	

		if (old_argv0 && (strlen(argv[0]) >= strlen(new_argv0))) { 

			INFOPRINT("Setting process name of madhava monitor child process %d to %s\n", getpid(), new_argv0);
			
			size_t 		sz1 = strlen(argv[0]);

			std::memset(argv[0], ' ', sz1);

			strcpy(argv[0], new_argv0);
			prctl(PR_SET_NAME, (unsigned long)argv[0]);

			argv_upd = true;
		}
		
		ma_parent = pchildproc->ppid_;

		setsid();

		try {
			ASYNC_FUNC_HDLR::init_singleton();
			
			GY_SCHEDULER::init_singletons(false);

			GY_SCHEDULER::cancel_rcu_schedules();	// If singleton was already initialized

			PROC_CPU_IO_STATS::init_singleton(60, "madhmon");

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
						INFOPRINT("madhava Monitor process %d : Parent process %d seems to be exited.\n",
							getpid(), pchildproc->ppid_);

						::close(pchildproc->get_socket());
						break;
					}	
				}	
			}	

			if ((auto_respawn_on_exit == false) || (false == pmadhava->init_completed_)) {
				if (false == pmadhava->force_restart_) {
					INFOPRINT("madhava Monitor process exiting now...\n");
					_exit(EXIT_SUCCESS);
				}

				pmadhava->force_restart_ = false;
			}
				
			if (0 != gsig_mon_rcvd.load()) {
				INFOPRINT("madhava Monitor process exiting as signal to exit %d was received earlier...\n", gsig_mon_rcvd.load());
				_exit(EXIT_SUCCESS);
			}	

			for (int i = 0; i < 15; ++i) {
				gy_nanosleep(1, 0);

				if (0 != gsig_mon_rcvd.load()) {
					INFOPRINT("madhava Monitor process exiting as signal %d was received earlier...\n", gsig_mon_rcvd.load());
					_exit(EXIT_SUCCESS);
				}	
			}

			if ((getppid() == pchildproc->ppid_) && (pchildproc->ppid_ != 1)) {
				char			buf1[128];
				struct stat		stat1;

				snprintf(buf1, sizeof(buf1), "/proc/%d/status", pchildproc->ppid_);

				if (0 == stat(buf1, &stat1)) {

					ERRORPRINT("Parent process of madhava Monitor PID %d is still running although exit signal was received. Exiting without re-spawning madhava\n",
						pchildproc->ppid_);
					_exit(EXIT_FAILURE);
				}
			}
				
			NOTEPRINT("madhava Monitor process : starting new madhava process by exec as parent madhava process has exited...\n\n");
			
			if (argv_upd && old_argv0) {
				strcpy(argv[0], old_argv0);
			}	
			
			for (int i = 3; i < 32767; ++i) {
				::close(i);
			}
				
			execv(argv[0], argv);
				
			PERRORPRINT("Failed to execv madhava binary %s : Exiting without re-execing...", argv[0]);
			_exit(EXIT_FAILURE);

		}
		GY_CATCH_EXCEPTION(	
			ERRORPRINT("Exception caught in madhava Monitor handling : %s\n", GY_GET_EXCEPT_STRING);
		);
	}
	while (true);	
	
	return -1;
}	 

static int madhava_cmd_proc(CHILD_PROC *pchildproc) noexcept
{
	do {
		try {
			ASYNC_FUNC_HDLR::init_singleton();
			
			GY_SCHEDULER::init_singletons(false);
			
			GY_SCHEDULER::cancel_rcu_schedules();	// If singleton was already initialized

			PROC_CPU_IO_STATS::init_singleton(60, "madhava_cmd_proc");

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
						INFOPRINT("madhava command process %d : Parent process %d seems to be exited.\n",
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

					ERRORPRINT("Parent process of madhava command PID %d is still running although exit signal was received. Exiting...\n",
						pchildproc->ppid_);
					_exit(EXIT_FAILURE);
				}
			}

			INFOPRINT("madhava Command process exiting as parent signalled to quit ...\n");

			_exit(EXIT_SUCCESS);
		}
		GY_CATCH_EXCEPTION(	
			ERRORPRINT("Exception caught in madhava command process handling : %s\n", GY_GET_EXCEPT_STRING);
		);
	}
	while (true);	
	
	return -1;
}	

MADHAVA_C::MADHAVA_C(int argc, char **argv, bool nolog, const char *logdir, const char *cfgdir, const char *tmpdir, const char *reportsdir, bool allow_core)
	: log_debug_level_(gdebugexecn)
{

	pid_t			childpid1, childpid2;
	char			logpath[GY_PATH_MAX], descbuf[128];
	int			ret;

	snprintf(descbuf, sizeof(descbuf), "Madhava - Gyeeta's Analytics Intermediate Server : Version %s", gversion);
		
	pgmadhava = this;

	bool			throw_if_ulimit = !allow_core;

#ifdef	UNDER_VALGRIND
	throw_if_ulimit		= false;
#endif	

	pinitproc_ = new INIT_PROC(argc, argv, true /* handle_signals */, false /* exit_on_parent_kill */, true /* chown_if_root */,	
		nolog ? nullptr : logdir, "madhava.log", "madhava.log", 0 /* log_wrap_size */, false /* rename_old_log */,
		descbuf, !allow_core, true /* set_sessionid */, cfgdir, tmpdir, "madhava.lock",
		true /* close_stdin */, 2 * 1024 * 1024 /* max_stacksize */, 2 * 1024 * 1024 /* min_stacksize */, 65535 /* min_openfiles */, 2048 /* min_nproc */, throw_if_ulimit, guse_utc_time, 
		true /* unbuffered_stdout */);
	
	pinitproc_->is_chown_uid_gid(chown_uid_, chown_gid_);

	if (chown_uid_ || chown_gid_) {
		INFOPRINT("All new files created will have their ownership set to UID %d GID %d\n", chown_uid_, chown_gid_);
	}

	if (true) {
		char			cfgfile[GY_PATH_MAX], *preadbuf = nullptr;
		struct stat		stat1;
		size_t			readsz = 0;

		snprintf(cfgfile, sizeof(cfgfile), "%s/madhava_main.json", pinitproc_->get_cfg_dir());
		
		ret = stat(cfgfile, &stat1);
		if (ret != 0) {
			WARNPRINT("Madhava Config file not found : %s : Will try to get config from environment variables...\n", cfgfile);
			preadbuf = strdup("{}");
		}
		else {
			preadbuf = read_file_to_alloc_buffer(cfgfile, &readsz, 512 * 1024);
		}

		if (!preadbuf) {
			GY_THROW_SYS_EXCEPTION("Failed to read global madhava config file %s", cfgfile);
		}	

		GY_SCOPE_EXIT {
			free(preadbuf);
		};	

		psettings_ = new MA_SETTINGS_C(preadbuf); 
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

				snprintf(path, sizeof(path), "%s/madhava_crash.log", MADHAVA_C::get_singleton()->pinitproc_->get_log_dir());

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

				ERRORFDUNLOCKPRINT(fdo, "madhava process was signalled a fatal signal %s as per the above stack trace\n", gy_signal_str(signo));
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
		
	INFOPRINT("Spawning the madhava monitor \'madhmon\' and command handler processes ...\n"); 

	if (!nolog) {
		snprintf(logpath, sizeof(logpath), "%s/madhmon.log", logdir);
	}
	else {
		*logpath = '\0';	
	}		

	pcleanup_child_ = new CHILD_PROC(nolog, logpath, logpath, false /* exit_on_parent_kill */, true /* use_socket_pair */, 
				true /* use_shared_pool */, 128, sizeof(COMM_MSG_C), handle_signal_mon_proc, true /* signal_callback_will_exit */);

	childpid1 = pcleanup_child_->fork_child("madhmon", true /* set_thr_name */, "madhava cleanup and monitor process", O_APPEND,
					3, 1024, chown_uid_, chown_gid_); 
	if (childpid1 == 0) {
		// Within child
		madhava_monitor_proc(argc, argv, pcleanup_child_, psettings_->auto_respawn_on_exit);

		_exit(EXIT_FAILURE);
	}

	if (!nolog) {
		snprintf(logpath, sizeof(logpath), "%s/madhava_cmd_child.log", logdir);
	}
	else {
		*logpath = '\0';	
	}		

	pcmd_child_ = new CHILD_PROC(nolog, logpath, logpath, true /* exit_on_parent_kill */, true /* use_socket_pair */, 
			true /* use_shared_pool */, 128, sizeof(COMM_MSG_C), nullptr, false /* signal_callback_will_exit */);

	childpid2 = pcmd_child_->fork_child("madhava_cmd_child", false /* set_thr_name */, "madhava command exec process", O_APPEND, 3, 1024, chown_uid_, chown_gid_); 

	if (childpid2 == 0) {
		// Within child
		madhava_cmd_proc(pcmd_child_);

		_exit(EXIT_FAILURE);
	}

	// Exec this after the child processes have been spawned
	init_all_singletons();

	init_completed_ = true;

	COMM_MSG_C			tmsg;
	
	tmsg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		MADHAVA_C::get_singleton()->init_completed_ = true;
		return 0;
	};	

	ret = COMM_MSG_C::send_msg_locked(pcleanup_child_->get_socket(), pcleanup_child_->get_mutex(), tmsg, nullptr, false /* is_nonblock */); 
	assert (ret == 0);

	INFOPRINT("madhava initialization completed successfully...\n\n");
}	

void MADHAVA_C::send_proc_restart_exit(int max_retries) 
{
	COMM_MSG_C			tmsg;
	int				ret, ntry = 0;
	
	tmsg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		MADHAVA_C::get_singleton()->force_restart_ = true;
		return 0;
	};	

	do {
		ret = COMM_MSG_C::send_msg_locked(pcleanup_child_->get_socket(), pcleanup_child_->get_mutex(), tmsg, nullptr, false /* is_nonblock */); 

		if (ret != 0 && ++ntry >= max_retries) {
			gy_nanosleep(1, 0);
		}	
		else {
			break;
		}	
	}
	while (true);

	if (ret != 0) {
		ERRORPRINT("Failed to signal Child process to restart process. Now exiting without restarting...\n\n");

		sched_yield();
		_exit(EXIT_FAILURE);
	}
	else {
		INFOPRINT("Signalled Child process to restart process. Now exiting...\n\n");

		sched_yield();
		_exit(EXIT_SUCCESS);
	}	

}


MADHAVA_C * MADHAVA_C::get_singleton() noexcept
{
	return pgmadhava;
}	

} // namespace madhava 
} // namespace gyeeta 

using namespace 	gyeeta;
using namespace 	gyeeta::madhava;

static void madhava_usage(const char *pname) noexcept
{
	IRPRINT("\nUsage : %s \n"	/* Keep this \n as the runmadhava.sh skips the first line */
			"\t\t--nolog (Use if no separate log files : Will directly write to stdout/stderr : Will override --logdir if specified)\n"
			"\t\t--logdir <Directory where log files are created> (Optional : Default ./log)\n"
			"\t\t--cfgdir <Directory where cfg files are present> (Optional : Default ./cfg)\n"
			"\t\t--tmpdir <Directory where temporary files will be created> (Optional : Default ./tmp)\n"
			"\t\t--reportsdir <Directory where temporary reports will be created> (Optional : Default ./reports)\n"
			"\t\t--uselocaltime (Will use Local Timezone instead of default UTC)\n"
			"\n\n", pname);
}	

static int start_madhava(int argc, char **argv)
{
	int			ret, i, log_console = 0, setcore = 0;	
	void			*pbuf;	
	size_t			szbuf;
	char			logdir[GY_PATH_MAX], cfgdir[GY_PATH_MAX], tmpdir[GY_PATH_MAX], reportsdir[GY_PATH_MAX];
	bool			nolog = false, allow_core = false, uselocaltime = false;

	strcpy(logdir, "./log");
	strcpy(cfgdir, "./cfg");
	strcpy(tmpdir, "./tmp");
	strcpy(reportsdir, "./reports");

	if (argc > 1) {
		if ((0 == strcmp(argv[1], "-v")) || (0 == strcmp(argv[1], "--version"))) {
			IRPRINT("\n%s : Version %s\n\n", argv[0], gversion);
			fflush(stdout);
			exit(EXIT_SUCCESS);
		}	
		else if (0 == strcmp(argv[1], "--help")) {
			madhava_usage(argv[0]);
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

		constexpr uint32_t		hash_nolog		= fnv1_consthash("--nolog"),
						hash_logdir 		= fnv1_consthash("--logdir"),
						hash_cfgdir		= fnv1_consthash("--cfgdir"),
						hash_tmpdir		= fnv1_consthash("--tmpdir"),
						hash_reportsdir		= fnv1_consthash("--reportsdir"),
						hash_debuglevel		= fnv1_consthash("--debuglevel"),
						hash_core		= fnv1_consthash("--core"),
						hash_uselocaltime	= fnv1_consthash("--uselocaltime"),
						hash_logutc		= fnv1_consthash("--logutc");

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
					madhava_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_cfgdir :
				if (i + 1 < argc) {
					GY_STRNCPY(cfgdir, argv[i + 1], sizeof(cfgdir));
					i++;
				}
				else {
					madhava_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_tmpdir :
				if (i + 1 < argc) {
					GY_STRNCPY(tmpdir, argv[i + 1], sizeof(tmpdir));
					i++;
				}
				else {
					madhava_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_reportsdir :
				if (i + 1 < argc) {
					GY_STRNCPY(reportsdir, argv[i + 1], sizeof(reportsdir));
					i++;
				}
				else {
					madhava_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_core :
				allow_core = true;
				break;

			case hash_debuglevel :
				if (i + 1 < argc) {
					gdebugexecn = atoi(argv[i + 1]);
					i++;
				}
				break;

			case hash_uselocaltime :
				uselocaltime = true;
				break;

			case hash_logutc :
				guse_utc_time = true;
				break;

			default :
				ERRORPRINTCOLOR(GY_COLOR_RED, "Unknown option %s\n", argv[i]);
				madhava_usage(argv[0]);

				_exit(EXIT_FAILURE);
			}	
		
		}
	}

	if (!uselocaltime) {
		setenv("TZ", "UTC", 1);
	}

	tzset();

	umask(0006);

	time_t			tlast_debug = time(nullptr);
	char			tdebugfile[GY_PATH_MAX], tbuf[4096];
	struct stat		stat1;
	int			nlvl;

	try {
		(void) new MADHAVA_C(argc, argv, nolog, logdir, cfgdir, tmpdir, reportsdir, allow_core);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to initialize madhava : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);

		_exit(EXIT_FAILURE);	
	);
	
	/*
	 * Now that things are on auto-pilot, we just keep checking if run time changes such as debug level are needed
	 */
	
	if (gdebugexecn > 0) {
		INFOPRINT("Current Log Debug Level %d\n\n", gdebugexecn);
	}	

	snprintf(tdebugfile, sizeof(tdebugfile), "%s/madhava_runtime.json", pgmadhava->pinitproc_->get_tmp_dir());
		
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
			
			pgmadhava->update_runtime_cfg(tbuf, ret);
		}	
	}	

	return 0;
}	

int main(int argc, char **argv)
{
	return start_madhava(argc, argv);
}	

