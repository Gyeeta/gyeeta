
#include		"gyshyama.h"
#include 		"gy_socket_stat.h"
#include 		"gy_init_proc.h"
#include 		"gy_child_proc.h"
#include		"gy_print_offload.h"
#include		"gy_mount_disk.h"
#include		"gy_sys_hardware.h"
#include		"gy_settings.h"
#include 		"gy_async_func.h"
#include 		"gy_scheduler.h"
#include 		"gy_acct_taskstat.h"
#include 		"gy_sys_stat.h"
#include 		"gy_multi_proc_comm.h"
#include		"gy_rapidjson.h"
#include		"gy_query_common.h"
#include		"gy_libcurl.h"

namespace gyeeta {
namespace shyama {

static SHYAMA_C	*pgshyama;

int SHYAMA_C::init_all_singletons()
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

	PROC_CPU_IO_STATS::init_singleton(60, "shyama");

	MOUNT_HDLR::init_singleton(false /* mount_proc_if_not */, false /* mount_sys_if_not */, false /* mount_tracefs_if_not */);

	SYS_HARDWARE::init_singleton(false /* ignore_min_kern */, false /* need_root_priv */, false /* error_on_no_host_ns */);

	if (true == SYS_HARDWARE::get_singleton()->is_mount_ns_container()) {
		get_root_mount_ns_info(OS_INFO::get_singleton(), pcmd_child_, SYS_HARDWARE::get_singleton()->is_uts_ns_container());
	}	

	ASYNC_FUNC_HDLR::init_singleton();

	/*
	 * Now start the listener
	 */
	pconnhdlr_ = new SHCONN_HANDLER(this);

	SYS_HARDWARE::get_singleton()->print_system_info();

	SYS_CPU_STATS::init_singleton();

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
 * Current format of tmp/shyama_runtime.json :
{
	"debuglevel"			:	10,
	"log_use_utc_time"		:	false
}		 	
 */

int SHYAMA_C::update_runtime_cfg(char *pcfg, int sz) noexcept
{
	try {
		JSON_DOCUMENT<2048, 2048>	jdoc;
		auto				& doc = jdoc.get_doc();

		if (doc.ParseInsitu(pcfg).HasParseError()) {
			ERRORPRINTCOLOR_OFFLOAD(GY_COLOR_RED, "Runtime Config Change : Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
				doc.GetErrorOffset(), rapidjson::GetParseError_En(doc.GetParseError()));
			return -1;
		}	

		if (auto aiter = doc.FindMember("debuglevel"); ((aiter != doc.MemberEnd()) && (aiter->value.IsInt()))) {
			int 		nlvl = aiter->value.GetInt();

			if (gdebugexecn != nlvl) {
				INFOPRINT("Log Debug Level Changes seen : New Debug Level %d : Current Debug Level %d\n\n", nlvl, gdebugexecn);

				gdebugexecn = nlvl;

				pgshyama->log_debug_level_ = nlvl;
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
		DEBUGEXECN(1, ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while parsing shyama_runtime.json : %s\n", GY_GET_EXCEPT_STRING););
		return -1;
	);		 
}


// Mutable pjson
SA_SETTINGS_C::SA_SETTINGS_C(char *pjson)
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
	
	penv = getenv("CFG_LISTENER_IP");
	if (penv) {
		ewriter.KeyConst("listener_ip");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kArrayType);
	}	

	penv = getenv("CFG_LISTENER_PORT");
	if (penv) {
		ewriter.KeyConst("listener_port");
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

	penv = getenv("CFG_SHYAMA_NAME");
	if (penv) {
		ewriter.KeyConst("shyama_name");

		if (*penv != '"') {
			ewriter.StringStreamStart();
			ewriter.StringStream(penv, strlen(penv));
			ewriter.StringStreamEnd();
		}
		else {
			ewriter.RawValue(penv, strlen(penv), rapidjson::kStringType);
		}	
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

	penv = getenv("CFG_MIN_MADHAVA");
	if (penv) {
		ewriter.KeyConst("min_madhava");
		ewriter.RawValue(penv, strlen(penv), rapidjson::kNumberType);
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

	penv = getenv("CFG_WEBSERVER_URL");
	if (penv) {
		ewriter.KeyConst("webserver_url");

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

	INFOPRINT("Shyama Config from config file is : \n%s\n\nShyama Config from Environment Variables is : \n%s\n\n", pjson, penvjson); 

	if (doc.ParseInsitu(pjson).HasParseError()) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Not valid JSON : Error at offset %lu : Error is \'%s\'", 
			doc.GetErrorOffset(), rapidjson::GetParseError_En(doc.GetParseError()));
	}	

	if (edoc.Parse(penvjson).HasParseError()) {
		GY_THROW_EXCEPTION("Shyama Config Environment Variables set but not valid JSON : Error at offset %lu : Error is \'%s\'", 
			edoc.GetErrorOffset(), rapidjson::GetParseError_En(edoc.GetParseError()));
	}	

	if (false == doc.IsObject()) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Config not in JSON Object format");
	}	


	/*
	 * Current format of cfg/shyama_main.json :
	{
		"listener_ip"		 	:	"0.0.0.0",
		"listener_port"			:	10037,
		"service_hostname"		:	"shyama.test1.local",
		"service_port"			:	10037,

		"shyama_name"			:	"shyama-us-east-1a",
		"shyama_secret"			:	"This is a secret",

		"cloud_type"			:	"aws",
		"region_name"			:	"us-east-1",
		"zone_name"			:	"us-east-1a",

		"min_madhava"			:	2,
		
		"postgres_hostname"		:	"localhost",
		"postgres_port"			:	10040,
		"postgres_user"			:	"gyeeta",
		"postgres_password"		:	"gyeeta",
		"postgres_storage_days"		:	15,
		"db_logging"			:	"always",

		"webserver_url"			:	"http://gyeetaweb.local:10039",

		"auto_respawn_on_exit"		:	true,
		"log_use_utc_time"		:	false
	}
	 */ 
	
	if (aiter = edoc.FindMember("listener_ip"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString() || aiter->value.IsArray()))) {
		if (aiter->value.IsString()) {
			listener_ip.emplace_back(aiter->value.GetString());
		}
		else {
			for (uint32_t i = 0; i < aiter->value.Size(); i++) {
				if (false == aiter->value[i].IsString()) {
					GY_THROW_EXCEPTION("Invalid Shyama Config from Environment Variable : Config option \'listener_ip\' array element not of String type");
				}	
				listener_ip.emplace_back(aiter->value[i].GetString());
			}
		}
	}
	else if (aiter = doc.FindMember("listener_ip"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString() || aiter->value.IsArray()))) {
		if (aiter->value.IsString()) {
			listener_ip.emplace_back(aiter->value.GetString());
		}
		else {
			for (uint32_t i = 0; i < aiter->value.Size(); i++) {
				if (false == aiter->value[i].IsString()) {
					GY_THROW_EXCEPTION("Invalid Shyama Config : Config option \'listener_ip\' array element not of String type");
				}	
				listener_ip.emplace_back(aiter->value[i].GetString());
			}
		}
	}	
	else {
		// Default 0.0.0.0
		listener_ip.emplace_back("0.0.0.0");
	}	

	if (aiter = edoc.FindMember("listener_port"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint() || aiter->value.IsArray()))) {
		if (aiter->value.IsUint()) {
			listener_port.emplace_back(aiter->value.GetUint());
		}
		else {
			for (uint32_t i = 0; i < aiter->value.Size(); i++) {
				if (false == aiter->value[i].IsUint()) {
					GY_THROW_EXCEPTION("Invalid Shyama Config from Environment Variable : Mandatory Config option \'listener_port\' array element not of integer type");
				}	
				listener_port.emplace_back(aiter->value[i].GetUint());
			}
		}
	}
	else if (aiter = doc.FindMember("listener_port"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint() || aiter->value.IsArray()))) {
		if (aiter->value.IsUint()) {
			listener_port.emplace_back(aiter->value.GetUint());
		}
		else {
			for (uint32_t i = 0; i < aiter->value.Size(); i++) {
				if (false == aiter->value[i].IsUint()) {
					GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'listener_port\' array element not of integer type");
				}	
				listener_port.emplace_back(aiter->value[i].GetUint());
			}
		}
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'listener_port\' not found in config json");
	}	

	if (listener_port.size() != listener_ip.size()) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Config option listener_port and listener_ip have different array sizes");
	}
	else if ((listener_ip.size() == 0) || (listener_ip.size() > 16)) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Config option listener_ip array size %lu invalid : Max allowed 16 elements", listener_ip.size());
	}	

		
	if (aiter = edoc.FindMember("shyama_name"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_db_name(aiter->value.GetString(), aiter->value.GetStringLength(), sizeof(shyama_name), "Shyama Name from Environment Variable");

		GY_STRNCPY(shyama_name, aiter->value.GetString(), sizeof(shyama_name));
	}	
	else if (aiter = doc.FindMember("shyama_name"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		validate_db_name(aiter->value.GetString(), aiter->value.GetStringLength(), sizeof(shyama_name), "Shyama Name from config");

		GY_STRNCPY(shyama_name, aiter->value.GetString(), sizeof(shyama_name));
	}
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'shyama_name\' not found or is not a String Type in config json");
	}	

	if (0 != memcmp(shyama_name, "shyama", GY_CONST_STRLEN("shyama"))) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Config option shyama_name \'%s\' invalid : Must start with keyword \'shyama\' for example \'shyama1\'", shyama_name);
	}	


	
	if (aiter = edoc.FindMember("shyama_secret"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		if (aiter->value.GetStringLength() >= sizeof(shyama_secret) || aiter->value.GetStringLength() == 0) {
			GY_THROW_EXCEPTION("Invalid Shyama Config from Environment Variable : Config option shyama_secret size %u invalid : Must be between 1 and 63 bytes", aiter->value.GetStringLength());
		}	

		GY_STRNCPY(shyama_secret, aiter->value.GetString(), sizeof(shyama_secret));
	}	
	else if (aiter = doc.FindMember("shyama_secret"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		if (aiter->value.GetStringLength() >= sizeof(shyama_secret) || aiter->value.GetStringLength() == 0) {
			GY_THROW_EXCEPTION("Invalid Shyama Config : Config option shyama_secret size %u invalid : Must be between 1 and 63 bytes", aiter->value.GetStringLength());
		}	

		GY_STRNCPY(shyama_secret, aiter->value.GetString(), sizeof(shyama_secret));
	}
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'shyama_secret\' not found or is not a String Type in config json");
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
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'service_hostname\' not found or is not a String Type in config json");
	}	

	if (aiter = edoc.FindMember("service_port"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint()))) {
		service_port = aiter->value.GetUint();
	}	
	else if (aiter = doc.FindMember("service_port"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint()))) {
		service_port = aiter->value.GetUint();
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'service_port\' not found or is not an Integer Type in config json");
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


	if (aiter = edoc.FindMember("postgres_hostname"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_hostname, aiter->value.GetString(), sizeof(postgres_hostname));
	}	
	else if (aiter = doc.FindMember("postgres_hostname"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_hostname, aiter->value.GetString(), sizeof(postgres_hostname));
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'postgres_hostname\' not found or of invalid type in config json");
	}	

	if (0 == *postgres_hostname) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'postgres_hostname\' must not be an empty string in config json");
	}	

	if (aiter = edoc.FindMember("postgres_port"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint()))) {
		postgres_port = aiter->value.GetUint();
	}	
	else if (aiter = doc.FindMember("postgres_port"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint()))) {
		postgres_port = aiter->value.GetUint();
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option postgres_port not found or of invalid type in config json");
	}	


	if (aiter = doc.FindMember("postgres_user"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_user, aiter->value.GetString(), sizeof(postgres_user));
	}	
	else if (aiter = edoc.FindMember("postgres_user"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_STRNCPY(postgres_user, aiter->value.GetString(), sizeof(postgres_user));
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'postgres_user\' not found or of invalid type in config json");
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
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'postgres_password\' not found or of invalid type in config json");
	}	

#if 0		 
	/* 
	 * Currently we do not supprt spawning DB
	 */
	if (aiter = doc.FindMember("spawn_postgres_db"); ((aiter != doc.MemberEnd()) && (aiter->value.IsBool()))) {
		spawn_postgres_db = aiter->value.GetBool();
	}	
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'spawn_postgres_db\' not found or of invalid type in config json");
	}	

	if (spawn_postgres_db) {

		if (aiter = doc.FindMember("postgres_conf_path"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
			GY_STRNCPY(postgres_conf_path, aiter->value.GetString(), sizeof(postgres_conf_path));
		}	
		else {
			GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'postgres_conf_path\' not found or of invalid type in config json");
		}	

		if (aiter = doc.FindMember("postgres_data_dir"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
			GY_STRNCPY(postgres_data_dir, aiter->value.GetString(), sizeof(postgres_conf_path));
		}	
		else {
			GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'postgres_data_dir\' not found or of invalid type in config json");
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
		postgres_storage_days = 7;
	}	

	if (postgres_storage_days < 3) postgres_storage_days = 3;
	if (postgres_storage_days > 60) postgres_storage_days = 60;

	
	if (aiter = edoc.FindMember("webserver_url"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsString()))) {
		if (aiter->value.GetStringLength() >= sizeof(webserver_url)) {
			GY_THROW_EXCEPTION("Invalid Shyama Config from Environment Variable : Config option \'webserver_url\' length too large : %u : Max allowed = %lu bytes",
				aiter->value.GetStringLength(), sizeof(webserver_url) - 1);
		}
		
		GY_STRNCPY(webserver_url, aiter->value.GetString(), sizeof(webserver_url));
	}	
	else if (aiter = doc.FindMember("webserver_url"); ((aiter != doc.MemberEnd()) && (aiter->value.IsString()))) {
		if (aiter->value.GetStringLength() >= sizeof(webserver_url)) {
			GY_THROW_EXCEPTION("Invalid Shyama Config : Config option \'webserver_url\' length too large : %u : Max allowed = %lu bytes",
				aiter->value.GetStringLength(), sizeof(webserver_url) - 1);
		}
		
		GY_STRNCPY(webserver_url, aiter->value.GetString(), sizeof(webserver_url));
	}
	else {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'webserver_url\' not found or of invalid type in config json");
	}	

	if ((0 != std::memcmp(webserver_url, "http://", 7)) && (0 != std::memcmp(webserver_url, "https://", 8))) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Mandatory Config option \'webserver_url\' specified \'%s\' not in valid format in config json : "
				"Please specify the complete URL as in http://webserver.local:10039 or https://webserver.local:8443", webserver_url);
	}	
	else {
		auto			escurl = gy_escape_json<8192>(webserver_url, aiter->value.GetStringLength(), false);

		esc_webserver_url.assign(escurl.data(), escurl.size());
	}

	if (aiter = edoc.FindMember("min_madhava"); ((aiter != edoc.MemberEnd()) && (aiter->value.IsUint()))) {
		min_madhava = aiter->value.GetUint();
	}
	else if (aiter = doc.FindMember("min_madhava"); ((aiter != doc.MemberEnd()) && (aiter->value.IsUint()))) {
		min_madhava = aiter->value.GetUint();
	}

	if (min_madhava > comm::MAX_MADHAVA_PER_SHYAMA) {
		GY_THROW_EXCEPTION("Invalid Shyama Config : Config option \'min_madhava\' value %u is invalid : Valid values between 1 and %lu", 
					min_madhava, comm::MAX_MADHAVA_PER_SHYAMA);
	}	
	if (min_madhava == 0) {
		min_madhava = 1;
	}	


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


static int shyama_monitor_proc(int argc, char **argv, CHILD_PROC * pchildproc, bool auto_respawn_on_exit) noexcept
{
	do {
		static pid_t		ma_parent;
		const char 		* const old_argv0 = strdup(argv[0]), *new_argv0 = "shymon";	
		auto			*pshyama = SHYAMA_C::get_singleton();
		bool			argv_upd = false;
		int			ret;	

		GY_SCOPE_EXIT {
			if (old_argv0) free(const_cast<char *>(old_argv0));
		};	

		if (old_argv0 && (strlen(argv[0]) >= strlen(new_argv0))) { 

			INFOPRINT("Setting process name of shyama monitor child process %d to %s\n", getpid(), new_argv0);
			
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

			PROC_CPU_IO_STATS::init_singleton(60, "shymon");

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
						INFOPRINT("shyama Monitor process %d : Parent process %d seems to be exited.\n",
							getpid(), pchildproc->ppid_);

						::close(pchildproc->get_socket());
						break;
					}	
				}	
			}	

			if ((auto_respawn_on_exit == false) || (false == pshyama->init_completed_)) {
				if (false == pshyama->force_restart_) {
					INFOPRINT("shyama Monitor process exiting now...\n");
					_exit(EXIT_SUCCESS);
				}

				pshyama->force_restart_ = false;
			}
				
			if (0 != gsig_mon_rcvd.load()) {
				INFOPRINT("shyama Monitor process exiting as signal to exit %d was received earlier...\n", gsig_mon_rcvd.load());
				_exit(EXIT_SUCCESS);
			}	

			for (int i = 0; i < 15; ++i) {
				gy_nanosleep(1, 0);

				if (0 != gsig_mon_rcvd.load()) {
					INFOPRINT("shyama Monitor process exiting as signal %d was received earlier...\n", gsig_mon_rcvd.load());
					_exit(EXIT_SUCCESS);
				}	
			}

			if ((getppid() == pchildproc->ppid_) && (pchildproc->ppid_ != 1)) {
				char			buf1[128];
				struct stat		stat1;

				snprintf(buf1, sizeof(buf1), "/proc/%d/status", pchildproc->ppid_);

				if (0 == stat(buf1, &stat1)) {

					ERRORPRINT("Parent process of shyama Monitor PID %d is still running although exit signal was received. Exiting without re-spawning shyama\n",
						pchildproc->ppid_);
					_exit(EXIT_FAILURE);
				}
			}
				
			NOTEPRINT("shyama Monitor process : starting new shyama process by exec as parent shyama process has exited...\n\n");
			
			if (argv_upd && old_argv0) {
				strcpy(argv[0], old_argv0);
			}	
			
			for (int i = 3; i < 32767; ++i) {
				::close(i);
			}
				
			execv(argv[0], argv);
				
			PERRORPRINT("Failed to execv shyama binary %s : Exiting without re-execing...", argv[0]);
			_exit(EXIT_FAILURE);

		}
		GY_CATCH_EXCEPTION(	
			ERRORPRINT("Exception caught in shyama Monitor handling : %s\n", GY_GET_EXCEPT_STRING);
		);
	}
	while (true);	
	
	return -1;
}	 

static int shyama_cmd_proc(CHILD_PROC *pchildproc) noexcept
{
	do {
		try {
			ASYNC_FUNC_HDLR::init_singleton();
			
			GY_SCHEDULER::init_singletons(false);
			
			GY_SCHEDULER::cancel_rcu_schedules();	// If singleton was already initialized

			PROC_CPU_IO_STATS::init_singleton(60, "shyama_cmd_proc");

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
						INFOPRINT("shyama command process %d : Parent process %d seems to be exited.\n",
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

					ERRORPRINT("Parent process of shyama command PID %d is still running although exit signal was received. Exiting...\n",
						pchildproc->ppid_);
					_exit(EXIT_FAILURE);
				}
			}

			INFOPRINT("shyama Command process exiting as parent signalled to quit ...\n");

			_exit(EXIT_SUCCESS);
		}
		GY_CATCH_EXCEPTION(	
			ERRORPRINT("Exception caught in shyama command process handling : %s\n", GY_GET_EXCEPT_STRING);
		);
	}
	while (true);	
	
	return -1;
}	

SHYAMA_C::SHYAMA_C(int argc, char **argv, bool nolog, const char *logdir, const char *cfgdir, const char *tmpdir, const char *reportsdir, bool allow_core)
	: log_debug_level_(gdebugexecn)
{

	pid_t			childpid1, childpid2;
	char			logpath[GY_PATH_MAX], descbuf[128];
	int			ret;

	snprintf(descbuf, sizeof(descbuf), "Shyama - Gyeeta's Control Server : Version %s", gversion);
		
	pgshyama = this;

	bool			throw_if_ulimit = !allow_core;

#ifdef	UNDER_VALGRIND
	throw_if_ulimit		= false;
#endif	

	pinitproc_ = new INIT_PROC(argc, argv, true /* handle_signals */, false /* exit_on_parent_kill */, true /* chown_if_root */,	
		nolog ? nullptr : logdir, "shyama.log", "shyama.log", 0 /* log_wrap_size */, false /* rename_old_log */,
		descbuf, !allow_core, true /* set_sessionid */, cfgdir, tmpdir, "shyama.lock",
		true /* close_stdin */, 2 * 1024 * 1024 /* max_stacksize */, 2 * 1024 * 1024 /* min_stacksize */, 65535 /* min_openfiles */, 2048 /* min_nproc */, throw_if_ulimit, guse_utc_time,
		true /* unbuffered_stdout */);
	
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

			INFOPRINT("Using %s as the shyama Config file as per environment variable CFG_JSON_FILE ...\n", cfgfile);
		}
		else {
			snprintf(cfgfile, sizeof(cfgfile), "%s/shyama_main.json", pinitproc_->get_cfg_dir());
		}
			
		ret = stat(cfgfile, &stat1);
		if (ret != 0) {
			if (!penv) {
				WARNPRINT("Shyama Config file not found : %s : Will try to get config from environment variables...\n", cfgfile);
				preadbuf = strdup("{}");
			}
		}
		else {
			preadbuf = read_file_to_alloc_buffer(cfgfile, &readsz, 512 * 1024);
		}

		if (!preadbuf) {
			GY_THROW_SYS_EXCEPTION("Failed to read global shyama config file %s%s", cfgfile, penv ? " as per CFG_JSON_FILE env" : "");
		}	

		GY_SCOPE_EXIT {
			free(preadbuf);
		};	

		psettings_ = new SA_SETTINGS_C(preadbuf); 
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

				snprintf(path, sizeof(path), "%s/shyama_crash.log", SHYAMA_C::get_singleton()->pinitproc_->get_log_dir());

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

				ERRORFDUNLOCKPRINT(fdo, "shyama process was signalled a fatal signal %s as per the above stack trace\n", gy_signal_str(signo));
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
		
	INFOPRINT("Spawning the shyama monitor \'shymon\' and command handler processes ...\n"); 

	if (!nolog) {
		snprintf(logpath, sizeof(logpath), "%s/shymon.log", logdir);
	}
	else {
		*logpath = '\0';	
	}		

	pcleanup_child_ = new CHILD_PROC(nolog, logpath, logpath, false /* exit_on_parent_kill */, true /* use_socket_pair */, 
				true /* use_shared_pool */, 128, sizeof(COMM_MSG_C), handle_signal_mon_proc, true /* signal_callback_will_exit */);

	childpid1 = pcleanup_child_->fork_child("shymon", true /* set_thr_name */, "shyama cleanup and monitor process", O_APPEND,
					3, 1024, chown_uid_, chown_gid_); 
	if (childpid1 == 0) {
		// Within child
		shyama_monitor_proc(argc, argv, pcleanup_child_, psettings_->auto_respawn_on_exit);

		_exit(EXIT_FAILURE);
	}

	if (!nolog) {
		snprintf(logpath, sizeof(logpath), "%s/shyama_cmd_child.log", logdir);
	}
	else {
		*logpath = '\0';	
	}		

	pcmd_child_ = new CHILD_PROC(nolog, logpath, logpath, true /* exit_on_parent_kill */, true /* use_socket_pair */, 
			true /* use_shared_pool */, 128, sizeof(COMM_MSG_C), nullptr, false /* signal_callback_will_exit */);

	childpid2 = pcmd_child_->fork_child("shyama_cmd_child", false /* set_thr_name */, "shyama command exec process", O_APPEND, 3, 1024, chown_uid_, chown_gid_); 

	if (childpid2 == 0) {
		// Within child
		shyama_cmd_proc(pcmd_child_);

		_exit(EXIT_FAILURE);
	}

	// Exec this after the child processes have been spawned
	init_all_singletons();

	init_completed_ = true;

	COMM_MSG_C			tmsg;
	
	tmsg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		SHYAMA_C::get_singleton()->init_completed_ = true;
		return 0;
	};	

	ret = COMM_MSG_C::send_msg_locked(pcleanup_child_->get_socket(), pcleanup_child_->get_mutex(), tmsg, nullptr, false /* is_nonblock */); 
	assert (ret == 0);
	
	INFOPRINT("Shyama Initialization Completed Successfully...\n\n");
}	

void SHYAMA_C::send_proc_restart_exit(int max_retries) 
{
	COMM_MSG_C			tmsg;
	int				ret, ntry = 0;
	
	tmsg.func_ = [](uint64_t arg1, uint64_t arg2, uint64_t arg3, const uint8_t *poptbuf, size_t opt_bufsize)
	{
		SHYAMA_C::get_singleton()->force_restart_ = true;
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


SHYAMA_C * SHYAMA_C::get_singleton() noexcept
{
	return pgshyama;
}	

} // namespace shyama 
} // namespace gyeeta 

using namespace 	gyeeta;
using namespace 	gyeeta::shyama;

static void shyama_usage(const char *pname) noexcept
{
	IRPRINT("\nUsage : %s \n"	/* Keep this \n as the runshyama.sh skips the first line */
			"\t\t--nolog (Use if no separate log files : Will directly write to stdout/stderr : Will override --logdir if specified)\n"
			"\t\t--logdir <Directory where log files are created> (Optional : Default ./log)\n"
			"\t\t--tmpdir <Directory where temporary files will be created> (Optional : Default ./tmp)\n"
			"\n\n", pname);
}	

static int start_shyama(int argc, char **argv)
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
			shyama_usage(argv[0]);
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

		static constexpr uint32_t	hash_nolog			= fnv1_consthash("--nolog"),
						hash_logdir 			= fnv1_consthash("--logdir"),
						hash_cfgdir			= fnv1_consthash("--cfgdir"),
						hash_tmpdir			= fnv1_consthash("--tmpdir"),
						hash_reportsdir			= fnv1_consthash("--reportsdir"),
						hash_debuglevel			= fnv1_consthash("--debuglevel"),
						hash_core			= fnv1_consthash("--core"),
						hash_uselocaltime		= fnv1_consthash("--uselocaltime"),
						hash_logutc			= fnv1_consthash("--logutc"),

						// Config Options

						hash_cfg_listener_ip		= fnv1_consthash("--cfg_listener_ip"),	
						hash_cfg_listener_port		= fnv1_consthash("--cfg_listener_port"),
						hash_cfg_service_hostname	= fnv1_consthash("--cfg_service_hostname"),	
						hash_cfg_service_port		= fnv1_consthash("--cfg_service_port"),	
						hash_cfg_shyama_name		= fnv1_consthash("--cfg_shyama_name"),	
						hash_cfg_shyama_secret		= fnv1_consthash("--cfg_shyama_secret"),
						hash_cfg_cloud_type		= fnv1_consthash("--cfg_cloud_type"),
						hash_cfg_region_name		= fnv1_consthash("--cfg_region_name"),
						hash_cfg_zone_name		= fnv1_consthash("--cfg_zone_name"),
						hash_cfg_min_madhava		= fnv1_consthash("--cfg_min_madhava"),
						hash_cfg_postgres_hostname	= fnv1_consthash("--cfg_postgres_hostname"),
						hash_cfg_postgres_port		= fnv1_consthash("--cfg_postgres_port"),
						hash_cfg_postgres_user		= fnv1_consthash("--cfg_postgres_user"),
						hash_cfg_postgres_password	= fnv1_consthash("--cfg_postgres_password"),
						hash_cfg_postgres_storage_days	= fnv1_consthash("--cfg_postgres_storage_days"),
						hash_cfg_db_logging		= fnv1_consthash("--cfg_db_logging"),
						hash_cfg_webserver_url		= fnv1_consthash("--cfg_webserver_url"),
						hash_cfg_auto_respawn_on_exit	= fnv1_consthash("--cfg_auto_respawn_on_exit"),
						hash_cfg_log_use_utc_time	= fnv1_consthash("--cfg_log_use_utc_time");

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
					shyama_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_cfgdir :
				if (i + 1 < argc) {
					GY_STRNCPY(cfgdir, argv[i + 1], sizeof(cfgdir));
					i++;
				}
				else {
					shyama_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_tmpdir :
				if (i + 1 < argc) {
					GY_STRNCPY(tmpdir, argv[i + 1], sizeof(tmpdir));
					i++;
				}
				else {
					shyama_usage(argv[0]);
					_exit(EXIT_FAILURE);
				}	
				break;

			case hash_reportsdir :
				if (i + 1 < argc) {
					GY_STRNCPY(reportsdir, argv[i + 1], sizeof(reportsdir));
					i++;
				}
				else {
					shyama_usage(argv[0]);
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

			case hash_cfg_listener_ip :
				if (i + 1 < argc) {
					setenv("CFG_LISTENER_IP", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_listener_port :
				if (i + 1 < argc) {
					setenv("CFG_LISTENER_PORT", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_service_hostname :
				if (i + 1 < argc) {
					setenv("CFG_SERVICE_HOSTNAME", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_service_port :
				if (i + 1 < argc) {
					setenv("CFG_SERVICE_PORT", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_shyama_name :
				if (i + 1 < argc) {
					setenv("CFG_SHYAMA_NAME", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_shyama_secret :
				if (i + 1 < argc) {
					setenv("CFG_SHYAMA_SECRET", argv[i + 1], 1);
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

			case hash_cfg_min_madhava :
				if (i + 1 < argc) {
					setenv("CFG_MIN_MADHAVA", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_postgres_hostname :
				if (i + 1 < argc) {
					setenv("CFG_POSTGRES_HOSTNAME", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_postgres_port :
				if (i + 1 < argc) {
					setenv("CFG_POSTGRES_PORT", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_postgres_user :
				if (i + 1 < argc) {
					setenv("CFG_POSTGRES_USER", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_postgres_password :
				if (i + 1 < argc) {
					setenv("CFG_POSTGRES_PASSWORD", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_postgres_storage_days :
				if (i + 1 < argc) {
					setenv("CFG_POSTGRES_STORAGE_DAYS", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_db_logging :
				if (i + 1 < argc) {
					setenv("CFG_DB_LOGGING", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_webserver_url :
				if (i + 1 < argc) {
					setenv("CFG_WEBSERVER_URL", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_auto_respawn_on_exit :
				if (i + 1 < argc) {
					setenv("CFG_AUTO_RESPAWN_ON_EXIT", argv[i + 1], 1);
					i++;
				}
				break;

			case hash_cfg_log_use_utc_time :
				if (i + 1 < argc) {
					setenv("CFG_LOG_USE_UTC_TIME", argv[i + 1], 1);
					i++;
				}
				break;



			default :
				ERRORPRINTCOLOR(GY_COLOR_RED, "Unknown option %s\n", argv[i]);
				shyama_usage(argv[0]);

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
		(void) new SHYAMA_C(argc, argv, nolog, logdir, cfgdir, tmpdir, reportsdir, allow_core);
	}
	GY_CATCH_EXCEPTION(
		ERRORPRINTCOLOR(GY_COLOR_RED, "Failed to initialize shyama : %s : Exiting...\n\n", GY_GET_EXCEPT_STRING);

		_exit(EXIT_FAILURE);	
	);
	
	/*
	 * Now that things are on auto-pilot, we just keep checking if run time changes such as debug level are needed
	 */
	
	if (gdebugexecn > 0) {
		INFOPRINT("Current Log Debug Level %d\n\n", gdebugexecn);
	}	

	snprintf(tdebugfile, sizeof(tdebugfile), "%s/shyama_runtime.json", pgshyama->pinitproc_->get_tmp_dir());
		
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
			
			pgshyama->update_runtime_cfg(tbuf, ret);
		}	
	}	

	return 0;
}	

int main(int argc, char **argv)
{
	return start_shyama(argc, argv);
}	



