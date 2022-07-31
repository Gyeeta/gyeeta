
#pragma			once

#include		"gy_common_inc.h"
#include		"gy_init_proc.h"
#include		"gy_child_proc.h"
#include		"gy_misc.h"
#include		"pa_misc.h"
#include		"gy_comm_proto.h"

namespace gyeeta {

class OS_INFO;

namespace partha {

class PACONN_HANDLER;

class PARTHA_C
{
public :
	class PA_SETTINGS_C
	{
	public :		
		char				cluster_name[comm::MAX_CLUSTER_NAME_LEN]	{};
		char				region_name[comm::MAX_ZONE_LEN]			{};
		char				zone_name[comm::MAX_ZONE_LEN]			{};
		char				cloud_type[comm::MAX_ZONE_LEN]			{};

		std::vector<std::string>	shyama_hosts;
		std::vector<uint16_t>		shyama_ports;

		uint8_t				response_sampling_percent			{100};
		bool				capture_errcode					{true};
		bool				capture_api_call				{false};
		bool				auto_respawn_on_exit				{true};
		bool				is_kubernetes					{false};
		bool				log_use_utc_time				{false};

		PA_SETTINGS_C(char *pjson);
	};	
		
	GY_CAPABILITIES			proc_cap_;

	PACONN_HANDLER			*pconnhdlr_		{nullptr};	
	INIT_PROC			*pinitproc_		{nullptr};
	PA_SETTINGS_C			*psettings_		{nullptr};
	CHILD_PROC			*pcleanup_child_	{nullptr};
	CHILD_PROC			*pcmd_child_		{nullptr};

	uid_t				chown_uid_		{0};
	gid_t				chown_gid_		{0};
	
	int				log_debug_level_	{0};
	bool				allow_core_		{false};
	bool				init_completed_		{false};

	PARTHA_C(int argc, char **argv, bool nolog, const char *logdir, const char *cfgdir, const char *tmpdir, bool allow_core);

	~PARTHA_C()			= delete;

	PARTHA_C(const PARTHA_C &)	= delete;

	PARTHA_C(PARTHA_C &&)		= delete;

	int				update_runtime_cfg(char *pcfg, int sz) noexcept;

	int				update_server_status(const char *status) noexcept;

	void				verify_caps_kernhdr();

	static PARTHA_C *		get_singleton() noexcept;

private :

	int				init_all_singletons();
};	

} // namespace partha
} // namespace gyeeta


