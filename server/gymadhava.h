//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#pragma			once

#include		"gy_common_inc.h"
#include		"gy_init_proc.h"
#include		"gy_child_proc.h"
#include		"gy_mconnhdlr.h"

namespace gyeeta {
namespace madhava {

class MA_SETTINGS_C
{
public :		

	std::vector<std::string>	listener_ip;
	std::vector<uint16_t>		listener_port;

	char				service_hostname[MAX_DOMAINNAME_SIZE]		{};
	uint16_t			service_port					{0};

	char				madhava_name[comm::MAX_CLUSTER_NAME_LEN]	{};

	std::vector<std::string>	shyama_hosts;
	std::vector<uint16_t>		shyama_ports;
	char				shyama_secret[comm::MAX_CLUSTER_NAME_LEN]	{};

	char				region_name[comm::MAX_ZONE_LEN]			{};
	char				zone_name[comm::MAX_ZONE_LEN]			{};
	char				cloud_type[comm::MAX_ZONE_LEN]			{};

	char				postgres_hostname[MAX_DOMAINNAME_SIZE]		{};
	uint16_t			postgres_port					{0};
	char				postgres_user[128]				{};
	char				postgres_password[128]				{};
	bool				spawn_postgres_db				{false};
	bool				is_db_remote					{true};
	char				postgres_conf_path[GY_PATH_MAX]			{};
	char				postgres_data_dir[GY_PATH_MAX]			{};
	uint32_t			postgres_storage_days				{0};

	uint16_t			set_max_hosts					{0};
	DB_LOGGING_E			db_logging					{DB_LOGGING_ALWAYS};
	bool				auto_respawn_on_exit				{true};
	bool				log_use_utc_time				{false};

	MA_SETTINGS_C(char *pjson);
};	

class MADHAVA_C
{
public :
	INIT_PROC			*pinitproc_		{nullptr};
	MA_SETTINGS_C			*psettings_		{nullptr};

	MCONN_HANDLER			*pconnhdlr_		{nullptr};

	CHILD_PROC			*pcleanup_child_	{nullptr};
	CHILD_PROC			*pcmd_child_		{nullptr};

	uid_t				chown_uid_		{0};
	gid_t				chown_gid_		{0};
	
	int				log_debug_level_;
	bool				init_completed_		{false};
	bool				force_restart_		{false};

	MADHAVA_C(int argc, char **argv, bool nolog, const char *logdir, const char *cfgdir, const char *tmpdir, const char *reportsdir, bool allow_core);

	~MADHAVA_C()			= delete;

	MADHAVA_C(const MADHAVA_C &)	= delete;

	MADHAVA_C(MADHAVA_C &&)		= delete;

	MCONN_HANDLER * get_conn_handler() const noexcept
	{
		return pconnhdlr_;
	}	

	int update_runtime_cfg(char *pcfg, int sz) noexcept;

	void send_proc_restart_exit(int max_retries = 2); 
	
	static MADHAVA_C *		get_singleton() noexcept;

private :
	int				init_all_singletons();
};	

extern const char *			const gversion;
extern const uint32_t			gversion_num, gmin_partha_version, gmin_shyama_version, gmin_node_version;


} // namespace madhava
} // namespace gyeeta

