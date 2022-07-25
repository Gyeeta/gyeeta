

#pragma			once

#include		"gy_common_inc.h"
#include		"gy_init_proc.h"
#include		"gy_child_proc.h"
#include		"gy_shconnhdlr.h"

namespace gyeeta {
namespace shyama {

class SA_SETTINGS_C
{
public :		
	std::vector<std::string>	listener_ip;
	std::vector<uint16_t>		listener_port;

	char				service_hostname[MAX_DOMAINNAME_SIZE]		{};
	uint16_t			service_port					{0};

	char				shyama_name[comm::MAX_CLUSTER_NAME_LEN]		{};
	char				shyama_secret[comm::MAX_CLUSTER_NAME_LEN]	{};

	char				region_name[comm::MAX_ZONE_LEN]			{};
	char				zone_name[comm::MAX_ZONE_LEN]			{};
	char				cloud_type[comm::MAX_ZONE_LEN]			{};

	char				postgres_hostname[MAX_DOMAINNAME_SIZE]		{};
	uint16_t			postgres_port					{0};
	char				postgres_user[128]				{};
	char				postgres_password[128]				{};
	bool				spawn_postgres_db				{false};
	char				postgres_conf_path[GY_PATH_MAX]			{};
	char				postgres_data_dir[GY_PATH_MAX]			{};
	uint32_t			postgres_storage_days				{0};

	char				webserver_url[800]				{};
	std::string			esc_webserver_url;

	uint32_t			min_madhava					{1};
	DB_LOGGING_E			db_logging					{DB_LOGGING_ALWAYS};
	bool				auto_respawn_on_exit				{true};
	bool				log_use_utc_time				{false};

	SA_SETTINGS_C(char *pjson);
};	
	


class SHYAMA_C final
{
public :

	INIT_PROC			*pinitproc_		{nullptr};
	SA_SETTINGS_C			*psettings_		{nullptr};

	SHCONN_HANDLER			*pconnhdlr_		{nullptr};

	CHILD_PROC			*pcleanup_child_	{nullptr};
	CHILD_PROC			*pcmd_child_		{nullptr};

	uid_t				chown_uid_		{0};
	gid_t				chown_gid_		{0};
	
	int				log_debug_level_	{0};
	bool				init_completed_		{false};
	bool				force_restart_		{false};

	SHYAMA_C(int argc, char **argv, bool nolog, const char *logdir, const char *cfgdir, const char *tmpdir, const char *reportsdir, bool allow_core);

	~SHYAMA_C()			= delete;

	SHYAMA_C(const SHYAMA_C &)	= delete;

	SHYAMA_C(SHYAMA_C &&)		= delete;

	SHCONN_HANDLER *		get_conn_handler() const noexcept
	{
		return pconnhdlr_;
	}	

	SA_SETTINGS_C *			get_settings() const noexcept
	{
		return psettings_;
	}	

	int				update_runtime_cfg(char *pcfg, int sz) noexcept;

	void 				send_proc_restart_exit(int max_retries = 2); 

	static SHYAMA_C *		get_singleton() noexcept;

private :

	int				init_all_singletons();
};	

extern const char *			const gversion;
extern const uint32_t			gversion_num, gmin_partha_version, gmin_madhava_version, gmin_node_version;

} // namespace shyama
} // namespace gyeeta

