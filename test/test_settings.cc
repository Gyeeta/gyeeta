
#include 		"gy_settings.h"

using namespace gyeeta;

struct PCT_MIN_MAX
{
	static constexpr float		min_val_ = 25.0f;
	static constexpr float		max_val_ = 99.99999f;
};	

static constexpr GY_SETTINGS set1[] = 
{
	{"server_ip", typeid(const char *), true, nullptr /* No default Value */, "Remote server IP/Hostname", gyeeta::settings::valid_hostname_ip},
	{"server_port", typeid(uint16_t), true, nullptr /* No default Value */, "Remote server port", gyeeta::settings::valid_port},
	{"check_interval", typeid(int64_t), false, "100" /* Default 100 sec */, "Check for disk usage in secs", gyeeta::settings::always_valid_numeric<int64_t>},
	{"admin_user", typeid(const char *), false, "admin", "Login name of admin", gyeeta::settings::valid_string},
	{"response_sample", typeid(bool), false, "0" /* Default false (0) */, "To enable Response sampling", gyeeta::settings::always_valid_numeric<bool>},
	{"cpu_percentile", typeid(float), false, "99.9", "Valid CPU Util percentile values", gyeeta::settings::min_max_numeric<float, PCT_MIN_MAX>},
};	

int test_basic()
{
	const char	*server_ip_tests[] = {"google.com", "8.8.8.8", "aaaa", nullptr, "1.1,1,1"};					
	const char	*server_port_tests[] = {"1111", "2222", "ssh", "11111111", "0", nullptr, "   22", "-333", "  tcp"};
	const char	*check_interval_tests[] = {"0", "11", nullptr, "-123", "  0x1A", "0112"};
	const char	*admin_user_tests[] = {"aaaaaaa", "            aaaaaa", "111111111", nullptr, "admin"};
	const char	*response_sample_tests[] = {"0", "2", "111111111", nullptr, "", "test,,,", "  abc"};
	const char	*cpu_percentile_tests[] = {"0.0001", "25.0001", "100.111111", nullptr, "  99.999", "-71.1", "  felee", "  0x31.2"};

	uint16_t	server_port_ints[] = {1111, 2222, 0, 22, 333};
	float		cpu_percentile_floats[] = {0.00f, 25.21, 100.001f, 99.999f, -71.1, 31.2};

	char		error_buf[128];
	char		server_ip[256];
	uint16_t	server_port;
	uint64_t	check_interval;
	char		admin_user[16];
	bool		response_sample;
	float		cpu_percentile;
	
	bool		bret;

	for (size_t i = 0; i < GY_ARRAY_SIZE(server_ip_tests); ++i) {
		bret = validate_string_save(set1, GY_ARRAY_SIZE(set1), "server_ip", server_ip_tests[i], server_ip, sizeof(server_ip), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "server_ip Setting : Valid input \'%s\' specified : server_ip = %s\n", server_ip_tests[i], server_ip);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "server_ip Setting : Invalid input \'%s\' : %s\n", server_ip_tests[i], error_buf);
		}	
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(server_port_tests); ++i) {
		bret = validate_string_save(set1, GY_ARRAY_SIZE(set1), "server_port", server_port_tests[i], &server_port, sizeof(server_port), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "server_port Setting : Valid input \'%s\' specified : server_port = %hu\n", server_port_tests[i], server_port);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "server_port Setting : Invalid input \'%s\' : %s\n", server_port_tests[i], error_buf);
		}	
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(check_interval_tests); ++i) {
		bret = validate_string_save(set1, GY_ARRAY_SIZE(set1), "check_interval", check_interval_tests[i], &check_interval, sizeof(check_interval), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "check_interval Setting : Valid input \'%s\' specified : check_interval = %lu\n", check_interval_tests[i], check_interval);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "check_interval Setting : Invalid input \'%s\' : %s\n", check_interval_tests[i], error_buf);
		}	
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(admin_user_tests); ++i) {
		bret = validate_string_save(set1, GY_ARRAY_SIZE(set1), "admin_user", admin_user_tests[i], &admin_user, sizeof(admin_user), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "admin_user Setting : Valid input \'%s\' specified : admin_user = %s\n", admin_user_tests[i], admin_user);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "admin_user Setting : Invalid input \'%s\' : %s\n", admin_user_tests[i], error_buf);
		}	
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(response_sample_tests); ++i) {
		bret = validate_string_save(set1, GY_ARRAY_SIZE(set1), "response_sample", response_sample_tests[i], &response_sample, sizeof(response_sample), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "response_sample Setting : Valid input \'%s\' specified : response_sample = %d\n", response_sample_tests[i], response_sample);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "response_sample Setting : Invalid input \'%s\' : %s\n", response_sample_tests[i], error_buf);
		}	
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(cpu_percentile_tests); ++i) {
		bret = validate_string_save(set1, GY_ARRAY_SIZE(set1), "cpu_percentile", cpu_percentile_tests[i], &cpu_percentile, sizeof(cpu_percentile), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "cpu_percentile Setting : Valid input \'%s\' specified : cpu_percentile = %f\n", cpu_percentile_tests[i], cpu_percentile);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "cpu_percentile Setting : Invalid input \'%s\' : %s\n", cpu_percentile_tests[i], error_buf);
		}	
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(server_port_ints); ++i) {
		bret = validate_numeric_save(set1, GY_ARRAY_SIZE(set1), "server_port", server_port_ints[i], &server_port, sizeof(server_port), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "server_port Setting : Valid input %hu specified : server_port = %hu\n", server_port_ints[i], server_port);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "server_port Setting : Invalid input %hu : %s\n", server_port_ints[i], error_buf);
		}	
	}	

	for (size_t i = 0; i < GY_ARRAY_SIZE(cpu_percentile_floats); ++i) {
		bret = validate_numeric_save(set1, GY_ARRAY_SIZE(set1), "cpu_percentile", cpu_percentile_floats[i], &cpu_percentile, sizeof(cpu_percentile), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "cpu_percentile Setting : Valid input %f specified : cpu_percentile = %f\n", cpu_percentile_floats[i], cpu_percentile);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "cpu_percentile Setting : Invalid input %f : %s\n", cpu_percentile_floats[i], error_buf);
		}	
	}	

	return 0;
}	


int main(int argc, char *argv[])
{
	test_basic();

	return 0;
}	


