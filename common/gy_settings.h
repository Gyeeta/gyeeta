
#pragma 			once

#include			"gy_common_inc.h"

#include 			<sys/socket.h>
#include 			<netdb.h>

namespace gyeeta {

typedef bool (*VALIDATE_SAVE_FP)(const void *setting, void * store_addr, size_t sz_store, char *error_buf, size_t szerror);

#if 0
/*
 * Define Settings fields and validation methods :
 *
 * Only supported types for settings fields are : 
 * char *, const char *, long double, double, float, int64_t, uint64_t, int32_t, uint32_t, int16_t, uint16_t, bool, char, uint8_t
 *
 * Usage : Define the settings array as shown below :
 */
	static constexpr GY_SETTINGS gsettings[] = 
	{
		{"server_ip", typeid(const char *), true, "", "Remote server IP/Hostname", gyeeta::settings::validate_hostname_ip},

		{"server_port", typeid(uint16_t), true, "", "Remote server port", gyeeta::settings::validate_port},

		{"check_interval", typeid(int64_t), false, "100" /* Default 100 sec */, "Check for disk usage in secs", gyeeta::settings::always_valid_numeric<int64_t>},

		{"admin_user", typeid(const char *), false, "admin", "Login name of admin", gyeeta::settings::is_valid_string},

		{"response_sample", typeid(bool), false, "0" /* Default false (0) */, "To enable Response sampling", gyeeta::settings::always_valid_numeric<bool>},

		{"cpu_percentile", typeid(float), false, "99.9", "Valid CPU Util percentile values", gyeeta::settings::min_max_numeric<float, PCT_MIN_MAX>},
		
	};	
	
	The min_max_numeric function needs a template class argument which should contain constexpr min_val_ and max_val_ defined.
	
	Then to test and set a setting field (here input_string is the input setting string to be validated and if valid should update server_ip :

		bool bret = gyeeta::validate_save_setting(gsettings, GY_ARRAY_SIZE(gsettings), "server_ip", input_string, server_ip, sizeof(server_ip), error_buf, sizeof(error_buf));	
		if (bret == true) {
			INFOPRINTCOLOR(GY_COLOR_GREEN, "server_ip Setting : Valid input \'%s\' specified : server_ip = %s\n", input_string, server_ip);
		}
		else {
			ERRORPRINTCOLOR(GY_COLOR_RED, "server_ip Setting : Invalid input \'%s\' : %s\n", input_string, error_buf);
		}	

	If the input setting value is within a C string, users can call validate_string_save() directly as the validation function will convert the const char * to the
	appropriate type.

 	If the appropriate data type (Only numeric) is already available, then users can call the gyeeta::validate_numeric_save() directly
 
	Some sample validate_fp_ function pointers are defined in this header directly. Users can specify their own functions if needed. The
	validate_fp_ will validate the input of type specified in the settings object and then save the input to the specified address of output if valid. 
/*	
 */ 
#endif
 
class GY_SETTINGS
{
public :	
	const char * const 		name_;	
	const std::type_info		& typeid_;
	bool				is_mandatory_;
	const char * const		default_value_str_;		// Default value of field in string format (even though the field may not be a string)
	const char * const 		desc_;
	VALIDATE_SAVE_FP		validate_fp_;
};		

union POD_U
{
	long double			long_double_	{0};
	double				double_;
	float				float_;
	int64_t				int64_;
	uint64_t			uint64_;
	int32_t				int32_;
	uint32_t			uint32_;
	int16_t				int16_;	
	uint16_t			uint16_;
	bool				bool_;
	char				char_;
	uint8_t				uint8_;
};	

static bool validate_string_save(const GY_SETTINGS *psetarr, size_t szsetting, const char * name, const char *setting_value, void *store_addr, size_t sz_store, char *error_buf, size_t szerror) noexcept
{
	POD_U				pod;
	const void			*pdata = &pod.long_double_;
	int				ret;
	bool				bret;

	assert(psetarr);
	assert(name);
	assert(store_addr);
	assert(error_buf);

	*error_buf = '\0';

	for (size_t i = 0; i < szsetting; ++i) {
		if (0 == strcmp(psetarr[i].name_, name)) {

			auto		psetting = &psetarr[i];
			const auto & 	typeid_ = psetting->typeid_;

			assert(psetting->validate_fp_);

			if (!psetting->validate_fp_) {
				snprintf(error_buf, szerror, "No validation function pointer");
				return false;
			}	

			if (!setting_value) {
				if ((psetting->is_mandatory_)) {
					snprintf(error_buf, szerror, "Mandatory field %s not found", name);
					return false;
				}	

				if ((!psetting->default_value_str_) || (*psetting->default_value_str_ == '\0')) {
					// This field can be ignored
					return true;
				}
					
				setting_value = psetting->default_value_str_;
			}	

			ret = 0;
			bret = true;

			if ((typeid_ == typeid(char *)) || (typeid_ == typeid(const char *))) {
				pdata = setting_value;
			}	
			else if (typeid_ == typeid(long double)) {
				bret = string_to_number(setting_value, pod.long_double_);
			}	
			else if (typeid_ == typeid(double)) {
				bret = string_to_number(setting_value, pod.double_);
			}
			else if (typeid_ == typeid(float)) {
				bret = string_to_number(setting_value, pod.float_);
			}
			else if (typeid_ == typeid(int64_t)) {
				bret = string_to_number(setting_value, pod.int64_);
			}
			else if (typeid_ == typeid(uint64_t)) {
				bret = string_to_number(setting_value, pod.uint64_);
			}
			else if (typeid_ == typeid(int32_t)) {
				bret = string_to_number(setting_value, pod.int32_);
			}
			else if (typeid_ == typeid(uint32_t)) {
				bret = string_to_number(setting_value, pod.uint32_);
			}
			else if (typeid_ == typeid(int16_t)) {
				bret = string_to_number(setting_value, pod.int16_);
			}
			else if (typeid_ == typeid(uint16_t)) {
				bret = string_to_number(setting_value, pod.uint16_);
			}
			else if (typeid_ == typeid(bool)) {
				bret = string_to_number(setting_value, pod.bool_);
			}
			else if ((typeid_ == typeid(char)) || (typeid_ == typeid(int8_t))) {
				pod.char_ = *setting_value;
			}
			else if (typeid_ == typeid(uint8_t)) {
				pod.uint8_ = static_cast<uint8_t>(*setting_value);
			}
			else {
				assert(szerror != sizeof("typeid Unsupported : Please use POD type with only char * as a pointer type") + 111111);
				 
				snprintf(error_buf, szerror, "typeid unsupported for %s : Please use POD integral / float type or a char pointer type", name);
				return false;
			}

			if (!bret) {
				char		ebuf[64];
				
				snprintf(error_buf, szerror, "Invalid numeric type : %s", strerror_r(errno, ebuf, sizeof(ebuf) - 1));
				return false;
			}	

			try {
				return (*psetting->validate_fp_)(pdata, store_addr, sz_store, error_buf, szerror);
			}
			GY_CATCH_EXCEPTION(
				snprintf(error_buf, szerror, "Exception caught while validating setting %s : %s", name, GY_GET_EXCEPT_STRING);
				return false;
			);	
		}
	}		

	snprintf(error_buf, szerror, "Invalid setting name \'%s\'", name);
	return false;
}
		

template <typename T>
static bool validate_numeric_save(const GY_SETTINGS *psetarr, size_t szsetting, const char * name, const T setting_value, void *store_addr, size_t sz_store, char *error_buf, size_t szerror) noexcept
{
	POD_U				pod;
	const void			*pdata = &pod.long_double_;
	int				ret;

	static_assert(std::is_arithmetic<T>::value, "Integral or Floating point data type required.");

	T				data = setting_value;

	assert(psetarr);
	assert(name);
	assert(store_addr);
	assert(error_buf);

	*error_buf = '\0';

	for (size_t i = 0; i < szsetting; ++i) {
		if (0 == strcmp(psetarr[i].name_, name)) {

			auto		psetting = &psetarr[i];

			const auto &	typeid_ = typeid(T);

			assert(typeid_ == psetting->typeid_);

			if (typeid_ != psetting->typeid_) {
				snprintf(error_buf, szerror, "Invalid type specified while calling validation as different from configured type");
				return false;
			}	

			assert(psetting->validate_fp_);
			
			if (!psetting->validate_fp_) {
				snprintf(error_buf, szerror, "No validation function pointer");
				return false;
			}	

			try {
				return (*psetting->validate_fp_)(&data, store_addr, sz_store, error_buf, szerror);
			}
			GY_CATCH_EXCEPTION(
				snprintf(error_buf, szerror, "Exception caught while validating setting %s : %s", name, GY_GET_EXCEPT_STRING);
				return false;
			);	
		}
	}		

	snprintf(error_buf, szerror, "Invalid setting name \'%s\'", name);
	return false;
}

namespace settings {

/*
 * The validate_fp_ always receive the input data in the configured data type if it is a const char *. For e.g., in the function below,
 * const void *setting is already in a const char * format. store_addr is the address of the output variable to be updated.
 *
 * For integral or floating type fields, the setting is actually a pointer to the input type. See comments for validate_port() 
 */ 
static bool valid_hostname_ip(const void * setting, void * store_addr, size_t sz_store, char *error_buf, size_t szerror) noexcept
{
	const char 		*phost = static_cast<const char *>(setting);
	char			*pstore_addr = static_cast<char *>(store_addr);
	struct addrinfo		*res, hints;
	int			ret;

	std::memset(&hints, 0, sizeof(hints));

	hints.ai_family 	= AF_UNSPEC;
	hints.ai_socktype 	= SOCK_STREAM;

	ret = ::getaddrinfo(phost, nullptr, &hints, &res);
	if (ret != 0) {
		snprintf(error_buf, szerror, "Invalid IP/Hostname : %s for %s", gai_strerror(ret), phost);
		return false;
	}	

	::freeaddrinfo(res);

	if (pstore_addr) {
		GY_STRNCPY(pstore_addr, phost, sz_store);
	}

	return true;
}

/*
 * Here as the setting field is a non-string type, the const void *setting is a pointer to the actual input data. 
 * Here the input data is of uint16_t. So a deref is done after typecasting to a const uint16_t * type.
 *
 * The store_addr is of type uint16_t *.
 */ 
static bool valid_port(const void * setting, void * store_addr, size_t sz_store, char *error_buf, size_t szerror) noexcept
{
	uint16_t		port = *(static_cast<const uint16_t *>(setting));
	uint16_t		*pstore_port = static_cast<uint16_t *>(store_addr);

	if (port > 0) {
		if (pstore_port) {
			*pstore_port = port;
		}
		return true;
	}
	else {
		snprintf(error_buf, szerror, "Invalid Port 0 specified");
		return false;
	}	
}


static bool valid_string(const void * setting, void * store_addr, size_t sz_store, char *error_buf, size_t szerror) noexcept
{
	const char 		*pname = static_cast<const char *>(setting);
	char			*pstore_addr = static_cast<char *>(store_addr);

	assert(sz_store > 1);

	auto 			slen = ::strnlen(pname, sz_store);
	
	if (pname && slen < sz_store) {
		if (pstore_addr) {
			std::memcpy(pstore_addr, pname, slen);
			pstore_addr[slen] = '\0';
		}

		return true;
	}

	snprintf(error_buf, szerror, "Invalid length of input string");
	return false;
}

template <typename T>
static bool always_valid_numeric(const void * setting, void * store_addr, size_t sz_store, char *error_buf, size_t szerror) noexcept
{
	static_assert(std::is_arithmetic<T>::value, "Integral or Floating point data type required.");

	T			val = *(static_cast<const T *>(setting));
	T			*pstore_addr = static_cast<T *>(store_addr);

	assert(pstore_addr);
		
	*pstore_addr = val;
	return true;
}

/*
 * Pass a struct with constexpr min_val_ and max_val_ defined
 * For e.g., if T is of type float :
 *
struct PCT_MIN_MAX
{
	static constexpr float		min_val_ = 25.0f;
	static constexpr float		max_val_ = 99.99999f;
};	
 */ 
template <typename T, typename MIN_MAX_CLASS>
static bool min_max_numeric(const void * setting, void * store_addr, size_t sz_store, char *error_buf, size_t szerror) noexcept
{
	static_assert(std::is_arithmetic<T>::value, "Integral or Floating point data type required.");

	T			val = *(static_cast<const T *>(setting));
	T			*pstore_addr = static_cast<T *>(store_addr);

	const T			min_val = MIN_MAX_CLASS::min_val_, max_val = MIN_MAX_CLASS::max_val_;

	assert(pstore_addr);

	if ((val >= min_val) && (val < max_val)) {
		*pstore_addr = val;
		return true;
	}
	else {
		snprintf(error_buf, szerror, "Numeric value not within min max range");
		return false;
	}	
}


} // namespace settings
	
} // namespace gyeeta

