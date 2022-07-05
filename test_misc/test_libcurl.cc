
#include		"gy_common_inc.h"
#include 		"gy_libcurl.h"
#include		"gy_rapidjson.h"

using namespace 	gyeeta;

int main(int argc, char *argv[])
{
	GY_CURL_EASY::global_init();

	{
		GY_CURL_EASY		ceasy;

		{
			auto			puniq = ceasy.url_encode("String to encode", GY_CONST_STRLEN("String to encode"));

			INFOPRINT("URL Encoded string for input \'String to encode\' is \'%s\'\n\n", puniq.get());
		}

		ceasy.set_url("http://localhost:10039/v1/currtime").set_user_agent("Test binary/1.0");

		ceasy.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
			INFOPRINT("Received Response : \'%s\' of length %lu\n", (const char *)contents, size * nmemb);

			return size * nmemb;
		}, nullptr);	


		auto 			[isok, res, perrstr] = ceasy.send_request_blocking();

		INFOPRINT("Request completed : isok = %d : Status = %ld : Error string is \'%s\'\n", isok, res, perrstr);
		
		ceasy.set_url("http://localhost:10039/v1/shyamastatus");

		auto 			[isok2, res2, perrstr2] = ceasy.send_request_blocking();

		INFOPRINT("Request 2 completed : isok = %d : Status = %ld : Error string is \'%s\'\n", isok2, res2, perrstr2);

		if (res2 == 401) {
			INFOPRINT("Now logging in as 401 Error seen...\n");

			GY_CURL_EASY		c2;
			SSO_STRING<200>		sso;		

			c2.set_url("http://localhost:10039/v1/basicauth").set_user_agent("Test binary/1.0");

			c2.set_http_post().set_content_json().set_http_post_data("{ \"username\" : \"admin\", \"password\" : \"gyeeta\" }");

			c2.set_response_callback([](void *contents, size_t size, size_t nmemb, void *userp) {
				size_t			tsz = size * nmemb;
				SSO_STRING<200>		*psso = (SSO_STRING<200> *)userp;

				if (psso && tsz && contents) {
					psso->append((const char *)contents, tsz);
				}	

				return tsz;
			}, &sso);	
			
			auto			[isok3, res3, perrstr3] = c2.send_request_blocking();
			
			if (isok3 && sso.size() > 0) {
				JSON_DOCUMENT<2048, 2048>		doc;
				auto					& jdoc = doc.get_doc();

				INFOPRINT("Login Response received is : \'%s\'\n\n", sso.data());

				if (jdoc.ParseInsitu(sso.data()).HasParseError()) {
					ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
						doc.get_doc().GetErrorOffset(), rapidjson::GetParseError_En(doc.get_doc().GetParseError()));
				}	

			}
			else {
				INFOPRINT("Login Request failed with Status %ld and Error \'%s\' \n\n", res3, perrstr3);
			}	
		}	
	}

	GY_CURL_EASY::global_cleanup();
}	




