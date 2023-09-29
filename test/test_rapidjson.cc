//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later


#include		"gy_rapidjson.h"
#include		"gy_malloc_hook.h"

using namespace gyeeta;


static void stack_parse()
{
	JSON_DOCUMENT<2048, 2048>		doc;
	auto					& jdoc = doc.get_doc();
	char					telem[8192];

	static constexpr const char		origjson[] = R"(
		{
			"listener_domains"	 	:	["192.168.0.1", "127.0.0.1"],
			"listener_ports"		:	[10038, 10038],
			"shyama_hostname" 		:	"shyama.test1.local",
			"shyama_port"			:	10037,
			"postgres_info"			: {
				"postgres_hostname"		:	"localhost",
				"postgres_port"			:	10040,
				"postgres_user"			:	"gyeeta",
				"postgres_password"		:	"postgres",
				"spawn_postgres_db"		:	true,
				"postgres_conf_path"		:	"/opt/gyeeta/madhava/dbdata/postgresql.conf",
				"postgres_data_dir"		:	"/opt/gyeeta/madhava/dbdata",
				"autovacuum_scale_factor"	:	0.2
			},
			"नमस्ते"				:	"This is the config file containing the नमस्ते Есть credentials",
			"auto_respawn_on_exit"		:	true,
			"log_use_utc_time"		:	false
		}
	)";


	EXEC_TIME				exectime("json parser stack_parse");

	/*
	 * Cannot use ParseInsitu() as cannot mutate buffer
	 */
	/* jdoc.ParseInsitu(lstr).HasParseError() */

	if (jdoc.Parse(origjson).HasParseError()) {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid json : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), rapidjson::GetParseError_En(jdoc.GetParseError()));
		return;
	}	

	exectime.print_current_exec_time("After Parse");

	assert(true == jdoc.IsObject());

	if (auto aiter = jdoc.FindMember("listener_domains"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			assert(true == aiter->value[i].IsString());
		}
	}
	else {
		assert(false);
	}	

	if (auto aiter = jdoc.FindMember("listener_ports"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsArray()))) {
		for (uint32_t i = 0; i < aiter->value.Size(); i++) {
			assert(true == aiter->value[i].IsInt());
		}
	}
	else {
		assert(false);
	}	

	if (auto aiter = jdoc.FindMember("shyama_hostname"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsString()))) {
		GY_SAFE_STR_MEMCPY(telem, sizeof(telem), aiter->value.GetString(), aiter->value.GetStringLength());
	}	

	assert(0 == strcmp(telem, "shyama.test1.local"));

	if (auto aiter = jdoc.FindMember("shyama_port"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsInt()))) {
		int		shyama_port = aiter->value.GetInt();
	}	

	if (auto aiter = jdoc.FindMember("postgres_info"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsObject()))) {
		const GEN_JSON_VALUE 	& postobj = aiter->value.GetObject();
		
		if (auto aiter = postobj.FindMember("postgres_hostname"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsString()))) {
			GY_SAFE_STR_MEMCPY(telem, sizeof(telem), aiter->value.GetString(), aiter->value.GetStringLength());
		}	
		else {
			assert(false);
		}	

		if (auto aiter = postobj.FindMember("postgres_port"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsInt()))) {
			int		postgres_port = aiter->value.GetInt();
		}	

		if (auto aiter = postobj.FindMember("postgres_user"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsString()))) {
			GY_SAFE_STR_MEMCPY(telem, sizeof(telem), aiter->value.GetString(), aiter->value.GetStringLength());
		}	

		if (auto aiter = postobj.FindMember("postgres_password"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsString()))) {
			GY_SAFE_STR_MEMCPY(telem, sizeof(telem), aiter->value.GetString(), aiter->value.GetStringLength());
		}	

		if (auto aiter = postobj.FindMember("spawn_postgres_db"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsBool()))) {
			bool		spawn_postgres_db = aiter->value.GetBool();

			if (spawn_postgres_db) {

				if (auto aiter = postobj.FindMember("postgres_conf_path"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsString()))) {
					GY_SAFE_STR_MEMCPY(telem, sizeof(telem), aiter->value.GetString(), aiter->value.GetStringLength());
				}	

				if (auto aiter = postobj.FindMember("postgres_data_dir"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsString()))) {
					GY_SAFE_STR_MEMCPY(telem, sizeof(telem), aiter->value.GetString(), aiter->value.GetStringLength());
				}	

				if (auto aiter = postobj.FindMember("autovacuum_scale_factor"); ((aiter != postobj.MemberEnd()) && (aiter->value.IsDouble()))) {
					double		fact = aiter->value.GetDouble();
				}	
				else {
					assert(false);
				}	
			}	
			else {
				assert(false);
			}	
		}
		else {
			assert(false);
		}	
	}
	else {
		assert(false);
	}	

	if (auto aiter = jdoc.FindMember("auto_respawn_on_exit"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsBool()))) {
		bool		auto_respawn_on_exit = aiter->value.GetBool();
	}	

	if (auto aiter = jdoc.FindMember("log_use_utc_time"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsBool()))) {
		bool		log_use_utc_time = aiter->value.GetBool();
	}	

	if (auto aiter = jdoc.FindMember("नमस्ते"); ((aiter != jdoc.MemberEnd()) && (aiter->value.IsString()))) {
		INFOPRINTCOLOR(GY_COLOR_BLUE, "UTF8 field : %s : Value %s\n", "नमस्ते", aiter->value.GetString());
	}
	else {
		assert(false);	
	}	

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Stack JSON Allocator : Value Capacity = %lu bytes, Used = %lu bytes\n", doc.get_value_alloc().Capacity(), doc.get_value_alloc().Size());
	INFOPRINTCOLOR(GY_COLOR_CYAN, "Stack JSON Allocator : Parse Capacity = %lu bytes, Used = %lu bytes\n", doc.get_parse_alloc().Capacity(), doc.get_parse_alloc().Size());
}	

static void parse_situ_test()
{
	constexpr const char			tstr[] = "[ {\"hello\":\"world\",\"t\":true,\"f\":false,\"n\":null,\"i\":123,         \"pi\":3.1416,\"a\":[1,2,3],\"u64\":1234567890123456789,\"i64\":-1234567890123456789}, {\"h2\" : 1 }, {\"o3\" : -1 } ]";
	char					lstr[sizeof(tstr)];

	std::memcpy(lstr, tstr, sizeof(lstr));

	EXEC_TIME				exectime("json parser parse_situ_test");

	JSON_DOCUMENT<2048, 2048>		doc;
	auto					& jdoc = doc.get_doc();

	if (jdoc.ParseInsitu(lstr).HasParseError()) {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			doc.get_doc().GetErrorOffset(), rapidjson::GetParseError_En(doc.get_doc().GetParseError()));
		return;
	}	

	exectime.print_current_exec_time("After Parse");

	assert(true == jdoc.IsArray());
	assert(3 == jdoc.Size());
	assert(true == jdoc[1].IsObject());

	const auto			& obj = jdoc[1].GetObject();
	JSON_MEM_ITER	 		aiter = obj.FindMember("h2"); 

	if ((aiter != obj.MemberEnd()) && (aiter->value.IsInt())) {
		int		h2 = aiter->value.GetInt();

		assert(h2 == 1);

		// Replace h2 int with an Object

		auto				& value = aiter->value;
		JSON_DOCUMENT			doc2;
		auto				& jdoc2 = doc2.get_doc();

		if (jdoc2.Parse("{ \"h2a\" : \"Str1\", \"h2b\" : \"Str2\" }").HasParseError()) {
			ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
				doc2.get_doc().GetErrorOffset(), rapidjson::GetParseError_En(doc2.get_doc().GetParseError()));
			return;
		}	

		value.CopyFrom(jdoc2, jdoc.GetAllocator(), true /* copyConstStrings */);
		
		assert(value.IsObject());
		assert(value.HasMember("h2a"));
	}	



	STACK_JSON_WRITER<1024, 1024>		writer;
	STACK_JSON_PRETTY_WRITER<1024, 1024>	pr_writer;

	aiter->value.Accept(writer); 
	jdoc.Accept(pr_writer); 

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Output JSON Array 1 h2 elem is \'%s\'\n\n", writer.get_string());
	INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "Output Pretty JSON is \'%s\'\n\n", pr_writer.get_string());

	STRING_BUFFER<1024>			strbuf;
	const auto				& obj0 = jdoc[0].GetObject();
	
	for (auto it = obj0.MemberBegin(); it != obj0.MemberEnd(); ++it) {
		strbuf << "\n\t\t\tKey : \'" << std::pair(it->name.GetString(), it->name.GetStringLength()) << "\'\t\tValue : ";

		switch (it->value.GetType()) {
		
		case rapidjson::kNullType 	:	strbuf << "null"; break;	
		case rapidjson::kFalseType	:	strbuf << "false"; break;
		case rapidjson::kTrueType	:	strbuf << "true"; break;
		case rapidjson::kObjectType	:	strbuf << "[Object]"; break;
		case rapidjson::kArrayType	:	strbuf << "[Array]"; break;
		case rapidjson::kStringType	:	strbuf << '\'' << std::pair(it->value.GetString(), it->value.GetStringLength()) << '\''; break;
		case rapidjson::kNumberType	:	
							if (it->value.IsDouble()) {
								strbuf << it->value.GetDouble();
							}
							else {
								strbuf << it->value.GetInt64();
							}	
							break;

		default				:	break;				
		}	
	}	

	INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "Iterated Object Element #0 is %s\n\n", strbuf.buffer());
}	

static void small_stack_json_test()
{
	constexpr const char		tstr[] = "[ {\"hello\":\"world\" } ]";

	JSON_DOCUMENT<128, 128>		doc;
	auto				& jdoc = doc.get_doc();

	if (jdoc.Parse(tstr).HasParseError()) {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			doc.get_doc().GetErrorOffset(), rapidjson::GetParseError_En(doc.get_doc().GetParseError()));
		return;
	}	

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Small Stack JSON Allocator : Value Capacity = %lu bytes, Used = %lu bytes\n", doc.get_value_alloc().Capacity(), doc.get_value_alloc().Size());
	INFOPRINTCOLOR(GY_COLOR_CYAN, "Small Stack JSON Allocator : Parse Capacity = %lu bytes, Used = %lu bytes\n", doc.get_parse_alloc().Capacity(), doc.get_parse_alloc().Size());
}	

static void heap_json_doc_test()
{
	static constexpr const char		tstr[] = R"(
		{
			"listener_domains"	 	:	["192.168.0.1", "127.0.0.1"],
			"listener_ports"		:	[10038, 10038],
			"shyama_hostname" 		:	"shyama.test1.local",
			"shyama_port"			:	10037,
			"postgres_info"			: {
				"postgres_hostname"		:	"localhost",
				"postgres_port"			:	10040,
				"postgres_user"			:	"gyeeta",
				"postgres_password"		:	"postgres",
				"spawn_postgres_db"		:	true,
				"postgres_conf_path"		:	"/opt/gyeeta/madhava/dbdata/postgresql.conf",
				"postgres_data_dir"		:	"/opt/gyeeta/madhava/dbdata",
				"autovacuum_scale_factor"	:	0.2
			},
			"postgres_info2"			: {
				"postgres_hostname"		:	"localhost",
				"postgres_port"			:	10040,
				"postgres_user"			:	"gyeeta",
				"postgres_password"		:	"postgres",
				"spawn_postgres_db"		:	true,
				"postgres_conf_path"		:	"/opt/gyeeta/madhava/dbdata/postgresql.conf",
				"postgres_data_dir"		:	"/opt/gyeeta/madhava/dbdata",
				"autovacuum_scale_factor"	:	0.2
			},
			"नमस्ते"				:	"This is the config file containing the नमस्ते Есть credentials------------------------------------------------------------------------------------------------------------------------------------------------------This is the config file containing the नमस्ते Есть credentials------------------------------------------------------------------------------------------------------------------------------------------------------This is the config file containing the नमस्ते Есть credentials------------------------------------------------------------------------------------------------------------------------------------------------------This is the config file containing the नमस्ते Есть credentials------------------------------------------------------------------------------------------------------------------------------------------------------",
			"auto_respawn_on_exit"		:	true,
			"log_use_utc_time"		:	false
		}
	)";

	HEAP_JSON_DOCUMENT		doc(2600, 3800);
	auto				& jdoc = doc.get_doc();

	if (jdoc.Parse(tstr).HasParseError()) {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			jdoc.GetErrorOffset(), rapidjson::GetParseError_En(jdoc.GetParseError()));
		return;
	}	

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Heap JSON Allocator : Value Capacity = %lu bytes, Used = %lu bytes\n", doc.get_value_alloc().Capacity(), doc.get_value_alloc().Size());
	INFOPRINTCOLOR(GY_COLOR_CYAN, "Heap JSON Allocator : Parse Capacity = %lu bytes, Used = %lu bytes\n", doc.get_parse_alloc().Capacity(), doc.get_parse_alloc().Size());
}	



static void heap_writer_test()
{
	HEAP_JSON_WRITER<2048>		writer(4096);

	writer.StartObject();

	writer.KeyConst("first");
	writer.Int(1);

	writer.KeyConst("double array");
	writer.StartArray();
	writer.SetMaxDecimalPlaces(3);

	writer.Double(0.12345);                 // "0.123"
	writer.Double(0.001);                  // "0.001"
	writer.Double(0.0001);                  // "0.0"
	writer.Double(1.234567890123456e30);    // "1.234567890123456e30" (do not truncate significand for positive exponent)
	writer.Double(1.23e-4);                 // "0.0"                  (do truncate significand for negative exponent)
        
	writer.SetMaxDecimalPlaces(writer.kDefaultMaxDecimalPlaces);
	writer.EndArray();

	{
		char			tbuf[128];

		writer.KeyConst("Sub Object");
		writer.StartObject();

		writer.KeyConst("Subkey String");
		std::memset(tbuf, '.', sizeof(tbuf));
		snprintf(tbuf, sizeof(tbuf), "Test string with embedded \\x0 Current Time is %ld", time(0));
		writer.String(tbuf, sizeof(tbuf));

		writer.KeyConst("Subkey Array");
		writer.StartArray();
		writer.Int64(0x11111);
		writer.Int64(0x22222);
		writer.Int64(0x33333);
		writer.Int64(0x44444);
		writer.EndArray();

		writer.EndObject();

		assert(false == writer.IsComplete());
	}

	{
		const char 		jsonstr[] = "[\"Hello\\nWorld\", 123.456]";
		writer.Key("raw json");
		writer.RawValue(jsonstr, strlen(jsonstr), rapidjson::kArrayType);
	}

	writer.EndObject();

	assert(true == writer.IsComplete());

	assert(true == writer.is_string_internal(writer.get_string()));
	
	INFOPRINTCOLOR(GY_COLOR_CYAN, "Written new JSON using Heap Writer of size %lu bytes : \n%s\n\n", writer.get_size(), writer.get_string());
}	

static void stack_writer_test()
{
	STACK_JSON_WRITER<4096>		smallwriter;
	
	smallwriter.StartObject();

	smallwriter.KeyConst("Test2");
	smallwriter.Int(2);

	char				tbuf[512];

	strcpy(tbuf, "Long string follows");
	std::memset(tbuf + strlen("Long string follows"), '.', sizeof(tbuf) - strlen("Long string follows") - 1);
	tbuf[sizeof(tbuf) - 1] = 0;

	smallwriter.KeyConst("Long string");
	smallwriter.String(tbuf, sizeof(tbuf) - 1);
	smallwriter.EndObject();

	assert(true == smallwriter.IsComplete());

	assert(true == smallwriter.is_string_internal(smallwriter.get_string()));
	
	INFOPRINTCOLOR(GY_COLOR_BLUE, "Written new JSON using Stack Writer of size %lu bytes : \n%s\n\n", smallwriter.get_size(), smallwriter.get_string());


}	

static void ext_writer_test()
{
	char				extbuf[4096];
	EXT_JSON_PRETTY_WRITER		smallwriter(extbuf, sizeof(extbuf));
	
	smallwriter.StartObject();

	smallwriter.KeyConst("MultiLine");
	smallwriter.StringConst(R"(
		This is a \" multiline
		string with \\ नमस्ते aaa
		...)");

	char				tbuf[256];

	strcpy(tbuf, "Long string follows");
	std::memset(tbuf + strlen("Long string follows"), '.', sizeof(tbuf) - strlen("Long string follows") - 1);
	tbuf[sizeof(tbuf) - 1] = 0;

	smallwriter.KeyConst("Long string");
	smallwriter.String(tbuf, sizeof(tbuf) - 1);

	smallwriter.EndObject();

	assert(true == smallwriter.IsComplete());

	assert(true == smallwriter.is_string_internal(smallwriter.get_string()));
	
	INFOPRINTCOLOR(GY_COLOR_GREEN, "Written new JSON using Ext Writer of size %lu bytes : \n%s\n\n", smallwriter.get_size(), smallwriter.get_string());
}	

static void stack_reader_writer()
{
	STACK_JSON_PRETTY_WRITER<11000, 1400>	smallwriter;
	
	smallwriter.StartObject();

	smallwriter.KeyConst("Test3");
	smallwriter.Int(3);

	char					tbuf[1200];

	strcpy(tbuf, "Long string follows");
	std::memset(tbuf + strlen("Long string follows"), '.', sizeof(tbuf) - strlen("Long string follows") - 1);
	tbuf[sizeof(tbuf) - 1] = 0;

	smallwriter.KeyConst("Long string");
	smallwriter.String(tbuf, sizeof(tbuf) - 1);

	smallwriter.KeyConst("double array");
	smallwriter.StartArray();
	smallwriter.SetMaxDecimalPlaces(3);

	smallwriter.Double(0.12345);              
	smallwriter.Double(0.001);               
	smallwriter.Double(0.0001);             
        
	smallwriter.SetMaxDecimalPlaces(smallwriter.kDefaultMaxDecimalPlaces);
	smallwriter.EndArray();

	{
		char			tbuf[128];

		smallwriter.KeyConst("Sub Object");
		smallwriter.StartObject();

		smallwriter.KeyConst("Subkey String");
		auto 	tsz = GY_SAFE_SNPRINTF(tbuf, sizeof(tbuf), "Test string Current Time is %ld", time(0));
		smallwriter.String(tbuf, tsz);

		smallwriter.KeyConst("Subkey Array");
		smallwriter.StartArray();
		smallwriter.Int64(11111);
		smallwriter.Int64(22222);
		smallwriter.Int64(33333);
		smallwriter.String(number_to_string(0xFF269ABF0E89F643ul, "0x%016lX").get());
		smallwriter.EndArray();

		smallwriter.KeyConst("String Stream");
		smallwriter.StringStreamStart();
		smallwriter.StringStream("This", 4);
		smallwriter.StringStream(" is", 3);
		smallwriter.StringStream(" a ", 3);
		smallwriter.StringStreamConst("stream");
		smallwriter.StringStreamEnd();

		smallwriter.EndObject();

		assert(false == smallwriter.IsComplete());
	}

	smallwriter.EndObject();

	assert(true == smallwriter.IsComplete());

	assert(true == smallwriter.is_string_internal(smallwriter.get_string()));
	
	INFOPRINTCOLOR(GY_COLOR_CYAN, "Written new JSON using Stack Writer of size %lu bytes : \n%s\n\n", smallwriter.get_size(), smallwriter.get_string());

	JSON_DOCUMENT<4096, 4096>		doc;

	if (doc.get_doc().Parse(smallwriter.get_string()).HasParseError()) {
		ERRORPRINTCOLOR(GY_COLOR_RED, "Invalid JSON : Error at offset %lu : Error is \'%s\'\n\n", 
			doc.get_doc().GetErrorOffset(), rapidjson::GetParseError_En(doc.get_doc().GetParseError()));
		return;
	}	
	
	JSON_ALLOCATOR			& allocator = doc.get_doc().GetAllocator();
	rapidjson::Value		objval(rapidjson::kObjectType);

	objval.AddMember("var1", 123, allocator).AddMember("var2", "444", allocator);
	objval.AddMember("var3", 555, allocator);

	objval.RemoveMember("var3");  

	objval.AddMember("varstr", std::move(rapidjson::Value().SetString("foo")), allocator);

	doc.get_doc().AddMember("ValObject", std::move(objval), allocator);

	objval.SetArray().PushBack(1234, allocator).PushBack(2345, allocator);
	doc.get_doc().AddMember("ValArray", std::move(objval), allocator);

	assert(doc.get_doc().HasMember("ValObject"));
	
	auto		aiter = doc.get_doc().FindMember("ValArray");

	assert(aiter != doc.get_doc().MemberEnd());
	assert(aiter->value.IsArray());

	for (uint32_t i = 0; i < aiter->value.Size(); i++) {
		IRPRINT("%s[%d] = %d\n", aiter->name.GetString(), i, aiter->value[i].GetInt());
	}	

	aiter->value.PushBack(3456, allocator);

	aiter = doc.get_doc().FindMember("Sub Object");
	assert(aiter != doc.get_doc().MemberEnd());
	assert(aiter->value.IsObject());

	const auto & subobj = aiter->value.GetObject();

	aiter = subobj.FindMember("Subkey String");
	assert(aiter != subobj.MemberEnd());

	assert(nullptr != strstr(aiter->value.GetString(), "Current Time")); 

	smallwriter.Reset();

	smallwriter.StartObject();

	smallwriter.KeyConst("smallwriter");
	
	doc.get_doc().Accept(smallwriter); 

	smallwriter.EndObject();

	INFOPRINTCOLOR(GY_COLOR_BOLD_GREEN, "stack_reader_writer : Output Pretty JSON is \'%s\'\n\n", smallwriter.get_string());
}	

static void small_heap_test()
{
	HEAP_JSON_PRETTY_WRITER<128>	smallwriter(128);
	
	smallwriter.StartObject();

	smallwriter.KeyConst("Test2");
	smallwriter.Int(2);

	char				tbuf[512];

	strcpy(tbuf, "Long string follows");
	std::memset(tbuf + strlen("Long string follows"), '.', sizeof(tbuf) - strlen("Long string follows") - 1);
	tbuf[sizeof(tbuf) - 1] = 0;

	smallwriter.KeyConst("Long string");
	smallwriter.String(tbuf, sizeof(tbuf) - 1);

	GY_MALLOC_HOOK::gy_print_memuse("During small_heap_test() : > 1 mallocs expected...");

	smallwriter.EndObject();

	assert(true == smallwriter.IsComplete());
	
	assert(false == smallwriter.is_string_internal(smallwriter.get_string()));

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Written new JSON using Small Heap Writer of size %lu bytes : \n%s\n\n", smallwriter.get_size(), smallwriter.get_string());
}	

static void orig_writer_test()
{
	rapidjson::StringBuffer			buffer;
	POOL_JSON_PRETTY_WRITER 		writer(buffer);

	writer.StartObject();

	writer.KeyConst("a");
	writer.Int(1);

	writer.Key("raw");
	const char json[] = "[\"Hello\\nWorld\", 123.456]";
	writer.RawValue(json, sizeof(json) - 1, rapidjson::kArrayType);
	
	writer.Key("rawobj");
	const char json2[] = "{ \"int1\" : 123, \"flt1\" : 456.12 }";
	writer.RawValue(json2, sizeof(json2) - 1, rapidjson::kObjectType);

	writer.Key("UTF8 नमस्ते");
	writer.String("नमस्ते 你好 ...");

	writer.KeyConst("String Stream");
	writer.StringStreamStart();
	writer.StringStream("This", 4);
	writer.StringStream(" is", 3);
	writer.StringStream(" a ", 3);
	writer.StringStreamConst("नमस्ते ");
	writer.StringStreamConst("stream");
	writer.StringStreamConst(" spanning 2 lines...\n\tSecond Line...");
	writer.StringStreamEnd();

	writer.KeyConst("rawstream");

	writer.RawStreamStart(rapidjson::kObjectType);
	writer.RawStreamConst("{\n\t\"");
	writer.RawStream("key1", 4);
	writer.RawStreamConst("\" : ");
	writer.RawStreamConst("123,");
	writer.RawStreamConst("\"");
	writer.RawStreamConst("large\tkey\twith\ttabs", true /* escapestring */);
	writer.RawStreamConst("\" : \"");
	writer.RawStreamConst("This is a large string escaped ................................................................................"
	"\n\t\t..............................................................................................................................."
	"\n\t\t..............................................................................................................................."
	"\n\t\t..............................................................................................................................."
	"\n\t\t..............................................................................................................................."
	"\n\t\t...............................................................................................................................", true /* escapestring */);
	writer.RawStreamConst("\"}");
	writer.RawStreamEnd();


	writer.KeyConst("rawnum");
	writer.RawValue("123", 3, rapidjson::kNumberType);			// When the number is already in a string format

	{
		char			tbuf[128];

		writer.Key("Sub Object");
		writer.StartObject();

		writer.Key("Subkey String");
		auto 	tsz = GY_SAFE_SNPRINTF(tbuf, sizeof(tbuf), "Test string Current Time is %ld", time(0));
		writer.String(tbuf, tsz);

		writer.Key("Subkey Array");
		writer.StartArray();
		writer.Int64(11111);
		writer.Int64(22222);
		writer.Int64(33333);
		writer.Int64(44444);
		writer.EndArray();

		writer.EndObject();

		assert(false == writer.IsComplete());
	}

	GY_MALLOC_HOOK::gy_print_memuse("During orig_writer_test() : > 1 mallocs expected...");

	writer.EndObject();

	assert(true == writer.IsComplete());

	INFOPRINTCOLOR(GY_COLOR_CYAN, "Written new JSON using Rapidjson Writer of size %lu bytes : \n%s\n\n", writer.get_size(), writer.get_string());
}	

static void escape_json_test()
{
	char			ibuf[] = "Input string with 'Single Quote' and \"Double Quotes\" and \\ and ....\t\t\n";

	auto  			ebuf = gy_escape_json<512>(ibuf, sizeof(ibuf) - 1);

	INFOPRINTCOLOR(GY_COLOR_BLUE, "Escaped JSON Output of length %lu \'%s\' : [%s] of length %lu\n\n", sizeof(ibuf) - 1, ibuf, ebuf.get(), ebuf.length());

	char			tbuf[] = "p95resp";

	auto  			ebuf2 = gy_escape_json<300>(tbuf, sizeof(tbuf) - 1);

	INFOPRINTCOLOR(GY_COLOR_BLUE, "Escaped JSON Output of length %lu \'%s\' : [%s] of length %lu\n\n", sizeof(tbuf) - 1, tbuf, ebuf2.get(), ebuf2.length());
}

int main()
{
	GY_MALLOC_HOOK::gy_malloc_init("Starting rapidjson tests", true /* print_individual */);

	GY_MALLOC_HOOK::gy_print_memuse("Starting Tests now...", true);

	stack_parse();
	GY_MALLOC_HOOK::gy_print_memuse("After stack_parse() : 0 mallocs expected...", true);

	parse_situ_test();
	GY_MALLOC_HOOK::gy_print_memuse("After parse_situ_test() : 0 mallocs expected...", true);

	small_stack_json_test();
	GY_MALLOC_HOOK::gy_print_memuse("After small_stack_json_test() : > 1 mallocs expected...", true);

	heap_json_doc_test();
	GY_MALLOC_HOOK::gy_print_memuse("After heap_json_doc_test() : > 1 mallocs expected...", true);

	heap_writer_test();
	GY_MALLOC_HOOK::gy_print_memuse("After heap_writer_test() : only 1 malloc expected...", true);

	stack_writer_test();
	GY_MALLOC_HOOK::gy_print_memuse("After small_stack_test() : 0 mallocs expected...", true);

	ext_writer_test();
	GY_MALLOC_HOOK::gy_print_memuse("After ext_stack_test() : 0 mallocs expected...", true);

	stack_reader_writer();
	GY_MALLOC_HOOK::gy_print_memuse("After stack_reader_writer() : 0 mallocs expected...", true);

	small_heap_test();
	GY_MALLOC_HOOK::gy_print_memuse("After small_heap_test() : > 1 mallocs expected...", true);

	orig_writer_test();
	GY_MALLOC_HOOK::gy_print_memuse("After orig_writer_test() : > 1 mallocs expected...", true);

	escape_json_test();
	GY_MALLOC_HOOK::gy_print_memuse("After escape_json_test() : 0 mallocs expected...", true);
}

