//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"


/*
 * Enable SSE4.2 for better performance (SIMD). Comment this if running on a very old processor (older than Intel Sandybridge)
 * Only UTF8 encoding is supported. 
 */
#define 			RAPIDJSON_SSE42

#include 			"rapidjson/document.h"    
#include 			"rapidjson/error/en.h"
#include 			"rapidjson/prettywriter.h"

namespace gyeeta {

/*
 * NOTE : All Classes here are NOT Thread Safe
 */

using GEN_JSON_DOC		= rapidjson::GenericDocument<rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>, rapidjson::MemoryPoolAllocator<>>;
using GEN_JSON_VALUE		= rapidjson::GenericValue<rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>>;
using JSON_ALLOCATOR		= rapidjson::MemoryPoolAllocator<>;
using JSON_OBJECT		= rapidjson::GenericObject<false, GEN_JSON_VALUE>;
using JSON_CONST_OBJECT		= rapidjson::GenericObject<true, GEN_JSON_VALUE>;
using JSON_MEM_ITER		= rapidjson::GenericMemberIterator<false, rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>>::Iterator;
using JSON_MEM_CONST_ITER	= rapidjson::GenericMemberIterator<true, rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>>::Iterator;
using JSON_STRINGBUFFER 	= rapidjson::GenericStringBuffer<rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>>;

static constexpr size_t 	JSON_POOL_CHUNKHDRSZ = 24 /* sizeof(rapidjson::MemoryPoolAllocator<>::ChunkHeader) */;

/*
 * Heap Allocator with an initial Stack Buffer. Heap will be used after stack exhausted
 */
template <size_t stacksz_>
class JSON_STACK_ALLOCATOR : public CHAR_BUF<stacksz_>, public rapidjson::MemoryPoolAllocator<>
{
public :
	static_assert(stacksz_ >= 128, "Minimum 128 bytes stack");

	JSON_STACK_ALLOCATOR(size_t chunksz = 0) :
		rapidjson::MemoryPoolAllocator<>(this->buf_, stacksz_, chunksz ? std::max<size_t>(chunksz, JSON_POOL_CHUNKHDRSZ) : std::min<size_t>(stacksz_ - JSON_POOL_CHUNKHDRSZ, 1024))
	{}	

	rapidjson::MemoryPoolAllocator<> * getpoolptr() noexcept
	{
		return this;
	}	

	size_t get_max_size() const noexcept
	{
		return stacksz_;
	}	

	const char * get_buf_ptr() const noexcept
	{
		return this->buf_;
	}	
};	

/*
 * Json Document with initial Stack based Value and Parse buffers. Will use heap once these are exhausted.
 */
template <size_t value_stack_sz_ = 2048, size_t parse_stack_sz_ = 2048>
class JSON_DOCUMENT
{
public :
	JSON_STACK_ALLOCATOR<value_stack_sz_>	value_alloc_;
	JSON_STACK_ALLOCATOR<parse_stack_sz_>	parse_alloc_;
	GEN_JSON_DOC				doc_;	

	JSON_DOCUMENT(uint32_t value_chunk_sz = 0, uint32_t parse_chunk_sz = 0) 
		: value_alloc_(value_chunk_sz), parse_alloc_(parse_chunk_sz), doc_(&value_alloc_, parse_stack_sz_ >> 1, &parse_alloc_)
	{}	

	rapidjson::MemoryPoolAllocator<> & get_value_alloc() noexcept
	{
		return value_alloc_;
	}	

	rapidjson::MemoryPoolAllocator<> & get_parse_alloc() noexcept
	{
		return parse_alloc_;
	}	

	GEN_JSON_DOC & get_doc() noexcept
	{
		return doc_;
	}	

};	

/*
 * Json Document with Heap allocated Value and Parse buffers. This is efficient as multiple 
 * small sized heap alloc calls can be prevented. This can be used to store JSON objects 
 * with optimal memory usage. Users can parse the json string initially with a large Stack allocated 
 * doc and then based on get_value_alloc().Size() + 64, get_parse_alloc().Size() + 64 calls to allocate the
 * corresponding HEAP_JSON_DOCUMENT. 
 */
class HEAP_JSON_DOCUMENT
{
public :
	uint32_t				valblocksz_;
	uint32_t				parseblocksz_;
	std::unique_ptr<char []>		valuniq_;
	std::unique_ptr<char []>		parseuniq_;
	std::optional<JSON_ALLOCATOR>		value_alloc_;
	std::optional<JSON_ALLOCATOR>		parse_alloc_;
	std::optional<GEN_JSON_DOC>		doc_;	

	HEAP_JSON_DOCUMENT(uint32_t valblocksz, uint32_t parseblocksz, uint32_t value_chunk_sz = 0, uint32_t parse_chunk_sz = 0) 
		: valblocksz_(std::max<uint32_t>(valblocksz, 128)), parseblocksz_(std::max<uint32_t>(parseblocksz, 128)),
		valuniq_(new char[valblocksz_]), parseuniq_(new char[parseblocksz_])
	{
		value_alloc_.emplace(valuniq_.get(), valblocksz_, 
					value_chunk_sz ? std::max<size_t>(value_chunk_sz, JSON_POOL_CHUNKHDRSZ) : std::min<size_t>(valblocksz_ - JSON_POOL_CHUNKHDRSZ, 1024));
		parse_alloc_.emplace(parseuniq_.get(), parseblocksz, 
					parse_chunk_sz ? std::max<size_t>(parse_chunk_sz, JSON_POOL_CHUNKHDRSZ) : std::min<size_t>(parseblocksz_ - JSON_POOL_CHUNKHDRSZ, 1024));

		doc_.emplace(&value_alloc_.value(), parseblocksz >> 1, &parse_alloc_.value());
	}	

	rapidjson::MemoryPoolAllocator<> & get_value_alloc() noexcept
	{
		return *value_alloc_;
	}	

	rapidjson::MemoryPoolAllocator<> & get_parse_alloc() noexcept
	{
		return *parse_alloc_;
	}	

	GEN_JSON_DOC & get_doc() noexcept
	{
		return *doc_;
	}	
};	


template <size_t string_stacksz_, size_t writer_stacksz_ = 2048>
class STACK_JSON_STRINGBUF : public JSON_STACK_ALLOCATOR<string_stacksz_>, public JSON_STRINGBUFFER
{
public :
	JSON_STACK_ALLOCATOR<writer_stacksz_>	writer_alloc_;

	STACK_JSON_STRINGBUF() : JSON_STRINGBUFFER(this->getpoolptr())
	{}	

	rapidjson::MemoryPoolAllocator<> * get_string_poolptr() noexcept
	{
		return this->getpoolptr();
	}	

	rapidjson::MemoryPoolAllocator<> * get_writer_poolptr() noexcept
	{
		return this->writer_alloc_.getpoolptr();
	}	

	JSON_STRINGBUFFER & get_string_buffer() noexcept
	{
		return *this;
	}	

	bool is_string_internal(const char * poutstr) const noexcept
	{
		return (this->get_buf_ptr() + JSON_POOL_CHUNKHDRSZ == poutstr);
	}	
};	

template <size_t writer_stacksz_ = 2048>
class HEAP_JSON_STRINGBUF : public std::unique_ptr<char []>, public rapidjson::MemoryPoolAllocator<>, public JSON_STRINGBUFFER
{
public :
	using CharUniq			= std::unique_ptr<char []>;

	JSON_STACK_ALLOCATOR<writer_stacksz_>	writer_alloc_;

	HEAP_JSON_STRINGBUF(size_t string_heapsz, size_t chunksz = 0) : 
		CharUniq(new char[string_heapsz]), 
		rapidjson::MemoryPoolAllocator<>(CharUniq::get(), string_heapsz, chunksz ? chunksz : string_heapsz - JSON_POOL_CHUNKHDRSZ), 
		JSON_STRINGBUFFER((rapidjson::MemoryPoolAllocator<> *)(this))
	{}	

	rapidjson::MemoryPoolAllocator<> * get_string_poolptr() noexcept
	{
		return this->getpoolptr();
	}	

	rapidjson::MemoryPoolAllocator<> * get_writer_poolptr() noexcept
	{
		return this->writer_alloc_.getpoolptr();
	}	

	JSON_STRINGBUFFER & get_string_buffer() noexcept
	{
		return *this;
	}	

	bool is_string_internal(const char * poutstr) const noexcept
	{
		return (CharUniq::get() + JSON_POOL_CHUNKHDRSZ == poutstr);
	}	
};	

template <size_t writer_stacksz_ = 2048>
class EXT_JSON_STRINGBUF : public rapidjson::MemoryPoolAllocator<>, public JSON_STRINGBUFFER
{
public :
	JSON_STACK_ALLOCATOR<writer_stacksz_>	writer_alloc_;
	char					*pextbuf_		{nullptr};

	EXT_JSON_STRINGBUF(char *pextbuf, size_t szext, size_t chunksz = 0) : 
		rapidjson::MemoryPoolAllocator<>(pextbuf, szext, chunksz ? chunksz : szext - JSON_POOL_CHUNKHDRSZ), 
		JSON_STRINGBUFFER((rapidjson::MemoryPoolAllocator<> *)(this)),
		pextbuf_(pextbuf)
	{}	

	rapidjson::MemoryPoolAllocator<> * get_string_poolptr() noexcept
	{
		return this->getpoolptr();
	}	

	rapidjson::MemoryPoolAllocator<> * get_writer_poolptr() noexcept
	{
		return this->writer_alloc_.getpoolptr();
	}	

	JSON_STRINGBUFFER & get_string_buffer() noexcept
	{
		return *this;
	}	

	bool is_string_internal(const char * poutstr) const noexcept
	{
		return (pextbuf_ + JSON_POOL_CHUNKHDRSZ == poutstr);
	}	
};	

typedef void (*RESERVE_CB)(void * arg, uint32_t sz);

template <typename OutputStream, typename Allocator, typename JWriter>
class JSON_WRITER_BASE : public JWriter
{
public :
	RESERVE_CB		reserve_cb_;
	void			*reserve_arg_;

	/*
	 * RESERVE_CB mainly used for streaming cases to prevent split of multibyte UTF8 strings. Will be called
	 * for Keys, Strings, RawWrite, StringStream, RawStream calls. The reason for the Reserve is if a 
	 * multibyte UTF8 char splits on a message boundary the message receiver will throw an error as UTF8 parse will fail.
	 */
	JSON_WRITER_BASE(OutputStream & os, Allocator * pallocator = nullptr, RESERVE_CB reserve_cb = nullptr, void * reserve_arg = nullptr)
		: JWriter(os, pallocator), reserve_cb_(reserve_cb), reserve_arg_(reserve_arg)
	{}	

	bool isStarted() const noexcept
	{
		return JWriter::hasRoot_;
	}

	bool isComplete() const 
	{
		return JWriter::IsComplete();
	}	

	bool Key(const char *str)
	{
		return Key(str, strlen(str));
	}	

	bool Key(const char *str, uint32_t len, bool tocopy = false)
	{
		if (len && reserve_cb_) {
			(*reserve_cb_)(reserve_arg_, len);
		}	
		return JWriter::Key(str, len, tocopy);
	}	

	bool String(const char *str)
	{
		return String(str, strlen(str));
	}	

	bool String(const char *str, uint32_t len, bool tocopy = false)
	{
		if (len && reserve_cb_) {
			(*reserve_cb_)(reserve_arg_, len);
		}	
		return JWriter::String(str, len, tocopy);
	}	

	bool String(std::pair<const char *, uint32_t> pstr)
	{
		return String(pstr.first, pstr.second);
	}	

	bool String(std::string_view view)
	{
		return String(view.data(), view.size());
	}	

	bool String(STR_WR_BUF & strbuf)
	{
		return String(strbuf.buffer(), strbuf.length());
	}	

	/*
	 * Use only for string literals and not char arrays as no run time strlen calculated...
	 */
	template <size_t N>
	JSON_WRITER_BASE & KeyConst(const char (&str)[N]) 
	{
		Key(static_cast<const char *>(str), N - 1);

		return *this;
	}

	template <size_t N>
	bool StringConst(const char (&str)[N]) 
	{
		return String(static_cast<const char *>(str), N - 1);
	}

	/*
	 * Disable local char arrays
	 */
	template <size_t N>
	JSON_WRITER_BASE & KeyConst(char (&str)[N])	= delete;

	template <size_t N>
	bool StringConst(char (&str)[N]) 		= delete;


	/*
	 * Streaming for very large strings.
	 * For e.g. if the Object consists of multiple rows from a DB query (cursor fetches)
	 * 
	 * e.g.
			writer.StartObject();
			writer.KeyConst("SS");

			writer.StringStreamStart();
			writer.StringStream("This", strlen("This"));
			writer.StringStream(" is", 3);
			writer.StringStreamConst(" a ");	// Using the String literal form
			writer.StringStreamConst("stream");
			writer.StringStreamEnd();

			writer.EndObject();
		
			Output : 
			{"SS":"This is a stream"}
	 */
	bool StringStream(const char *str, uint32_t length) 
	{
		return StringStreamInt(str, length);
	}

	void StringStreamStart()
	{
		StringStreamInt("", 0, true, false);
	}	

	void StringStreamEnd()
	{
		StringStreamInt("", 0, false, true);
	}	

	template <size_t N>
	bool StringStreamConst(const char (&str)[N]) 
	{
		return StringStream(static_cast<const char *>(str), N - 1);
	}

	template <size_t N>
	bool StringStreamConst(char (&str)[N]) 	= delete;


	/*
	 * Streaming Object Data for very large streaming data which is not of JSON type string.
	 * 
	 * WARNING : No JSON escaping will be done by default. Please ensure no characters from "\x00" to "\x1F" within 
	 * the data... or else invalid JSON will result.
	 *
	 * If data is a string type, you can specify the escapestring param as true to escape the invalid characters as shown below :
	 

		writer.KeyConst("rawstream");

		writer.RawStreamStart(rapidjson::kObjectType);
		writer.RawStreamConst("{\n\t\"");
		writer.RawStream("key1", 4);
		writer.RawStreamConst("\" : ");
		writer.RawStreamConst("123,");
		writer.RawStreamConst("\"");
		writer.RawStreamConst("large\tkey\twith\ttabs", true);	// escapestring
		writer.RawStreamConst("\" : \"");
		writer.RawStreamConst("This is a string escaped\t\t\n ................................................................................", true);	// escapestring
		writer.RawStreamConst("\"}");
		writer.RawStreamEnd();

		Output : 
		    "rawstream":{
			"key1" : 123,
			"large\tkey\twith\ttabs" : "This is a string escaped\t\t\n ................................................................................"
			}
				
	 */
	bool RawStream(const char * str, uint32_t length, bool escapestring = false) 
	{
		return RawStreamInt(str, length, false, false, escapestring ? rapidjson::kStringType : rapidjson::kNullType, escapestring);
	}

	void RawStreamStart(rapidjson::Type type)
	{
		RawStreamInt("", 0, true, false, type);
	}	

	void RawStreamEnd()
	{
		RawStreamInt("", 0, false, true);
	}	

	template <size_t N>
	bool RawStreamConst(const char (&str)[N], bool escapestring = false) 
	{
		return RawStream(static_cast<const char *>(str), N - 1, escapestring);
	}

	template <size_t N>
	bool RawStreamConst(char (&str)[N], bool) 	= delete;

	const char * get_string() const 
	{
		return JWriter::os_->GetString();
	}

	size_t get_size() const 
	{ 
		return JWriter::os_->GetSize();
	}

	OutputStream * get_stream() noexcept
	{
		return JWriter::os_;
	}	

protected :

	bool StringStreamInt(const char * str, uint32_t length, bool is_start = false, bool is_finish = false) 
	{
		if (is_start) {
			JWriter::Prefix(rapidjson::kStringType);
		}	

		bool bret = WriteStringStream(str, length, is_start, is_finish);

		if (is_finish) {
			return JWriter::EndValue(bret);
		}	

		return false;
	}

	bool RawStreamInt(const char * str, uint32_t length, bool is_start = false, bool is_finish = false, rapidjson::Type type = rapidjson::kNullType, bool escapestring = false) 
	{
		if (is_start) {
			JWriter::Prefix(type);
		}	

		bool 		bret;
		
		if (false == escapestring) {
			if (length) {
				
				if (reserve_cb_) {
					(*reserve_cb_)(reserve_arg_, length);
				}

				bret = JWriter::WriteRawValue(str, length);
			}
			else {
				bret = true;
			}	
		}
		else {
			bret = WriteStringStream(str, length, is_start, is_finish);
		}	

		if (is_finish) {
			return JWriter::EndValue(bret);
		}	

		return false;
	}

	bool WriteStringStream(const char * str, uint32_t length, bool is_start, bool is_finish)  
	{
		using namespace		rapidjson;

		static const typename OutputStream::Ch hexDigits[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
		static const char escape[256] = {
#define Z16 		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
			//0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
			'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'b', 't', 'n', 'u', 'f', 'r', 'u', 'u', // 00
			'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', 'u', // 10
			0,   0, '"',   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, // 20
			Z16, Z16,                                                                       // 30~4F
			0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,'\\',   0,   0,   0, // 50
			Z16, Z16, Z16, Z16, Z16, Z16, Z16, Z16, Z16, Z16                                // 60~FF
#undef Z16
		};

		if (length && reserve_cb_) {
			(*reserve_cb_)(reserve_arg_, length);
		}

		PutReserve(*JWriter::os_, 2 + length * 6); // "\uxxxx..."

		if (is_start) {
			PutUnsafe(*JWriter::os_, '\"');
		}
		GenericStringStream<UTF8<>> is(str);
		while (JWriter::ScanWriteUnescapedString(is, length)) {
			const char c = is.Peek();
			if (gy_unlikely(escape[static_cast<unsigned char>(c)]))  {
				is.Take();
				PutUnsafe(*JWriter::os_, '\\');
				PutUnsafe(*JWriter::os_, static_cast<typename OutputStream::Ch>(escape[static_cast<unsigned char>(c)]));
				if (escape[static_cast<unsigned char>(c)] == 'u') {
					PutUnsafe(*JWriter::os_, '0');
					PutUnsafe(*JWriter::os_, '0');
					PutUnsafe(*JWriter::os_, hexDigits[static_cast<unsigned char>(c) >> 4]);
					PutUnsafe(*JWriter::os_, hexDigits[static_cast<unsigned char>(c) & 0xF]);
				}
			}
			else if (!Transcoder<UTF8<>, UTF8<>>::TranscodeUnsafe(is, *JWriter::os_))
				return false;
		}

		if (is_finish) {
			PutUnsafe(*JWriter::os_, '\"');
		}
		return true;
	}

};	

template <typename OutputStream = rapidjson::StringBuffer, typename Allocator = rapidjson::CrtAllocator>
class POOL_JSON_WRITER : public JSON_WRITER_BASE<OutputStream, Allocator, rapidjson::Writer<OutputStream, rapidjson::UTF8<>, rapidjson::UTF8<>, Allocator>>
{
public :
	POOL_JSON_WRITER(OutputStream & os, Allocator * pallocator = nullptr, RESERVE_CB reserve_cb = nullptr, void * reserve_arg = nullptr)
		: JSON_WRITER_BASE<OutputStream, Allocator, rapidjson::Writer<OutputStream, rapidjson::UTF8<>, rapidjson::UTF8<>, Allocator>>(os, pallocator, reserve_cb, reserve_arg)
	{}	
};	

template <typename OutputStream = rapidjson::StringBuffer, typename Allocator = rapidjson::CrtAllocator>
class POOL_JSON_PRETTY_WRITER : public JSON_WRITER_BASE<OutputStream, Allocator, 
					rapidjson::PrettyWriter<OutputStream, rapidjson::UTF8<>, rapidjson::UTF8<>, Allocator>>
{
public :
	POOL_JSON_PRETTY_WRITER(OutputStream & os, Allocator * pallocator = nullptr, RESERVE_CB reserve_cb = nullptr, void * reserve_arg = nullptr)
		: JSON_WRITER_BASE<OutputStream, Allocator,
				rapidjson::PrettyWriter<OutputStream, rapidjson::UTF8<>, rapidjson::UTF8<>, Allocator>>(os, pallocator, reserve_cb, reserve_arg)
	{}	
};	

template <size_t string_stacksz_, size_t writer_stacksz_ = 2048>
class STACK_JSON_WRITER : public STACK_JSON_STRINGBUF<string_stacksz_, writer_stacksz_>, public POOL_JSON_WRITER<JSON_STRINGBUFFER, rapidjson::MemoryPoolAllocator<>>
{
public :
	STACK_JSON_WRITER() 
		: POOL_JSON_WRITER(this->get_string_buffer(), this->get_writer_poolptr())
	{}	

	POOL_JSON_WRITER & get_writer() noexcept
	{
		return *this;
	}	

	void Reset()
	{
		this->get_string_buffer().Clear();
		this->get_writer().Reset(this->get_string_buffer());
	}	
};	

template <size_t string_stacksz_, size_t writer_stacksz_ = 2048>
class STACK_JSON_PRETTY_WRITER : public STACK_JSON_STRINGBUF<string_stacksz_, writer_stacksz_>, public POOL_JSON_PRETTY_WRITER<JSON_STRINGBUFFER, rapidjson::MemoryPoolAllocator<>>
{
public :
	STACK_JSON_PRETTY_WRITER() 
		: POOL_JSON_PRETTY_WRITER(this->get_string_buffer(), this->get_writer_poolptr())
	{}	

	POOL_JSON_PRETTY_WRITER & get_writer() noexcept
	{
		return *this;
	}	

	void Reset()
	{
		this->get_string_buffer().Clear();
		this->get_writer().Reset(this->get_string_buffer());
	}	
};	

/*
 * NOTE : If the output JSON is expected to be larger than string_heapsz better to use rapidjson::Writer and rapidjson::StringBuffer as
 * else a lot of memory allocs will be cached and result in large memory utilization...
 */
template <size_t writer_stacksz_ = 2048>
class HEAP_JSON_WRITER : public HEAP_JSON_STRINGBUF<writer_stacksz_>, public POOL_JSON_WRITER<JSON_STRINGBUFFER, rapidjson::MemoryPoolAllocator<>>
{
public :
	HEAP_JSON_WRITER(size_t string_heapsz) 
		: HEAP_JSON_STRINGBUF<writer_stacksz_>(string_heapsz), POOL_JSON_WRITER(this->get_string_buffer(), this->get_writer_poolptr())
	{}	

	POOL_JSON_WRITER & get_writer() noexcept
	{
		return *this;
	}	

	void Reset()
	{
		this->get_string_buffer().Clear();
		this->get_writer().Reset(this->get_string_buffer());
	}	
};	

/*
 * NOTE : If the output JSON is expected to be larger than string_heapsz better to use rapidjson::Writer and rapidjson::StringBuffer as
 * else a lot of memory allocs will be cached and result in large memory utilization...
 */
template <size_t writer_stacksz_ = 2048>
class HEAP_JSON_PRETTY_WRITER : public HEAP_JSON_STRINGBUF<writer_stacksz_>, public POOL_JSON_PRETTY_WRITER<JSON_STRINGBUFFER, rapidjson::MemoryPoolAllocator<>>
{
public :
	HEAP_JSON_PRETTY_WRITER(size_t string_heapsz) 
		: HEAP_JSON_STRINGBUF<writer_stacksz_>(string_heapsz), POOL_JSON_PRETTY_WRITER(this->get_string_buffer(), this->get_writer_poolptr())
	{}	

	POOL_JSON_PRETTY_WRITER & get_writer() noexcept
	{
		return *this;
	}	

	void Reset()
	{
		this->get_string_buffer().Clear();
		this->get_writer().Reset(this->get_string_buffer());
	}	
};	

/*
 * NOTE : If the output JSON is expected to be larger than szext better to use rapidjson::Writer and rapidjson::StringBuffer as
 * else a lot of memory allocs will be cached and result in large memory utilization...
 */
template <size_t writer_stacksz_ = 2048>
class EXT_JSON_WRITER : public EXT_JSON_STRINGBUF<writer_stacksz_>, public POOL_JSON_WRITER<JSON_STRINGBUFFER, rapidjson::MemoryPoolAllocator<>>
{
public :
	EXT_JSON_WRITER(char *pextbuf, size_t szext) 
		: EXT_JSON_STRINGBUF<writer_stacksz_>(pextbuf, szext), POOL_JSON_WRITER(this->get_string_buffer(), this->get_writer_poolptr())
	{}	

	POOL_JSON_WRITER & get_writer() noexcept
	{
		return *this;
	}	

	void Reset()
	{
		this->get_string_buffer().Clear();
		this->get_writer().Reset(this->get_string_buffer());
	}	
};	

/*
 * NOTE : If the output JSON is expected to be larger than szext better to use rapidjson::Writer and rapidjson::StringBuffer as
 * else a lot of memory allocs will be cached and result in large memory utilization...
 */
template <size_t writer_stacksz_ = 2048>
class EXT_JSON_PRETTY_WRITER : public EXT_JSON_STRINGBUF<writer_stacksz_>, public POOL_JSON_PRETTY_WRITER<JSON_STRINGBUFFER, rapidjson::MemoryPoolAllocator<>>
{
public :
	EXT_JSON_PRETTY_WRITER(char *pextbuf, size_t szext) 
		: EXT_JSON_STRINGBUF<writer_stacksz_>(pextbuf, szext), POOL_JSON_PRETTY_WRITER(this->get_string_buffer(), this->get_writer_poolptr())
	{}	

	POOL_JSON_PRETTY_WRITER & get_writer() noexcept
	{
		return *this;
	}	

	void Reset()
	{
		this->get_string_buffer().Clear();
		this->get_writer().Reset(this->get_string_buffer());
	}	
};	

static constexpr size_t max_json_escape_size(size_t origbuf_sz) noexcept
{
	return origbuf_sz * 6 + 2;
}	

/*
 * NOTE : szout MUST be at least 288 bytes or else the escape will fail
 *
 * Will throw an exception if szout is inadequate for the escaped buffer. 
 * Min length of szout must be at least 6x inputlen (max_json_escape_size(inputlen))
 * The escaped string will be written at some offset from outbuf start and so the returned char * pointer needs to be used instead of outbuf directly
 * If throw_on_error is false, will return empty string
 */
static std::pair<const char *, size_t> gy_escape_json(char *outbuf, size_t szout, const char *input, size_t inputlen, bool throw_on_error = true)
{
	assert(outbuf && input);

	if (inputlen == 0) {
		if (szout > 3) {
			strcpy(outbuf, "\"\"");
			return {outbuf, 2};
		}

		*outbuf = 0;
		return {outbuf, 0};
	}

	if (szout < std::max<size_t>(288lu, max_json_escape_size(inputlen))) {
		if (throw_on_error == false) {
retempty :			
			*outbuf = 0;
			return {outbuf, 0};
		}
		if (szout < 128) {
			GY_THROW_EXCEPTION("JSON escape : Too small size of output buffer %lu : Require at least 300 bytes", szout);
		}

		GY_THROW_EXCEPTION("JSON escape inadequate size of output buffer %lu : required %lu", szout, max_json_escape_size(inputlen));
	}	

	try {
		EXT_JSON_WRITER			smallwriter(outbuf, szout);
		
		smallwriter.String(input, inputlen);
		
		const char *			pret = smallwriter.get_string();
		size_t				slen = smallwriter.get_size();

		if (true == smallwriter.is_string_internal(pret)) {
			return {pret, slen};
		}
		// This condition should not occur as we check at start itself...
		else if (throw_on_error) {
			GY_THROW_EXCEPTION("JSON escape inadequate size of output buffer %lu : require more than %lu", szout, max_json_escape_size(slen) + 2);
		}	

		*outbuf = 0;
		return {outbuf, 0};
	}
	catch(...) {
		if (throw_on_error == false) {
			goto retempty;
		}	

		throw;
	}
}	

/*
 * Will throw an exception if maxsz is inadequate for the escaped buffer. 
 * Min length of maxsz must be at least 6x inputlen (max_json_escape_size(inputlen))
 * If throw_on_error is false, will return empty string
 */
template <size_t maxsz = 1024, size_t min_inputlen = 0>
static STR_ARRAY<maxsz> gy_escape_json(const char *input, size_t inputlen, bool throw_on_error = true)
{
	STR_ARRAY<maxsz>		jbuf;
	char				*pwr = jbuf.get();

	static_assert(maxsz >= 300, "Min Output Buffer must size is 300");

	static_assert(maxsz >= max_json_escape_size(min_inputlen), "maxsz template param must be at least max_json_escape_size(min_inputlen) around 6x times");

	auto [pout, elen] = gy_escape_json(pwr, jbuf.maxsz(), input, inputlen, throw_on_error);

	jbuf.set_len_offset(elen, pout - pwr);

	return jbuf;
}	


} // namespace gyeeta	

