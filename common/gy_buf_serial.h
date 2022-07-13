
/*
 * Serialization of different types to a fixed size buffer.
 */ 
#pragma				once


#include 			"gy_common_inc.h"

namespace gyeeta {

template <uint32_t max_sz_>
class alignas(16) BUF_SERIALIZE
{
	static constexpr uint32_t	VARBUF_MAGIC		= 0xAABBCCDDu;

	uint8_t				data_[max_sz_];
	uint32_t			magic_			{VARBUF_MAGIC};
	uint32_t			cur_sz_			{0};

	static_assert(max_sz_ != 0);

public :
	BUF_SERIALIZE() noexcept	= default;
		
	BUF_SERIALIZE(const uint8_t *buf, size_t buflen) noexcept
	{
		assert(buflen <= max_sz_);

		cur_sz_ = (buflen <= max_sz_ ? buflen : max_sz_);
		std::memcpy(data_, buf, cur_sz_);
	}	

	BUF_SERIALIZE(const struct iovec *piov, int iovcnt) noexcept
	{
		for (int i = 0; i < iovcnt; i++) {
			size_t		iov_len = piov[i].iov_len;

			if (cur_sz_ + iov_len > max_sz_) {
				iov_len = max_sz_ - cur_sz_;
			}	
			
			std::memcpy(data_ + cur_sz_, piov[i].iov_base, iov_len);

			cur_sz_ += iov_len;
			if (cur_sz_ == max_sz_) {
				break;
			}	
		}	
	}	

	/*
	 * zero copy serialization. Given a base Type T and its corresponding serialization class TSERIAL
	 * construct an inplace TSERIAL using this class. TSERIAL_PTR is the TSERIAL Pointer type passed 
	 * as the constructor needs to have passed params of both types.
	 * pdummyobj can be passed as a nullptr typecast to TSERIAL_PTR. We just need the type not the data. 
	 *
	 * The TSERIAL constructor needs to be passed the T obj, max_sz_ of the BUF_SERIALIZE and resulting
	 * serialization size via cur_sz_
	 */ 
	template <typename T, typename TSERIAL_PTR>
	BUF_SERIALIZE(const T & obj, const TSERIAL_PTR pdummyobj) noexcept
	{
		try {
			static_assert(std::is_pointer<TSERIAL_PTR>::value);

			using TSERIAL = typename std::remove_pointer<TSERIAL_PTR>::type;

			static_assert(max_sz_ >= sizeof(TSERIAL), "Serialization struct size > max size specified");

			new ((void *)this) TSERIAL(obj, max_sz_, cur_sz_);

			assert(cur_sz_ <= max_sz_);
			assert(magic_ == VARBUF_MAGIC);

			if (cur_sz_ > max_sz_) {
				cur_sz_ = 0;
			}

			if (magic_ != VARBUF_MAGIC) {
				cur_sz_ = 0;
			}	
		}
		GY_CATCH_EXCEPTION(
			DEBUGEXECN(1,
				ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Exception caught while in place constructor serializing %s : %s\n", 
					__PRETTY_FUNCTION__, GY_GET_EXCEPT_STRING);
			);

			cur_sz_ = 0;
		);
	}	

	~BUF_SERIALIZE() noexcept		= default;

	BUF_SERIALIZE(const BUF_SERIALIZE & other) noexcept 	
		: magic_(other.magic_), cur_sz_(other.cur_sz_)
	{
		if (cur_sz_ > max_sz_) cur_sz_ = max_sz_;
		std::memcpy(data_, other.data_, cur_sz_);
	}

	BUF_SERIALIZE(BUF_SERIALIZE && other) noexcept 
		: magic_(other.magic_), cur_sz_(other.cur_sz_)
	{
		if (cur_sz_ > max_sz_) cur_sz_ = max_sz_;
		std::memcpy(data_, other.data_, cur_sz_);

		other.cur_sz_ = 0;
	}

	BUF_SERIALIZE & operator= (const BUF_SERIALIZE & other) noexcept
	{
		if (this != &other) {
			cur_sz_ 	= other.cur_sz_;
			magic_		= other.magic_;

			if (cur_sz_ > max_sz_) {
				cur_sz_ = 0;
			}
			else {
				std::memcpy(data_, other.data_, cur_sz_);
			}	
		}	

		return *this;
	}	

	BUF_SERIALIZE & operator= (BUF_SERIALIZE && other) noexcept
	{
		if (this != &other) {
			cur_sz_ 	= other.cur_sz_;
			magic_		= other.magic_;

			if (cur_sz_ > max_sz_) {
				cur_sz_ = 0;
			}
			else {
				std::memcpy(data_, other.data_, cur_sz_);
			}	

			other.cur_sz_ = 0;
		}	

		return *this;
	}	

	const uint8_t * get_data() const noexcept
	{
		return data_;
	}

	uint8_t * get_data() noexcept
	{
		return data_;
	}

	uint32_t get_curr_size() const noexcept
	{
		return cur_sz_;
	}	

	uint32_t get_max_size() const noexcept
	{
		return max_sz_;
	}	

};	

} // namespace gyeeta


