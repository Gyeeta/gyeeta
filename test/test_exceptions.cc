
#include	 	"gy_common_inc.h"
#include		"gy_malloc_hook.h"

#include 		<exception>	      // std::exception_ptr, std::current_exception, std::rethrow_exception
#include 		<stdexcept>     

using namespace gyeeta;

class MY_EXCEPTION_C : public std::exception
{
public:
	MY_EXCEPTION_C(const char *msg1) :
		num_except(
				({
					static int gnexcept = 0;
					if (*msg1) {
						gnexcept++;
					}	
					gnexcept;
				})
			)	
	{
		GY_STRNCPY(msg, msg1, sizeof(msg) - 1);
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Exception constructor #%d for message \'%s\'\n", num_except, msg);
	}
	
	MY_EXCEPTION_C() {*msg = '\0';}

	~MY_EXCEPTION_C()
	{
		INFOPRINTCOLOR(GY_COLOR_GREEN, "Exception destructor for #%d : message \'%s\'\n", num_except, msg);
		*msg = '\0';
	}	

	virtual const char *what() const noexcept
	{
		return msg;
	}

	char		msg[256];
	int		num_except;	
};

class except_test_c
{
public :	
	char		msg[256];

	except_test_c(const char *pmsg = "") noexcept
	{
		try {
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within except_test_c Constructor. Now throwing exception...\n");
			GY_STRNCPY(msg, pmsg, sizeof(msg));

			throw MY_EXCEPTION_C("Testing exception from noexcept class..."); 
		
		} 
		catch(const std::exception& e) {
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within class constructor exception catch...Exception is \'%s\'\n", e.what());
		}
	}

	~except_test_c()
	{
		INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within except_test_c Destructor...\n");
	}	
};	

void * dummy_thread(void *)
{
	while (true) {
		gy_nanosleep(100, 0);
	}	
}


int main () 
{
	pthread_t		thrid;

	// Create a dummy thread so that g++ will actually use Atomic stuff
	gy_create_thread(&thrid, dummy_thread, nullptr, 32 * 1024, false);
	
	std::exception_ptr p;
	
	INFOPRINT("Starting exception tests...\n");

	GY_MALLOC_HOOK::gy_malloc_init("Starting exception tests", true);

	GY_MALLOC_HOOK::gy_print_memuse("Starting Tests now...", true);

	{
		try {
			INFOPRINT("Before first throw...\n");
			throw MY_EXCEPTION_C("Testing first exception_ptr...");   // throws
		} 
		catch(const std::exception& e) {
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within Exception first catch...\n");

			p = std::current_exception();
			
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "After assigning to exception_ptr...\n");
		}

		try {
			GY_THROW_EXPRESSION("Testing GY_THROW_EXPRESSION exception...");
		}
		catch(const std::exception& e) {
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within Second Exception catch...Exception is \'%s\'\n", e.what());
		}

		try {
			throw std::runtime_error("Testing std::runtime_error exception...");
		}
		catch(const std::exception& e) {
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within std::runtime_error catch...Exception is \'%s\'\n", e.what());
		}

		except_test_c		test1;
	}
	INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "After first catch completed...\n");

	GY_MALLOC_HOOK::gy_print_memuse("After first catch completed...", true);

	try {
		std::rethrow_exception (p);
		
		INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "After rethrow_exception completed...\n");
	} 
	catch (const std::exception& e) {
		INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within Exception second catch...Exception is \'%s\'\n", e.what());
	}

	INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Now testing standard exceptions ...\n\n");
	{
		std::weak_ptr<int> 		weakp;

		try {
			std::shared_ptr<int> 	badshr(weakp);
		} 
		catch(const std::bad_weak_ptr& e) {
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within Standard Exception catch...Exception is \'%s\'\n", e.what());
		}
	}
	IRPRINT("\n\n"); INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Now testing GY_THROW_EXCEPTION  ...\n");
	{
		errno = ENOSPC;

		try {
			GY_THROW_SYS_EXCEPTION("Test of ENOSPC exception current time is %ld", syscall(SYS_time, nullptr));
		} 
		GY_CATCH_EXCEPTION(
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within GY_CATCH_EXCEPTION ... \'%s\'\n", GY_GET_EXCEPT_STRING);
		);

		try {
			GY_THROW_EXCEPTION("Test of no system error exception current time is %ld", time(nullptr));
		} 
		GY_CATCH_EXPRESSION(
			INFOPRINTCOLOR(GY_COLOR_CYAN_ITALIC, "Within GY_CATCH_EXPRESSION ... \'%s\'\n", GY_GET_EXCEPT_STRING);
		);

	}


	return 0;
}


