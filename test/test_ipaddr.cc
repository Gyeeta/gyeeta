
#include 	"gy_common_inc.h"
#include	"gy_file_api.h"	

using namespace gyeeta;


int handle_ip(const GY_IP_ADDR & ipaddr)
{
	uint8_t			buf[sizeof(struct in6_addr)];
	char 			ipstr[INET6_ADDRSTRLEN];
	int			ret;

	IRPRINT("\nInput IP was %s (IPv%d)\n\n", ipaddr.printaddr(ipstr, sizeof(ipstr)), ipaddr.is_ipv4_addr() ? 4 : 6);

	ret = ipaddr.get_as_inaddr(buf);

	gyeeta::gy_print_buf(STDOUT_FILENO, buf, ret, 1 /* print_ascii */, (char *)"Binary Representation of IP address ");

	ret = ipaddr.get_ipflags();
	
	IRPRINT("\nIP Address Flags : ");

	if (ret) {

		char		ipdesc[256];

		ipaddr.get_ipdescription(ipdesc, sizeof(ipdesc));
		IRPRINT("%s\n", ipdesc);

		if (ipaddr.is_embedded_ipv4()) {
			IRPRINT("\nIP Address includes a tunnel/mapped IPv4 : %s\n", ipaddr.print_mapped_ipv4(ipstr, sizeof(ipstr)));
		}	
	}
	else {
		IRPRINT("Misc IP Address : No special flags");
	}	

	IRPRINT("\n");

	IRPRINT("Hash of IP Address is %u\n\n", ipaddr.get_hash());
	
	return 0;
}	

int main(int argc, char **argv)
{

	gyeeta::gdebugexecn = 1;

	if (argc < 2) {
		IRPRINT("\nUsage : %s <IP address or Hostname>\n\ne.g. %s 2001:cb8:0:f101::1\n\n", argv[0], argv[0]);
		return EXIT_FAILURE;
	}	

	bool			is_valid = false;

	GY_IP_ADDR		addr(argv[1], is_valid);

	if (is_valid) {
		return handle_ip(addr);
	}	

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Trying to resolve this hostname...\n");

	int			ret;
	GY_IP_ADDR		addrs[8];
	char			ebuf[128];
	
	ret = gy_resolve_hostname(argv[1], addrs, GY_ARRAY_SIZE(addrs), ebuf);
	if (ret <= 0) {
		ERRORPRINTCOLOR(GY_COLOR_BOLD_RED, "Could not resolve Hostname \'%s\' as well : %s\n\n", argv[1], ebuf);
		return -1;
	}	

	INFOPRINTCOLOR(GY_COLOR_GREEN, "Host \'%s\' resolved to %d IPs : \n", argv[1], ret);

	for (int i = 0; i < ret; ++i) {
		IRPRINT("----------------------------------------\n");
		handle_ip(addrs[i]);
	}	

	return 0;
}	


