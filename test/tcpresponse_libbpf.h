
#pragma				once

typedef void (*TCPRESPONSE_LIBBPF_CB)(void *pcb_cookie, void *pdata, int data_size);


void * tcpresponse_libbpf_init(TCPRESPONSE_LIBBPF_CB cbv4, TCPRESPONSE_LIBBPF_CB cbv6, void *pcb_cookie = nullptr);

void tcpresponse_libbpf_poll(void *, int msec, bool is_v4);

void tcpresponse_libbpf_start_collection(void *);

void tcpresponse_libbpf_destroy(void *);

