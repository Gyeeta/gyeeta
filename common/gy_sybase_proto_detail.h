//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_sybase_proto.h"
#include			"gy_proto_common.h"
#include			"gy_datalist_proto.h"

namespace gyeeta {

#define SYB_MAX_MULTIPLEX		8
#define SYB_MAX_BUF_SAVED_LEN		128

#define SYBTDS_SQLLISTSIZE     		8
#define SYBTDS_SQLSTMTLEN       	128
#define SYBTDS_CURNAMELEN       	32
#define SYBTDS_HASHTBLSIZE      	128
#define SYBTDS_DYNIDLEN			32

struct SYB_DYN_SQL_STATS_S 
{
	char			dyn_sql[SYBTDS_SQLSTMTLEN];
	uint32_t		dyn_prep_reqnum;
	uint32_t		dyn_prep_time_t;
	uint32_t		len;
};

/*
 * tran_type definitions :
 */
enum SYB_TRAN_TYPES_E 
{
	TYPE_SYB_LOGIN			= 1 << 0,
	TYPE_SYB_LANG_REQ		= 1 << 1,
	TYPE_SYB_DBRPC_RPC		= 1 << 2,
	TYPE_SYB_DSQL_PREPARE		= 1 << 3,
	TYPE_SYB_DSQL_EXEC		= 1 << 4,
	TYPE_SYB_DSQL_EXEC_IMMED	= 1 << 5,
	TYPE_SYB_DSQL_DEALLOC		= 1 << 6,
	TYPE_SYB_CURSOR_DECLARE		= 1 << 7,
	TYPE_SYB_CURSOR_CLOSE		= 1 << 7,
	TYPE_SYB_CURSOR_FETCH		= 1 << 8,
	TYPE_SYB_CURSOR_DELETE		= 1 << 9,
	TYPE_SYB_CURSOR_OPEN		= 1 << 10,
	TYPE_SYB_CURSOR_UPDATE		= 1 << 11,
	TYPE_SYB_CANCEL_QUERY		= 1 << 12,
	TYPE_SYB_BULK_INSERT		= 1 << 13,

	TYPE_SYB_MISC			= 1 << 30,

	/* TRANS_LOGOUT defined as 1 << 31 */
};

enum SYB_TRAN_MASK_E
{
	MASK_SYB_DBRPC			= 1 << 0,
	MASK_SYB_RPC			= 1 << 1,
	MASK_SYB_CANCEL_QUERY		= 1 << 2, 	
	MASK_SYB_CUR_DECLARE_PROC	= 1 << 3,
};

enum SYB_SESS_STATE_E 
{
	SYB_STATE_UNINIT		= 0,
	SYB_STATE_TDS_LOGIN_REQ,
	SYB_STATE_TDS_LOGIN_SPLIT_REQ,
	SYB_STATE_TDS_LOGIN_RESP,
	SYB_STATE_TDS_LOGIN_SPLIT_RESP,
	SYB_STATE_LOGIN_COMPLETE,
};


enum SYB_RESP_TYPE_E
{
	SYB_LOGIN_RESP			= 1,
	SYB_QUERY_RESP,
};


enum SYB_ENVCHANGE_TOKEN_TYPE_E
{
	SYB_ENVCHANGE_DB		= 0x01,
	SYB_ENVCHANGE_LANG		= 0x02,
	SYB_ENVCHANGE_CHARSET		= 0x03,
	SYB_ENVCHANGE_PKTSIZE		= 0x04,
};

enum SYB_CURSOR_STATE_E
{
	SYB_CUR_UNUSED			= 0x0,
	SYB_CUR_DECLARED		= 0x1,
	SYB_CUR_OPEN			= 0x2,
	SYB_CUR_CLOSED			= 0x4,
	SYB_CUR_RDONLY			= 0x8,
	SYB_CUR_UPDATABLE		= 0x10,
	SYB_CUR_ROWCOUNT		= 0x20,
	SYB_CUR_DEALLOC			= 0x40,
	SYB_CUR_SCROLLABLE		= 0x80,
	SYB_CUR_IMPLICIT		= 0x100,
	SYB_CUR_SENSITIVE		= 0x200,
	SYB_CUR_INSENSITIVE		= 0x400,
	SYB_CUR_SEMISENSITIVE		= 0x800,
	SYB_CUR_KEYSETDRIVEN		= 0x1000,
};


enum SYB_STATUS_BITS_E
{
	SYB_STATUS_NORMAL		= 0x00,
	SYB_STATUS_EOM			= 0x01,		/* End of Message (Last Packet) */
	SYB_STATUS_ATTNACK		= 0x02,
	SYB_STATUS_ATTN			= 0x04,
	SYB_STATUS_EVENT		= 0x08,
	SYB_STATUS_SEAL			= 0x10,		/* Buffer is encrypted */
	SYB_STATUS_ENCRYPT		= 0x20,		/* Buffer is encrypted CMDSEQ */
};


enum SYB_DONE_STATUS_E 
{
	SYB_DONE_FINAL			= 0x00,
	SYB_DONE_MORE			= 0x01,
	SYB_DONE_ERROR			= 0x02,
	SYB_DONE_INXACT			= 0x04,
	SYB_DONE_PROC			= 0x08,
	SYB_DONE_COUNT			= 0x10,
	SYB_DONE_ATTN			= 0x20,
	SYB_DONE_EVENT			= 0x40,
};


enum SYB_DATA_TYPE_DESC_E
{
	SYB_DATA_TYPE_NORMAL		= 0,	
	SYB_DATA_TYPE_TEXT		= (1 << 0),	
	SYB_DATA_TYPE_DECIMAL		= (1 << 1),	
	SYB_DATA_TYPE_BLOB		= (1 << 2),	
	SYB_DATA_TYPE_SIMPLE_LEN1	= (1 << 3), 
	SYB_DATA_TYPE_SIMPLE_LEN4	= (1 << 4), 
	SYB_DATA_TYPE_BIGDATE		= (1 << 5), 
};



struct SYB_DATATYPE_INFO_T
{
	const char			*pdatatype		{nullptr};
	uint32_t			maxlen			{0};
	uint8_t				type_flags		{0};
	uint8_t				is_nullable		{0};
	uint8_t				lenbytes		{0};
	const char 			*ptxt			{nullptr};			
};


struct SYB_COLFMT_T
{
	uint32_t			len;
	uint32_t			status;
	uint32_t			usertype;
	uint8_t				blob_classid;
	uint8_t				datatype;
	uint8_t				precision;
	uint8_t				scale;
};


struct SYB_ROWFMT_T
{
	SYB_COLFMT_T			*pcol;
	uint32_t			tokenlen;
	uint16_t			ncols;
	uint16_t			nblobs;
	uint16_t			ntxt;
	uint8_t				token;
#define SYB_ROWFMT_MAGIC		0xFF
	uint8_t				magic;
};



enum SYB_DATATYPE_E : uint8_t
{
	SYB_TDS_BINARY 			= 0x2D,
	SYB_TDS_BIT 			= 0x32,
	SYB_TDS_BLOB 			= 0x24,
	SYB_TDS_BOUNDARY 		= 0x68,
	SYB_TDS_CHAR 			= 0x2F,
	SYB_TDS_DATE 			= 0x31,
	SYB_TDS_DATEN 			= 0x7B,
	SYB_TDS_DATETIME 		= 0x3D,
	SYB_TDS_DATETIMEN 		= 0x6F,
	SYB_TDS_DECN 			= 0x6A,
	SYB_TDS_FLT4 			= 0x3B,
	SYB_TDS_FLT8 			= 0x3E,
	SYB_TDS_FLTN 			= 0x6D,
	SYB_TDS_IMAGE 			= 0x22,
	SYB_TDS_INT1 			= 0x30,
	SYB_TDS_INT2 			= 0x34,
	SYB_TDS_INT4 			= 0x38,
	SYB_TDS_INT8 			= 0xbf,
	SYB_TDS_INTERVAL 		= 0x2E,
	SYB_TDS_INTN 			= 0x26,
	SYB_TDS_LONGBINARY 		= 0xE1,
	SYB_TDS_LONGCHAR 		= 0xAF,
	SYB_TDS_MONEY 			= 0x3C,
	SYB_TDS_MONEYN 			= 0x6E,
	SYB_TDS_NUMN 			= 0x6C,
	SYB_TDS_SENSITIVITY 		= 0x67,
	SYB_TDS_SHORTDATE 		= 0x3A,
	SYB_TDS_SHORTMONEY 		= 0x7A,
	SYB_TDS_SINT1 			= 0xb0,
	SYB_TDS_TEXT 			= 0x23,
	SYB_TDS_TIME 			= 0x33,
	SYB_TDS_TIMEN 			= 0x93,
	SYB_TDS_UINT2 			= 0x41,
	SYB_TDS_UINT4 			= 0x42,
	SYB_TDS_UINT8 			= 0x43,
	SYB_TDS_UINTN 			= 0x44,
	SYB_TDS_UNITEXT 		= 0xae,
	SYB_TDS_VARBINARY 		= 0x25,
	SYB_TDS_VARCHAR 		= 0x27,
	SYB_TDS_VOID 			= 0x1f,
	SYB_TDS_XML 			= 0xA3,
	SYB_TDS_BIGDATETIMEN		= 0xBB,
	SYB_TDS_BIGTIMEN		= 0xBC,
};

struct SYB_DATA_COL_PTR_T
{
	SYB_ROWFMT_T			*pcurrrowfmt;
	SYB_COLFMT_T			*pcol;
	uint32_t			blob_bytes_to_skip;
	uint16_t			ncols;
	uint16_t			currcol;
	uint16_t			ntimes;
	uint8_t				bytebuf[4];
	uint8_t				lenbytes;
	uint8_t				lenbytes_pending;
	uint8_t				parsept;
	uint8_t				labelpt;
};


enum SYB_CAPREQ_E
{
	SYB_CAPREQ_NONE, 
	SYB_CAPREQ_REQ_LANG, 
	SYB_CAPREQ_REQ_RPC, 
	SYB_CAPREQ_REQ_EVT, 
	SYB_CAPREQ_REQ_MSTMT, 
	SYB_CAPREQ_REQ_BCP, 
	SYB_CAPREQ_REQ_CURSOR, 
	SYB_CAPREQ_REQ_DYNF, 
	SYB_CAPREQ_REQ_MSG, 
	SYB_CAPREQ_REQ_PARAM, 
	SYB_CAPREQ_DATA_INT1, 
	SYB_CAPREQ_DATA_INT2, 
	SYB_CAPREQ_DATA_INT4, 
	SYB_CAPREQ_DATA_BIT, 
	SYB_CAPREQ_DATA_CHAR, 
	SYB_CAPREQ_DATA_VCHAR, 
	SYB_CAPREQ_DATA_BIN, 
	SYB_CAPREQ_DATA_VBIN, 
	SYB_CAPREQ_DATA_MNY8, 
	SYB_CAPREQ_DATA_MNY4, 
	SYB_CAPREQ_DATA_DATE8, 
	SYB_CAPREQ_DATA_DATE4, 
	SYB_CAPREQ_DATA_FLT4, 
	SYB_CAPREQ_DATA_FLT8, 
	SYB_CAPREQ_DATA_NUM, 
	SYB_CAPREQ_DATA_TEXT, 
	SYB_CAPREQ_DATA_IMAGE, 
	SYB_CAPREQ_DATA_DEC, 
	SYB_CAPREQ_DATA_LCHAR, 
	SYB_CAPREQ_DATA_LBIN, 
	SYB_CAPREQ_DATA_INTN, 
	SYB_CAPREQ_DATA_DATETIMEN, 
	SYB_CAPREQ_DATA_MONEYN, 
	SYB_CAPREQ_CSR_PREV, 
	SYB_CAPREQ_CSR_FIRST, 
	SYB_CAPREQ_CSR_LAST, 
	SYB_CAPREQ_CSR_ABS, 
	SYB_CAPREQ_CSR_REL, 
	SYB_CAPREQ_CSR_MULTI, 
	SYB_CAPREQ_CON_OOB, 
	SYB_CAPREQ_CON_INBAND, 
	SYB_CAPREQ_CON_LOGICAL, 
	SYB_CAPREQ_PROTO_TEXT, 
	SYB_CAPREQ_PROTO_BULK, 
	SYB_CAPREQ_REQ_URGEVT, 
	SYB_CAPREQ_DATA_SENSITIVITY, 
	SYB_CAPREQ_DATA_BOUNDARY, 
	SYB_CAPREQ_PROTO_DYNAMIC, 
	SYB_CAPREQ_PROTO_DYNPROC, 
	SYB_CAPREQ_DATA_FLTN, 
	SYB_CAPREQ_DATA_BITN, 
	SYB_CAPREQ_DATA_INT8, 
	SYB_CAPREQ_DATA_VOID, 
	SYB_CAPREQ_DOL_BULK, 
	SYB_CAPREQ_OBJECT_JAVA1, 
	SYB_CAPREQ_OBJECT_CHAR, 
	SYB_CAPREQ_REQ_RESERVED1, 
	SYB_CAPREQ_OBJECT_BINARY, 
	SYB_CAPREQ_DATA_COLUMNSTATUS, 
	SYB_CAPREQ_WIDETABLE, 
	SYB_CAPREQ_REQ_RESERVED2, 
	SYB_CAPREQ_DATA_UINT2, 
	SYB_CAPREQ_DATA_UINT4, 
	SYB_CAPREQ_DATA_UINT8, 
	SYB_CAPREQ_DATA_UINTN, 
	SYB_CAPREQ_CUR_IMPLICIT, 
	SYB_CAPREQ_DATA_NLBIN, 
	SYB_CAPREQ_IMAGE_NCHAR, 
	SYB_CAPREQ_BLOB_NCHAR_16, 
	SYB_CAPREQ_BLOB_NCHAR_8, 
	SYB_CAPREQ_BLOB_NCHAR_SCSU, 
	SYB_CAPREQ_DATA_DATE, 
	SYB_CAPREQ_DATA_TIME, 
	SYB_CAPREQ_DATA_INTERVAL, 
	SYB_CAPREQ_CSR_SCROLL, 
	SYB_CAPREQ_CSR_SENSITIVE, 
	SYB_CAPREQ_CSR_INSENSITIVE, 
	SYB_CAPREQ_CSR_SEMISENSITIVE, 
	SYB_CAPREQ_CSR_KEYSETDRIVEN, 
	SYB_CAPREQ_REQ_SRVPKTSIZE, 
	SYB_CAPREQ_DATA_UNITEXT, 
	SYB_CAPREQ_CAP_CLUSTERFAILOVER, 
	SYB_CAPREQ_DATA_SINT1, 
	SYB_CAPREQ_REQ_LARGEIDENT, 
	SYB_CAPREQ_REQ_BLOB_NCHAR_16, 
	SYB_CAPREQ_DATA_XML, 
	SYB_CAPREQ_REQ_CURINFO3, 
	SYB_CAPREQ_REQ_DBRPC2, 
	SYB_CAPREQ_REQ_UNUSED1, 
	SYB_CAPREQ_REQ_MIGRATE, 
	SYB_CAPREQ_MULTI_REQUESTS, 
	SYB_CAPREQ_REQ_UNUSED2, 
	SYB_CAPREQ_REQ_UNUSED3, 
	SYB_CAPREQ_DATA_BIGDATETIME, 
	SYB_CAPREQ_DATA_USECS, 
	SYB_CAPREQ_RPCPARAM_LOB, 
	SYB_CAPREQ_REQ_INSTID, 
	SYB_CAPREQ_REQ_GRID, 
	SYB_CAPREQ_REQ_DYN_BATCH, 
	SYB_CAPREQ_REQ_LANG_BATCH, 
	SYB_CAPREQ_REQ_RPC_BATCH, 
	SYB_CAPREQ_DATA_LOBLOCATOR, 
	SYB_CAPREQ_REQ_UNUSED4, 
	SYB_CAPREQ_REQ_UNUSED5,
};


enum SYB_CAPRESP_E : uint8_t
{
	SYB_CAPRESP_NONE, 
	SYB_CAPRESP_RES_NOMSG, 
	SYB_CAPRESP_RES_NOEED, 
	SYB_CAPRESP_RES_NOPARAM, 
	SYB_CAPRESP_DATA_NOINT1, 
	SYB_CAPRESP_DATA_NOINT2, 
	SYB_CAPRESP_DATA_NOINT4, 
	SYB_CAPRESP_DATA_NOBIT, 
	SYB_CAPRESP_DATA_NOCHAR, 
	SYB_CAPRESP_DATA_NOVCHAR, 
	SYB_CAPRESP_DATA_NOBIN, 
	SYB_CAPRESP_DATA_NOVBIN, 
	SYB_CAPRESP_DATA_NOMNY8, 
	SYB_CAPRESP_DATA_NOMNY4, 
	SYB_CAPRESP_DATA_NODATE8, 
	SYB_CAPRESP_DATA_NODATE4, 
	SYB_CAPRESP_DATA_NOFLT4, 
	SYB_CAPRESP_DATA_NOFLT8, 
	SYB_CAPRESP_DATA_NONUM, 
	SYB_CAPRESP_DATA_NOTEXT, 
	SYB_CAPRESP_DATA_NOIMAGE, 
	SYB_CAPRESP_DATA_NODEC, 
	SYB_CAPRESP_DATA_NOLCHAR, 
	SYB_CAPRESP_DATA_NOLBIN, 
	SYB_CAPRESP_DATA_NOINTN, 
	SYB_CAPRESP_DATA_NODATETIMEN, 
	SYB_CAPRESP_DATA_NOMONEYN, 
	SYB_CAPRESP_CON_NOOOB, 
	SYB_CAPRESP_CON_NOINBAND, 
	SYB_CAPRESP_PROTO_NOTEXT, 
	SYB_CAPRESP_PROTO_NOBULK, 
	SYB_CAPRESP_DATA_NOSENSITIVITY, 
	SYB_CAPRESP_DATA_NOBOUNDARY, 
	SYB_CAPRESP_RES_NOTDSDEBUG, 
	SYB_CAPRESP_RES_NOSTRIPBLANKS, 
	SYB_CAPRESP_DATA_NOINT8, 
	SYB_CAPRESP_OBJECT_NOJAVA1, 
	SYB_CAPRESP_OBJECT_NOCHAR, 
	SYB_CAPRESP_DATA_NOCOLUMNSTATUS, 
	SYB_CAPRESP_OBJECT_NOBINARY, 
	SYB_CAPRESP_RES_RESERVED1, 
	SYB_CAPRESP_DATA_NOUINT2, 
	SYB_CAPRESP_DATA_NOUINT4, 
	SYB_CAPRESP_DATA_NOUINT8, 
	SYB_CAPRESP_DATA_NOUINTN, 
	SYB_CAPRESP_NO_WIDETABLES, 
	SYB_CAPRESP_DATA_NONLBIN, 
	SYB_CAPRESP_IMAGE_NONCHAR, 
	SYB_CAPRESP_BLOB_NONCHAR_16, 
	SYB_CAPRESP_BLOB_NONCHAR_8, 
	SYB_CAPRESP_BLOB_NONCHAR_SCSU, 
	SYB_CAPRESP_DATA_NODATE, 
	SYB_CAPRESP_DATA_NOTIME, 
	SYB_CAPRESP_DATA_NOINTERVAL, 
	SYB_CAPRESP_DATA_NOUNITEXT, 
	SYB_CAPRESP_DATA_NOSINT1, 
	SYB_CAPRESP_RES_NOLARGEIDENT, 
	SYB_CAPRESP_RES_NOBLOB_NCHAR_16, 
	SYB_CAPRESP_NO_SRVPKTSIZE, 
	SYB_CAPRESP_RES_NODATA_XML, 
	SYB_CAPRESP_NONINT_RETURN_VALUE, 
	SYB_CAPRESP_RES_NOXNLDATA, 
	SYB_CAPRESP_RES_SUPPRESS_FMT, 
	SYB_CAPRESP_RES_SUPPRESS_DONEINPROC, 
	SYB_CAPRESP_RES_FORCE_ROWFMT2, 
	SYB_CAPRESP_DATA_NOBIGDATETIME, 
	SYB_CAPRESP_DATA_NOUSECS, 
	SYB_CAPRESP_RES_NO_TDSCONTROL, 
	SYB_CAPRESP_RPCPARAM_NOLOB, 
	SYB_CAPRESP_RES_UNUSED1, 
	SYB_CAPRESP_DATA_NOLOBLOCATOR, 
	SYB_CAPRESP_RES_UNUSED2, 
};


struct SYB_IW_CURSOR_LOOKUP_T
{
	SYB_ROWFMT_T		*pcurrparamfmt;
	uint32_t		dyn_prep_reqnum;
	uint32_t		dyn_prep_time_t;

	uint16_t		pcapcurstate;
	uint16_t		len;
	char			cursortext[SYBTDS_SQLSTMTLEN];
	char			cursorname[SYBTDS_CURNAMELEN];
};


#define SYB_MAX_CURSORS		1024

struct SYB_TRAN_EXTSTAT
{
	STRING_BUFFER<MAX_USER_DB_LEN>	userbuf_;
	STRING_BUFFER<MAX_USER_DB_LEN>	appbuf_;
	STRING_BUFFER<MAX_USER_DB_LEN>	dbbuf_;
	STRING_BUFFER<256>		errorbuf_;

	uint64_t			reqnum_				{0};
	uint64_t			last_upd_tusec_			{0};
	uint64_t			dyn_prep_reqnum_		{0};
	time_t				dyn_prep_time_t_		{0};
	int				spid_				{0};
	int				hostpid_			{0};
	uint8_t				errclass_			{0};
	bool				is_serv_err_			{false};

	void reset_on_req() noexcept
	{
		errorbuf_.reset();
		dyn_prep_reqnum_ = 0;
		dyn_prep_time_t_ = 0;
		errclass_ = 0;
		is_serv_err_ = false;
	}
};	

struct SYBASE_IW_PROTOSTAT_T
{
	uint64_t		nbytes_cur_req;
	uint64_t		nbytes_pcap_resp;
	uint32_t 		fragresp_len;
	uint32_t		max_token_buf_len;
	uint32_t		token_curr_len;
	uint32_t		token_pending_len;
	uint32_t		skip_token_resp;
	uint32_t		skip_token_req;
	uint32_t		skip_request_text;
	uint32_t		frag_req_nleft;
	uint32_t		frag_req_nparsed;	
	uint32_t		frag_resp_nleft;
	uint32_t		frag_resp_nparsed;	
	uint32_t		max_multi_tds_len;
	uint32_t		curr_multi_tds_len;
	uint32_t		ncurrcursor;
	uint32_t		pcap_server_version;
	SYB_RESP_TYPE_E         pcap_resp_type_expected[SYB_MAX_MULTIPLEX];
	DirPacket		last_dir;
	SYB_DATA_COL_PTR_T	data_col_ptr;
	SYB_SESS_STATE_E	pcap_sess_state;
	uint8_t 		pcap_req_frag;
	uint8_t 		pcap_resp_frag;
	uint8_t			ign_req_frag;
	uint8_t			ign_resp_frag;
	uint8_t			skip_till_nextreq;
	uint8_t			skip_till_login_rsp;
	uint8_t			drop_handled;
	uint8_t			skip_to_req_after_resp;
	uint8_t			npcap_response_pending;
	uint8_t			cursor_query_active;
	uint8_t			curr_pcap_cursors_pending;
	uint8_t			pcap_attn_ack_expected; 
	uint8_t			skip_pcap_req_till_eom; 
	uint8_t			skip_pcap_resp_till_eom; 
	uint8_t			cli_tds_version;
	uint8_t			pcap_buf_saved[SYB_MAX_BUF_SAVED_LEN];
	uint8_t			pcap_buf_saved_len;
	uint8_t			is_data_col_ptr_valid;
	uint8_t			param_req_pending;
	uint8_t			curinfo_tokenlen_bug;
	uint8_t			is_login_complete;
	uint8_t			chk_for_tds_byteorder;
	BYTE_ORDER_E		orig_client_bo;
	uint8_t			drop_seen;
	uint8_t			drop_req_seen;
	uint8_t			drop_resp_seen;
	uint8_t			to_flush_req;
	char			cursortext[SYBTDS_SQLSTMTLEN];
};

class SVC_INFO_CAP;

class SYBASE_ASE_SESSINFO : public SYBASE_ASE_PROTO
{
public :
	enum SYB_STATS_E : uint8_t
	{
		STATSYB_NEW_SESS		= 0,
		STATSYB_SESS_COMPLETE,
		STATSYB_MIDWAY_SESS,
		STATSYB_SSL_SESS,
		
		STATSYB_CURSOR_FIND_SUCCESS,
		STATSYB_CURSOR_FIND_FAIL,
		STATSYB_CURSOR_ADDED,
		STATSYB_CURSOR_ADD_FAIL,
		STATSYB_CURSOR_DEALLOC,

		STATSYB_DYN_ADDED,
		STATSYB_DYN_FIND_SUCCESS,
		STATSYB_DYN_FIND_FAIL,

		STATSYB_BLOB_DATA,
		STATSYB_LOB_LOCATOR_DATA,
		STATSYB_UNPARSED_REQ,
		STATSYB_UNHANDLED_REQ_TOKEN,
		STATSYB_CANCEL_QUERY,
		
		STATSYB_REQ_PKT_SKIP,
		STATSYB_RESP_PKT_SKIP,

		STATSYB_MAX,
	};	

	static inline constexpr const char *	gstatstr[STATSYB_MAX] =
	{
		"New Session", "Session Completed", "Midway Session", "SSL Session", 
		"Cursor Find Success", "Cursor Find Failed", "Cursor Added", "Cursor Add Failed", "Cursor Dealloc",
		"Dyn Stmt Added", "Dyn Stmt Found", "Dyn Stmt Not Found",
		"Blob Data", "Lob Locator Data", "Unparsed Request", "Unhandled Req Token", "Cancel Query",
		"Request Packets Skipped", "Response Packets Skipped",
	};	

	static inline uint64_t		gstats[STATSYB_MAX]		{};
	static inline uint64_t		gstats_old[STATSYB_MAX]		{};
	static inline uint64_t		gtotal_queries = 0, glast_queries = 0, gtotal_resp = 0, glast_resp = 0;


	SYBASE_IW_PROTOSTAT_T		sybstat_;
	API_TRAN			tran_;
	STRING_HEAP			tdstrbuf_;
	SYB_TRAN_EXTSTAT		tdstat_;

	SVC_SESSION 			& svcsess_;
	SVC_INFO_CAP			*psvc_				{nullptr};

	DataList 			*pCurList			{nullptr};
	uint8_t				*pReqFragBuf			{nullptr};
	uint8_t				*pResFragBuf			{nullptr};
	uint8_t				*pTokenBuf			{nullptr};
	uint8_t				*pMultiTDSBuf			{nullptr};
	SYB_IW_CURSOR_LOOKUP_T 		*pCurrCursor			{nullptr};
	Hashtbl 			*pCurIDLookupMap		{nullptr};
	Hashtbl 			*pDynStmtMap			{nullptr};
	DataList 			*pDynStmt			{nullptr};
	SYB_ROWFMT_T 			*pCurrParamFmt			{nullptr};
	char 				curname[SYBTDS_CURNAMELEN]	{};

	uint8_t				part_query_started_		{0};

	static constexpr size_t		SYB_FRAGBUFLEN			{65536};
	
	SYBASE_ASE_SESSINFO(SYBASE_ASE_PROTO & prot, SVC_SESSION & svcsess);

	~SYBASE_ASE_SESSINFO() noexcept;

	int handle_request_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	int handle_response_pkt(PARSE_PKT_HDR & hdr, uint8_t *pdata);
	void handle_session_end(PARSE_PKT_HDR & hdr);
	void handle_ssl_change(PARSE_PKT_HDR & hdr, uint8_t *pdata);

	void new_request(uint64_t tupd_usec) noexcept;
	void new_request() noexcept;
	void request_text_set(const char *request, int reqlen = 0, int chk_append = 0);
	void request_done();
	void handle_error(const char *errortext, size_t error_text_len, int error_code, uint8_t errclass);
	void set_session_pid(int pid);
	int handle_prev_req_frag(uint8_t *sptr, uint32_t ppkt_len, uint32_t *pbytes_left);
	int handle_prev_resp_frag(uint8_t *sptr, uint32_t ppkt_len, uint32_t *pbytes_left);
	void reset_req_flags();
	void set_resp_type_expected(SYB_RESP_TYPE_E resptype);
	void reset_resp_type_expected();
	void attention_reset_resp_type_expected();
	int find_pcap_cursor(uint32_t cursor);
	int add_cursor(uint32_t cursor, uint32_t status);
	int close_cursor(uint32_t cursor);
	void deallocate_cursor(SYB_IW_CURSOR_LOOKUP_T *pcursor);
	int handle_done_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_doneinproc_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_doneproc_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_loginack_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_capability_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_info_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_error_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int test_extended_error_token_resp(uint8_t *sptr, uint16_t len);
	int handle_extended_error_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_envchange_token_resp(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_curinfo_resp_tokens(uint8_t *sptr, uint16_t len, uint16_t *ptokenlen, int handle_frag);
	int handle_language_req_token(uint8_t *sptr, uint16_t len, uint32_t *ptokenlen, int handle_frag);
	int handle_dbrpc_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, int handle_frag);
	int store_dyn_txt(uint8_t *pid, uint8_t idlen, uint8_t *pstmt, uint32_t slen);
	void get_dyn_text(uint8_t *pid, uint8_t idlen, uint8_t dealloc, char *pdyntext = nullptr, uint32_t max_dyn_len = 0);
	int handle_dyn_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, int handle_frag);
	int handle_curdeclare_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, int handle_frag);
	void parse_date_time(uint32_t dateint, uint32_t timeint, uint64_t usecll, int type);
	void parse_intn(uint8_t *ptmp, uint8_t len, int is_signed);
	void parse_moneyn(uint8_t *ptmp, uint8_t len);
	int parse_fltn(uint8_t *ptmp, uint8_t len);
	int handle_param_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, DirPacket dir, SYB_DATA_COL_PTR_T *psybdataptr, int handle_frag);
	int handle_paramfmt_token(uint8_t *sptr, uint16_t len, uint8_t token, uint32_t *ptokenlen, DirPacket dir, int handle_frag);
	int chk_for_resp_errors(uint8_t *sptrin, uint16_t len);
	int handle_server_response(uint8_t *sptr, uint16_t len, int fresh_resp, int is_eom);
	int handle_unparsed_req(uint8_t *sptr, uint16_t tdstype, uint16_t len, int fresh_req, int is_eom);
	int handle_tds_normal_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom);
	int handle_attention_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom);
	int handle_bulk_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom);
	int handle_rpc_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom);
	int handle_lang_req(uint8_t *sptr, uint16_t len, int fresh_req, int is_eom);
	int handle_login_req(uint8_t *sptr, uint16_t len, int fresh_req);
	int handle_login_response(uint8_t *sptr, uint16_t len);
	int handle_pcap_tds_req(uint8_t *sptr, int is_frag_buf, uint16_t ntds, PARSE_PKT_HDR & hdr);
	int handle_pcap_tds_resp(uint8_t *sptr, int is_frag_buf, uint16_t ntds, PARSE_PKT_HDR & hdr);
	int is_tds_of_interest(uint8_t tdstype, DirPacket dir);
	int handle_drop_req_pkt(uint8_t *sptr, uint16_t ppkt_len);
	int handle_drop_pcap_resp_eom(uint8_t *sptr, uint16_t ppkt_len);
	int handle_drop_resp_pkt(uint8_t *sptr, uint16_t ppkt_len);
	bool print_req() noexcept;
		

	void print_partial_req()
	{
		// TODO
	}

	void set_partial_req()
	{
		// TODO
	}	

	void drop_partial_req()
	{
		// TODO
	}	

	static void print_stats(STR_WR_BUF & strbuf, time_t tcur, time_t tlast) noexcept;

	static bool syb_is_cursor_token(uint8_t c)
	{
		switch (c) {										

		case SYB_TOKEN_CURDECLARE :
		case SYB_TOKEN_CURDECLARE2 :
		case SYB_TOKEN_CURDECLARE3 :
		case SYB_TOKEN_CURCLOSE :
		case SYB_TOKEN_CUROPEN :
		case SYB_TOKEN_CURFETCH :
		case SYB_TOKEN_CURDELETE :
		case SYB_TOKEN_CURINFO :
		case SYB_TOKEN_CURINFO2 :
		case SYB_TOKEN_CURINFO3 :
		case SYB_TOKEN_CURUPDATE :
			
			return true;

		default :
			return false;
		}
	}
	
};



} // namespace gyeeta


