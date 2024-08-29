//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_print_offload.h"

namespace gyeeta {

class DataList
{
	public:

		DataList(int max_elem = 0x0FFFFFFFF, int print_after = 0);
		~DataList();
		int Init(int nelem, int elemsize, int nresize = 0);
		void* GetElementPtr(int index);
		int AddElement(void *databuf, int datalen);
		int AppendData(int index, int offset, void *databuf);
		int DeleteElement(int index, int reset = 0);
		int ResetElement(int index);
		int ResetList(void);
		int GetListSize(void);

	private:
		char *datalist;
		int *freelist;
		int elementsize;
		int nelements;
		int freelistsize;
		int nfreeelements;
		int nresizelem;
		const int max_elements, print_after_elem;
		int nprintskip;
		int ResizeList();
};


typedef struct _hash
{
	char *id;
	int val;
	struct _hash *next;
} Hash;

class Hashtbl
{
private:
	int keylen;
	int capacity;
	Hash *start;
	int   mult_member_count;
	int   count;

public:
	int (*fn)(char*, int len);	/*hashing function*/

	Hashtbl();
	Hashtbl(int keylen, int size);
	~Hashtbl();
	int add(char *id, int val);
	int update(char *id, int val);
	int remove(char *id);
	int search(char *id, int *val);
	void clear();
	void reset();
	int set(int keylen, int size);
	void sethashint();
	int iterate(int (*cb)(char*, int, void *param), void *param, int rmnode);
};


} // namespace gyeeta

