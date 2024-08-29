//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include			"gy_datalist_proto.h"

namespace gyeeta {

DataList :: DataList(int max_elem, int print_after) : max_elements(max_elem), print_after_elem(print_after), nprintskip(0)
{
	datalist = nullptr;
	freelist = nullptr;
	nfreeelements = freelistsize = 0;
	elementsize = nelements = 0;
	nresizelem = 0;
}


int DataList :: Init(int nelem, int elemsize, int nresize)
{
	if ((nelem <= 1) || (elemsize <= 0) || (nelem < nresize))
		return -1;

	char *tmp = datalist;

	if (datalist == nullptr) {

		datalist = (char *)malloc(nelem * elemsize);
		if (datalist == nullptr) {
			DEBUGEXECN(1, PERRORPRINT_OFFLOAD("malloc failed in datalist"););

			if (freelist) {
				free(freelist);
				freelist = nullptr;
			}
			return -1;
		}	
	}	
	else if ((datalist = (char *)realloc(tmp, (nelem * elemsize))) == nullptr)
	{
		DEBUGEXECN(1, PERRORPRINT_OFFLOAD("realloc failed in datalist"););
		if (tmp)
			free(tmp);

		if (freelist) {
			free(freelist);
			freelist = nullptr;
		}
		return -1;
	}

	if (freelist == nullptr)
	{
		if ((freelist = (int *)calloc(nelem, sizeof(int))) == nullptr)
		{
			DEBUGEXECN(1, PERRORPRINT_OFFLOAD("calloc failed in datalist"););
			if (datalist)
			{
				free(datalist);
				datalist = nullptr;
			}
			return -1;
		}

		nresizelem = (nresize == 0)? (nelem / 2) : nresize;

		freelistsize = nelem;
		elementsize = elemsize;
	}

	for (int i = nelements; i < nelem; i++)
		freelist[nfreeelements++] = i;

	nelements = nelem;
	return 0;
}


DataList :: ~DataList()
{
	if (datalist)
		free(datalist);

	if (freelist)
		free(freelist);
}


int DataList :: GetListSize(void)
{
	return nelements;
}


void* DataList :: GetElementPtr(int index)
{
	if ((datalist == nullptr) || (index >= nelements) || (index < 0))
		return nullptr;

	return (void *)(datalist + (index * elementsize));
}


int DataList :: AddElement(void *databuf, int datalen)
{
	if ((datalist == nullptr) || (freelist == nullptr) || (databuf == nullptr) || (datalen > elementsize))
		return -1;

	if (nfreeelements <= 0)
	{
		if (ResizeList() == -1)
			return -1;
	}

	int index = freelist[--nfreeelements];
	memset((datalist + (index * elementsize)), 0, elementsize);
	memcpy((datalist + (index * elementsize)), databuf, datalen);
	return index;
}


int DataList :: AppendData(int index, int offset, void *databuf)
{
	if ((datalist == nullptr) || (databuf == nullptr) || (index >= nelements) || (index < 0) || (offset >= elementsize))
		return -1;

	char *dataptr = (datalist + (index * elementsize));

	if (dataptr == nullptr)
		return -1;

	strncpy((dataptr + offset), (char *)databuf, (elementsize - offset - 1));

	return 0;
}


int DataList :: DeleteElement(int index, int reset)
{
	if ((freelist == nullptr) || (index >= nelements) || (index < 0))
		return -1;

	if (nfreeelements >= freelistsize)
	{
		int *tmplist = freelist;
		if ((freelist = (int *)realloc(tmplist, ((freelistsize + nresizelem) * sizeof(int)))) == nullptr)
		{
			DEBUGEXECN(1, PERRORPRINT_OFFLOAD("realloc failed in datalist"););
			if (tmplist)
				free(tmplist);

			if (datalist)
			{
				free(datalist);
				datalist = nullptr;
			}
			return -1;
		}
		freelistsize += nresizelem;
	}

	freelist[nfreeelements++] = index;

	if (reset)
		return ResetElement(index);

	return 0;
}


int DataList :: ResetElement(int index)
{
	if ((datalist == nullptr) || (index >= nelements) || (index < 0))
		return -1;

	memset((datalist + (index * elementsize)), 0, elementsize);
	return 0;
}


int DataList :: ResetList(void)
{
	if ((datalist == nullptr) || (freelist == nullptr) || (nelements > freelistsize))
		return -1;

	memset(datalist, 0, (nelements * elementsize));
	memset(freelist, 0, (freelistsize * sizeof(int)));

	nfreeelements = 0;
	for (int i = 0; i < nelements; i++)
		freelist[nfreeelements++] = i;

	return 0;
}


int DataList :: ResizeList(void)
{
	if (nelements + nresizelem > max_elements) {
		if ((print_after_elem > 0) && (print_after_elem < nelements + nresizelem)) {
			if (0 == nprintskip % print_after_elem) {
				DEBUGEXECN(5, 
					INFOPRINT_OFFLOAD("DataList 0x%p skipping resize as max elems %d reached : Total Skips so far %d...\n", this, max_elements, nprintskip++);
				);
			}
		}	
		return -1;
	}	
	else if (print_after_elem && (nelements + nresizelem > print_after_elem)) {
		DEBUGEXECN(5, 
			INFOPRINT_OFFLOAD("DataList 0x%p resizing to %d as max elems %d reached...\n", this, nelements + nresizelem, nelements);
		);	
	}	
	return Init(nelements + nresizelem, elementsize);
}

static int hash(char *id, int len)
{
	int sum=0, i=0;
	char c;
	int mult[]={257, 123, 61, 31, 17, 11};

	while(i<6 && (c=*id++))
	{
		sum += mult[i++]*((int)c - 64);
	}

	if(c!=0)
	{
		while(i++<len && (c=*id++)) sum += (int)c;
	}
	if(sum<0) sum = -sum;
	return sum;
}

static int hashint(char *id, int len)
{
	int sum;
	int *p=&sum;

	memcpy(p, id, sizeof(int));
	if(sum<0) sum = -sum;
	return sum;
}

void Hashtbl::clear()
{
	int k=0;
	Hash *h, *h1, *h2;

	if(start==nullptr) return;

	h1 = h = start;

	while(k++<capacity)
	{
		if(h->val>=0)	/* val = -1 means next ptr is unassigned */
		{
			delete[] h->id;
			h1=h->next;
			while((h2=h1))
			{
				h1=h1->next;
				delete[] h2->id;
				delete h2;
			}
			h->val=-1;
		}
		++h;
	}
}

void Hashtbl::reset()
{
	if(start)
	{
		clear();

		delete[] start;
		start=nullptr;
	}
}

Hashtbl::~Hashtbl()
{
	reset();
	if(start!=nullptr) delete[] start;
}

Hashtbl::Hashtbl()
{
	start=nullptr;
	mult_member_count=0;
	count=0;
}

Hashtbl::Hashtbl(int keylength, int size)
{
	start=nullptr;
	set(keylength, size);
	mult_member_count=0;
	count=0;
}

int Hashtbl::set(int keylength, int size)
{
	int i;
	Hash *node;

	reset();
	if(size<1) return 0;

	capacity=size;
	keylen=keylength;

	fn = hash;
	start = new Hash[capacity];
	for(i=0, node=start;i<capacity;i++, node++)
	{
		node->val=-1;
	}
	return 1;
}

int Hashtbl::add(char *id, int val)
{
	int k;
	Hash *h;

	k=(*fn)(id, keylen) % capacity;

	h = start + k;

	if(h->val==-1)
	{
		h->next = nullptr;
	}
	else
	{
		Hash *newh = new Hash;
		newh->next = h->next;
		h->next=newh;
		h = newh;
		mult_member_count++;
	}
	h->id=new char[keylen];
	memcpy(h->id, id, keylen);
	h->val = val;

	count++;

	return 1;
}

int Hashtbl::search(char *id, int *val)
{
	int k;
	Hash *h;
	int len=keylen;

	k=(*fn)(id, keylen) % capacity;
	h = start + k;

	if(h->val==-1) return 0;

	while(h != nullptr)
	{
		if (h->id && (memcmp(id, h->id, len)==0))
		{
			*val = h->val;
			return 1;
		}
		h = h->next;
	}

	return 0;
}

void Hashtbl::sethashint()
{
	fn=hashint;
}

int Hashtbl::update(char *id, int val)
{
	int k;
	Hash *h;
	int len=keylen;

	k=(*fn)(id, keylen) % capacity;
	h = start + k;

	if(h->val==-1) return 0;

	while(h != nullptr)
	{
		if(memcmp(id, h->id, len)==0)
		{
			h->val=val;
			return 1;
		}
		h = h->next;
	}

	return 0;
}

int Hashtbl::remove(char *id)
{
	int k;
	Hash *h, *h1, *h2 = nullptr;
	int len=keylen;

	k=(*fn)(id, keylen) % capacity;
	h1 = h = start + k;

	if(h->val==-1) return 0;

	while(h != nullptr)
	{
		if(memcmp(id, h->id, len)==0)
		{
			if(h1 == h)
			{
				delete[] h->id;
				h->id=nullptr;

				if((h1=h->next))
				{
					h->val=h1->val;
					h->next=h1->next;
					h->id=h1->id;
					delete h1;
				}
				else
					h->val=-1;
			}
			else
			{
				h2->next=h->next;
				delete[] h->id;
				delete h;
			}
			return 1;
		}
		h2=h;
		h = h->next;
	}

	return 0;
}

int Hashtbl::iterate(int (*cb)(char*, int, void *param), void *param, int rmnode)
{
	int k=0;
	Hash *h, *h1, *h2;

	if(start==nullptr) return 0;

	h1 = h = start;

	while(k++<capacity)
	{
		if(h->val>=0)	/* val = -1 means next ptr is unassigned */
		{
			if(cb(h->id, h->val, param)) return -1;

			if(rmnode) delete[] h->id;

			h1=h->next;
			while((h2=h1))
			{
				h1=h1->next;

				if(cb(h2->id, h2->val, param)) return -1;
				if(rmnode)
				{
					delete[] h2->id;
					delete h2;
				}
			}
			if(rmnode) h->val=-1;
		}
		++h;
	}
	return 0;
}

} // namespace gyeeta

