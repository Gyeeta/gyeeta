//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#include "gy_common_inc.h"

#include <iostream>

#include "folly/IntrusiveList.h"
#include "boost/intrusive/slist.hpp"
#include "boost/intrusive/list.hpp"

using namespace gyeeta;

// slist test
class MyNode : public boost::intrusive::slist_base_hook<boost::intrusive::cache_last<true>> 
{
public:
	MyNode(int value) : value(value) {}

	int getValue() const {
		return value;
	}

private:
	int value;
};

int test_slist() 
{
	// Create and insert nodes into the list
	MyNode node1(42);
	MyNode node2(17);
	MyNode node3(99);

	boost::intrusive::slist<MyNode, boost::intrusive::cache_last<true>> mySList;

	mySList.push_back(node1);
	mySList.push_back(node2);
	mySList.push_back(node3);

	// Iterate through the list
	for (const auto& node : mySList) {
		std::cout << "Value: " << node.getValue() << std::endl;
	}

	// Remove a node from the list
	mySList.erase(mySList.iterator_to(node2));

	std::cout << "After removing node2:" << std::endl;
	for (const auto& node : mySList) {
		std::cout << "Value: " << node.getValue() << std::endl;
	}

	return 0;
}

// Test with both base hook and member hook (16 + 16 bytes extra)
class MyClass : public boost::intrusive::list_base_hook<>   //This is a derivation hook
{
	int int_;

public:
	//This is a member hook
	boost::intrusive::list_member_hook<> member_hook_;

	MyClass(int i)
		:  int_(i)
	{}
};

//Define a list that will store MyClass using the public base hook
typedef boost::intrusive::list<MyClass>   BaseList;

//Define a list that will store MyClass using the public member hook
typedef boost::intrusive::list< MyClass , boost::intrusive::member_hook< MyClass, boost::intrusive::list_member_hook<>, &MyClass::member_hook_> > MemberList;

int test_list()
{
	typedef std::vector<MyClass>::iterator VectIt;

	//Create several MyClass objects, each one with a different value
	std::vector<MyClass> values;

	for(int i = 0; i < 100; ++i)  values.push_back(MyClass(i));

	BaseList baselist;
	MemberList memberlist;

	//Now insert them in the reverse order in the base hook list
	for(VectIt it(values.begin()), itend(values.end()); it != itend; ++it)
		baselist.push_front(*it);

	//Now insert them in the same order as in vector in the member hook list
	for(VectIt it(values.begin()), itend(values.end()); it != itend; ++it)
		memberlist.push_back(*it);

	//Now test lists
	{
		BaseList::reverse_iterator rbit(baselist.rbegin());
		MemberList::iterator mit(memberlist.begin());
		VectIt  it(values.begin()), itend(values.end());

		//Test the objects inserted in the base hook list
		for(; it != itend; ++it, ++rbit)
			if(&*rbit != &*it)   return 1;

		//Test the objects inserted in the member hook list
		for(it = values.begin(); it != itend; ++it, ++mit)
			if(&*mit != &*it)    return 1;
	}

	std::cout << "size(vector) = " << values.size() << " : size(baselist) = " << baselist.size() << " : size(memberlist) = " << memberlist.size() << "\n\n"; 

	return 0;
}


struct X
{
	static void operator delete(void* ptr, std::size_t sz)
	{
		std::cout << "custom delete for pointer " << ptr << " and size " << sz << '\n';
		// ::operator delete(ptr); do nothing
	}

	static void operator delete[](void* ptr, std::size_t sz)
	{
		std::cout << "custom delete [] for pointer " << ptr << " and size " << sz << '\n';
		// ::operator delete[](ptr); do nothing
	}

	int int_;

	folly::IntrusiveListHook listHook_;

	X(int i) : int_(i)
	{} 
};

struct Y
{
	static void operator delete(void* ptr, std::size_t sz)
	{
		std::cout << "custom Y delete for pointer " << ptr << " and size " << sz << '\n';
		::operator delete(ptr);
	}

	static void operator delete[](void* ptr, std::size_t sz)
	{
		std::cout << "custom Y delete [] for pointer " << ptr << " and size " << sz << '\n';
		::operator delete[](ptr);
	}

	int int_;

	folly::SafeIntrusiveListHook listHook_;

	Y(int i) : int_(i)
	{} 
};


int test_follylist()
{
	using FooList = folly::IntrusiveList<X, &X::listHook_>;
	using FooList2 = folly::CountedIntrusiveList<Y, &Y::listHook_>;

	X		x1(10), x2(11), x3(12);
	Y		y1(10), y2(11), y3(12);

	std::vector<std::unique_ptr<X>> myvec;
	FooList				mylist;
	FooList2			mylist2;

	myvec.emplace_back(&x1);
	myvec.emplace_back(&x2);
	myvec.emplace_back(&x3);

	mylist.push_back(x1);
	mylist.push_back(x2);
	mylist.push_back(x3);

	std::cout << "\n\nFolly IntrusiveList : ...\n";
	for (const auto& node : mylist) {
		std::cout << "Value: " << node.int_ << std::endl;
	}

	mylist.erase(mylist.iterator_to(x1));

	std::cout << "\n\nFolly IntrusiveList after erase : ...\n";
	for (const auto& node : mylist) {
		std::cout << "Value: " << node.int_ << std::endl;
	}

	mylist.erase(mylist.iterator_to(x2));
	mylist.erase(mylist.iterator_to(x3));

	std::cout << "\n\nFolly IntrusiveList after all erase : ...\n";
	for (const auto& node : mylist) {
		std::cout << "Value: " << node.int_ << std::endl;
	}

	auto foo = std::make_unique<Y>(1);

	mylist2.push_back(y1);
	mylist2.push_back(y2);
	mylist2.push_back(y3);
	mylist2.push_back(*foo.get());
	
	mylist2.pop_front();

	mylist2.erase(mylist2.iterator_to(*foo.get()));
	

	std::cout << "\n\nFolly CountedIntrusiveList size() = " << mylist2.size() << '\n';
	for (const auto& node : mylist2) {
		std::cout << "Value: " << node.int_ << std::endl;
	}

	return 0;
}	

int main()
{
	int ret1, ret2, ret3;

	ret1 = test_slist();

	ret2 = test_list();

	ret3 = test_follylist();

	return (ret1 || ret2 || ret3);
}	
