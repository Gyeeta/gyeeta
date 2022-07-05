
#pragma			once

#include 		<cstddef>
#include 		<functional>
#include 		<new>
#include 		<type_traits>
#include 		<utility>
#include		"gy_common_inc.h"

/*
 * Shamelessly lifted from folly/ScopeGuard.h so that folly dependency is removed
 */

namespace gyeeta {

class ScopeGuardImplBase {
public:
	void dismiss() noexcept {
		dismissed_ = true;
	}

	template <typename T>
		inline static void runAndWarnAboutToCrashOnException(
				T& function) noexcept {
			try {
				function();
			} catch (...) {
				ERRORPRINT("This program will now terminate because a ScopeGuard callback threw an exception...\n");
				std::terminate();
			}
		}

protected:
	ScopeGuardImplBase() noexcept : dismissed_(false) {}

	static ScopeGuardImplBase makeEmptyScopeGuard() noexcept {
		return ScopeGuardImplBase{};
	}

	template <typename T>
		static const T& asConst(const T& t) noexcept {
			return t;
		}

	bool dismissed_;

private:
	static void warnAboutToCrash() noexcept;
};

template <typename FunctionType>
class ScopeGuardImpl : public ScopeGuardImplBase {
public:
	explicit ScopeGuardImpl(FunctionType& fn) noexcept(
			std::is_nothrow_copy_constructible<FunctionType>::value)
		: ScopeGuardImpl(
				asConst(fn),
				makeFailsafe(std::is_nothrow_copy_constructible<FunctionType>{},
					&fn)) {}

	explicit ScopeGuardImpl(const FunctionType& fn) noexcept(
			std::is_nothrow_copy_constructible<FunctionType>::value)
		: ScopeGuardImpl(
				fn,
				makeFailsafe(std::is_nothrow_copy_constructible<FunctionType>{},
					&fn)) {}

	explicit ScopeGuardImpl(FunctionType&& fn) noexcept(
			std::is_nothrow_move_constructible<FunctionType>::value)
		: ScopeGuardImpl(
				std::move_if_noexcept(fn),
				makeFailsafe(std::is_nothrow_move_constructible<FunctionType>{},
					&fn)) {}

	ScopeGuardImpl(ScopeGuardImpl&& other) noexcept(
			std::is_nothrow_move_constructible<FunctionType>::value)
		: function_(std::move_if_noexcept(other.function_)) {
			// If the above line attempts a copy and the copy throws, other is
			// left owning the cleanup action and will execute it (or not) depending
			// on the value of other.dismissed_. The following lines only execute
			// if the move/copy succeeded, in which case *this assumes ownership of
			// the cleanup action and dismisses other.
			dismissed_ = other.dismissed_;
			other.dismissed_ = true;
		}

	~ScopeGuardImpl() noexcept {
		if (!dismissed_) {
			execute();
		}
	}

private:
	static ScopeGuardImplBase makeFailsafe(std::true_type, const void*) noexcept {
		return makeEmptyScopeGuard();
	}

	template <typename Fn>
		static auto makeFailsafe(std::false_type, Fn* fn) noexcept
		-> ScopeGuardImpl<decltype(std::ref(*fn))> {
			return ScopeGuardImpl<decltype(std::ref(*fn))>{std::ref(*fn)};
		}

	template <typename Fn>
		explicit ScopeGuardImpl(Fn&& fn, ScopeGuardImplBase&& failsafe)
		: ScopeGuardImplBase{}, function_(std::forward<Fn>(fn)) {
			failsafe.dismiss();
		}

	void* operator new(std::size_t) = delete;

	void execute() noexcept {
		runAndWarnAboutToCrashOnException(function_);
	}

	FunctionType function_;
};

template <typename F>
using ScopeGuardImplDecay = ScopeGuardImpl<typename std::decay<F>::type>;


/**
 * ScopeGuard is a general implementation of the "Initialization is
 * Resource Acquisition" idiom.  Basically, it guarantees that a function
 * is executed upon leaving the currrent scope unless otherwise told.
 *
 * The gy_make_guard() function is used to create a new ScopeGuard object.
 * It can be instantiated with a lambda function, a std::function<void()>,
 * a functor, or a void(*)() function pointer.
 *
 *
 * Usage example: Add a friend to memory if and only if it is also added
 * to the db.
 *
 * void User::addFriend(User& newFriend) {
 *   // add the friend to memory
 *   friends_.push_back(&newFriend);
 *
 *   // If the db insertion that follows fails, we should
 *   // remove it from memory.
 *   auto guard = gy_make_guard([&] { friends_.pop_back(); });
 *
 *   // this will throw an exception upon error, which
 *   // makes the ScopeGuard execute UserCont::pop_back()
 *   // once the Guard's destructor is called.
 *   db_->addFriend(GetName(), newFriend.GetName());
 *
 *   // an exception was not thrown, so don't execute
 *   // the Guard.
 *   guard.dismiss();
 * }
 *
 * Stolen from:
 *   Andrei's and Petru Marginean's CUJ article:
 *     http://drdobbs.com/184403758
 *   and the loki library:
 *     http://loki-lib.sourceforge.net/index.php?n=Idioms.ScopeGuardPointer
 *   and triendl.kj article:
 *     http://www.codeproject.com/KB/cpp/scope_guard.aspx
 */
template <typename F>
ScopeGuardImplDecay<F> gy_make_guard(F&& f) noexcept(
		noexcept(gyeeta::ScopeGuardImplDecay<F>(static_cast<F&&>(f)))) {
	return gyeeta::ScopeGuardImplDecay<F>(static_cast<F&&>(f));
}

/**
 * Internal use for the macro SCOPE_EXIT below
 */
enum class ScopeGuardOnExit {};

template <typename FunctionType>
	ScopeGuardImpl<typename std::decay<FunctionType>::type>
	operator+(ScopeGuardOnExit, FunctionType&& fn) {
		return ScopeGuardImpl<typename std::decay<FunctionType>::type>(
				std::forward<FunctionType>(fn));
	}

/*
 * XXX Please ensure that the scope exit handler does not throw unhandled exceptions
 * or else the program will abort (Note the noexcept)
 */ 
#define GY_SCOPE_EXIT \
	auto GY_ANONYMOUS_VARIABLE(SCOPE_EXIT_STATE) \
	= gyeeta::ScopeGuardOnExit() + [&]() noexcept

} // namespace gyeeta
