#pragma once

#include <folly/Conv.h>
#include <folly/ScopeGuard.h>

namespace folly {

namespace detail {

template <typename T, typename BucketT, class GetIdxFromVal>
class SlabHistogramBuckets {
 public:
  typedef T ValueType;
  typedef BucketT BucketType;
  typedef GetIdxFromVal hasher;

  /*
   * Create a set of histogram buckets.
   *
   * nbuckets and levelBuckets specify the discrete levels of the histogram dist 
   *
   * Additionally, one bucket will be created to track
   * all values that fall below the specified minimum, and one bucket will be
   * created for all values above the specified maximum.
   *
   */
  SlabHistogramBuckets(
      size_t nbuckets,
      const ValueType levelBuckets[],
      ValueType min,
      ValueType max,
      const BucketType& defaultBucket) 
      : nbuckets_(nbuckets), min_(min), max_(max) 

      {

	  // Add 2 for the extra 'below min' and 'above max' buckets
	  nbuckets_ += 2;
	  buckets_.assign(size_t(nbuckets_), defaultBucket);

	  bucketlevels_.reserve(nbuckets);

	  for (size_t i = 0; i < nbuckets; ++i) {
	    bucketlevels_.emplace_back(levelBuckets[i]);
	  }
      }		      

  /* Returns the min value at which bucketing begins. */
  ValueType getMin() const {
    return min_;
  }

  /* Returns the max value at which bucketing ends. */
  ValueType getMax() const {
    return max_;
  }

  /*
   * Returns the number of buckets.
   *
   * This includes the total number of buckets for the [min, max) range,
   * plus 2 extra buckets, one for handling values less than min, and one for
   * values greater than max.
   */
  size_t getNumBuckets() const {
    return buckets_.size();
  }

  /* Returns the bucket index into which the given value would fall. */
  size_t getBucketIdx(ValueType value) const {
  if (value < min_) {
    return 0;
  } else if (value >= max_) {
    return buckets_.size() - 1;
  }	  
  return hash_fn(value);
  } 	  

  /* Returns the bucket for the specified value */
  BucketType& getByValue(ValueType value) {
    return buckets_[getBucketIdx(value)];
  }

  /* Returns the bucket for the specified value */
  const BucketType& getByValue(ValueType value) const {
    return buckets_[getBucketIdx(value)];
  }

  /*
   * Returns the bucket at the specified index.
   *
   * Note that index 0 is the bucket for all values less than the specified
   * minimum.  Index 1 is the first bucket in the specified bucket range.
   */
  BucketType& getByIndex(size_t idx) {
    return buckets_[idx];
  }

  /* Returns the bucket at the specified index. */
  const BucketType& getByIndex(size_t idx) const {
    return buckets_[idx];
  }

  /*
   * Returns the minimum threshold for the bucket at the given index.
   */
  ValueType getBucketMin(size_t idx) const {
    if (idx == 0) {
      return std::numeric_limits<ValueType>::min();
    }
    if (idx >= buckets_.size() - 1) {
      return max_;
    }

    return bucketlevels_[idx - 1];
  }

  /*
   * Returns the maximum threshold for the bucket at the given index.
   */
  ValueType getBucketMax(size_t idx) const {
    if (idx >= buckets_.size() - 1) {
      return std::numeric_limits<ValueType>::max();
    }

    return bucketlevels_[idx];
  }

  /**
   * Computes the total number of values stored across all buckets.
   *
   * Runs in O(numBuckets)
   *
   * @param countFn A function that takes a const BucketType&, and returns the
   *                number of values in that bucket
   * @return Returns the total number of values stored across all buckets
   */
  template <typename CountFn>
  uint64_t computeTotalCount(CountFn countFromBucket) const {
	  uint64_t count = 0;
	  for (size_t n = 0; n < buckets_.size(); ++n) {
	    count += countFromBucket(const_cast<const BucketType&>(buckets_[n]));
	  }
	  return count;

  } 	  

  /**
   * Determine which bucket the specified percentile falls into.
   *
   * Looks for the bucket that contains the Nth percentile data point.
   *
   * @param pct     The desired percentile to find, as a value from 0.0 to 1.0.
   * @param countFn A function that takes a const BucketType&, and returns the
   *                number of values in that bucket.
   * @param lowPct  The lowest percentile stored in the selected bucket will be
   *                returned via this parameter.
   * @param highPct The highest percentile stored in the selected bucket will
   *                be returned via this parameter.
   *
   * @return Returns the index of the bucket that contains the Nth percentile
   *         data point.
   */
  template <typename CountFn>
  size_t getPercentileBucketIdx(
      double pct,
      CountFn countFromBucket,
      double* lowPct = nullptr,
      double* highPct = nullptr) const
   {
  CHECK_GE(pct, 0.0);
  CHECK_LE(pct, 1.0);

  auto numBuckets = buckets_.size();

  // Compute the counts in each bucket
  uint64_t	*counts;

  if (numBuckets <= 100) {
	counts = (uint64_t *)alloca(numBuckets * sizeof(uint64_t));		  
  } 	 
  else {
	counts = new uint64_t[numBuckets];
	  SCOPE_EXIT {
		  delete [] counts;
	  };
  }	   	

  uint64_t totalCount = 0;
  for (size_t n = 0; n < numBuckets; ++n) {
    uint64_t bucketCount =
        countFromBucket(const_cast<const BucketType&>(buckets_[n]));
    counts[n] = bucketCount;
    totalCount += bucketCount;
  }

  // If there are no elements, just return the lowest bucket.
  // Note that we return bucket 1, which is the first bucket in the
  // histogram range; bucket 0 is for all values below min_.
  if (totalCount == 0) {
    // Set lowPct and highPct both to 0.
    // getPercentileEstimate() will recognize this to mean that the histogram
    // is empty.
    if (lowPct) {
      *lowPct = 0.0;
    }
    if (highPct) {
      *highPct = 0.0;
    }
    return 1;
  }

  // Loop through all the buckets, keeping track of each bucket's
  // percentile range: [0,10], [10,17], [17,45], etc.  When we find a range
  // that includes our desired percentile, we return that bucket index.
  double prevPct = 0.0;
  double curPct = 0.0;
  uint64_t curCount = 0;
  size_t idx;
  for (idx = 0; idx < numBuckets; ++idx) {
    if (counts[idx] == 0) {
      // skip empty buckets
      continue;
    }

    prevPct = curPct;
    curCount += counts[idx];
    curPct = static_cast<double>(curCount) / totalCount;
    if (pct <= curPct) {
      // This is the desired bucket
      break;
    }
  }

  if (lowPct) {
    *lowPct = prevPct;
  }
  if (highPct) {
    *highPct = curPct;
  }
  return idx;
   
	   
   }	      

  /*
   * Iterator access to the buckets.
   *
   * Note that the first bucket is for all values less than min, and the last
   * bucket is for all values greater than max.  The buckets tracking values in
   * the [min, max) actually start at the second bucket.
   */
  typename std::vector<BucketType>::const_iterator begin() const {
    return buckets_.begin();
  }
  typename std::vector<BucketType>::iterator begin() {
    return buckets_.begin();
  }
  typename std::vector<BucketType>::const_iterator end() const {
    return buckets_.end();
  }
  typename std::vector<BucketType>::iterator end() {
    return buckets_.end();
  }

 private:
  size_t nbuckets_;
  ValueType min_;
  ValueType max_;
  std::vector<BucketType> buckets_;
  std::vector<ValueType> bucketlevels_;

  // The index from value function
  hasher hash_fn;


};


} // namespace detail
} // namespace folly


