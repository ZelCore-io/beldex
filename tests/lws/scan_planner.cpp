// Tests for the scan-thread planner.
//
// This is the fix for the reported "some accounts are stuck at the same height"
// bug: accounts used to be split into equal-sized buckets, so one freshly
// created account could land in a bucket with accounts already at the chain tip
// and hold all of them back. These tests pin the properties that must hold for
// that not to happen again.

#include "gtest/gtest.h"

#include <algorithm>
#include <numeric>
#include <set>

#include "scan_planner.h"

namespace
{
  constexpr const std::uint64_t default_span = 10000;

  //! \return Every index across `groups`, so coverage can be checked.
  std::multiset<std::size_t> all_indices(std::vector<std::vector<std::size_t>> const& groups)
  {
    std::multiset<std::size_t> out{};
    for (auto const& group : groups)
      out.insert(group.begin(), group.end());
    return out;
  }

  //! Assert the invariants every plan must satisfy, whatever the input.
  void expect_well_formed(
    std::vector<std::uint64_t> const& heights,
    std::vector<std::vector<std::size_t>> const& groups,
    std::size_t thread_count)
  {
    EXPECT_LE(groups.size(), thread_count) << "planner exceeded the thread budget";

    for (auto const& group : groups)
    {
      EXPECT_FALSE(group.empty()) << "planner produced an empty group";
      EXPECT_TRUE(std::is_sorted(group.begin(), group.end()))
        << "group indices must stay in ascending height order";
    }

    // every account must be planned exactly once - none dropped, none duplicated
    const auto planned = all_indices(groups);
    EXPECT_EQ(heights.size(), planned.size()) << "accounts were dropped or duplicated";
    for (std::size_t i = 0; i < heights.size(); ++i)
      EXPECT_EQ(1u, planned.count(i)) << "account " << i << " not planned exactly once";
  }
}

TEST(lws_scan_planner, empty_input)
{
  const std::vector<std::uint64_t> heights{};
  const auto groups = lws::plan_scan_groups(heights, 8, default_span);
  EXPECT_TRUE(groups.empty());
}

TEST(lws_scan_planner, single_account)
{
  const std::vector<std::uint64_t> heights{500};
  const auto groups = lws::plan_scan_groups(heights, 8, default_span);

  ASSERT_EQ(1u, groups.size());
  EXPECT_EQ(1u, groups[0].size());
  expect_well_formed(heights, groups, 8);
}

TEST(lws_scan_planner, accounts_at_one_height_never_stall)
{
  // 20 accounts all at the tip: any grouping is fine, but no group may have span
  std::vector<std::uint64_t> heights(20, 3'000'000);
  const auto groups = lws::plan_scan_groups(heights, 4, default_span);

  expect_well_formed(heights, groups, 4);
  for (auto const& group : groups)
    EXPECT_EQ(0u, lws::plan_group_span(heights, group));
}

// The exact scenario from the bug report: a fleet synced to the tip, plus one
// account that has just logged in and starts from zero.
TEST(lws_scan_planner, one_laggard_is_isolated_from_synced_accounts)
{
  std::vector<std::uint64_t> heights{};
  heights.push_back(0);                                  // the new account
  for (int i = 0; i < 99; ++i)
    heights.push_back(3'000'000);                        // already synced
  std::sort(heights.begin(), heights.end());

  const auto groups = lws::plan_scan_groups(heights, 8, default_span);
  expect_well_formed(heights, groups, 8);

  // the laggard must not share a group with anything near the tip
  for (auto const& group : groups)
  {
    const std::uint64_t low = heights[group.front()];
    const std::uint64_t high = heights[group.back()];
    if (low == 0)
    {
      EXPECT_EQ(0u, high)
        << "the new account was grouped with synced accounts - they would stall";
    }
  }
}

TEST(lws_scan_planner, bands_stay_within_max_span_when_threads_allow)
{
  // four clearly separated clusters, four threads: each cluster gets its own
  std::vector<std::uint64_t> heights{
    100, 105, 110,
    500'000, 500'004,
    1'200'000, 1'200'009,
    2'500'000
  };
  const auto groups = lws::plan_scan_groups(heights, 4, default_span);

  expect_well_formed(heights, groups, 4);
  ASSERT_EQ(4u, groups.size());
  for (auto const& group : groups)
    EXPECT_LE(lws::plan_group_span(heights, group), default_span);
}

TEST(lws_scan_planner, merges_the_cheapest_adjacent_pair_when_short_on_threads)
{
  // three clusters, two threads. The two closest clusters (100 and 60'000) must
  // merge, leaving the distant one alone - merging across the big gap would be
  // the expensive choice.
  std::vector<std::uint64_t> heights{100, 60'000, 5'000'000};
  const auto groups = lws::plan_scan_groups(heights, 2, default_span);

  expect_well_formed(heights, groups, 2);
  ASSERT_EQ(2u, groups.size());

  const auto* far_group = &groups[0];
  for (auto const& group : groups)
    if (heights[group.front()] == 5'000'000)
      far_group = &group;

  EXPECT_EQ(1u, far_group->size())
    << "the distant account should not have been merged with the near cluster";
}

TEST(lws_scan_planner, splits_large_bands_when_threads_are_spare)
{
  // 8 accounts at one height, 4 threads: work should spread rather than idle
  std::vector<std::uint64_t> heights(8, 900'000);
  const auto groups = lws::plan_scan_groups(heights, 4, default_span);

  expect_well_formed(heights, groups, 4);
  EXPECT_GT(groups.size(), 1u) << "spare threads were left idle";
}

// Scanning cost is linear in the accounts a thread carries, so the slowest
// thread sets the pace. Halving the largest band repeatedly used to leave 866
// accounts as six groups of 108 and four of 54 - half the threads idle for half
// of every batch.
TEST(lws_scan_planner, spare_threads_split_a_band_evenly)
{
  for (std::size_t threads : {2u, 3u, 8u, 10u, 14u})
  {
    std::vector<std::uint64_t> heights(866, 5'696'743);
    const auto groups = lws::plan_scan_groups(heights, threads, default_span);

    expect_well_formed(heights, groups, threads);
    ASSERT_EQ(threads, groups.size()) << "threads=" << threads;

    std::size_t smallest = heights.size(), largest = 0;
    for (auto const& group : groups)
    {
      smallest = std::min(smallest, group.size());
      largest = std::max(largest, group.size());
    }
    EXPECT_LE(largest - smallest, 1u)
      << "threads=" << threads << ": group sizes differ by " << (largest - smallest)
      << " (" << smallest << ".." << largest << "), so the slowest thread holds up the rest";
  }
}

TEST(lws_scan_planner, spare_threads_favour_the_busiest_band)
{
  // one big band at the tip and one laggard; the spare threads should go to the
  // band that actually has accounts to spread, not to the single account
  std::vector<std::uint64_t> heights{0};
  heights.insert(heights.end(), 100, 5'000'000);

  const auto groups = lws::plan_scan_groups(heights, 5, default_span);
  expect_well_formed(heights, groups, 5);

  for (auto const& group : groups)
  {
    if (heights[group.front()] == 0)
      EXPECT_EQ(1u, group.size()) << "the laggard should stay alone";
    else
      EXPECT_LE(group.size(), 26u) << "the busy band was not spread across the spare threads";
  }
}

TEST(lws_scan_planner, single_thread_still_plans_everything)
{
  std::vector<std::uint64_t> heights{0, 1000, 2'000'000, 3'000'000};
  const auto groups = lws::plan_scan_groups(heights, 1, default_span);

  expect_well_formed(heights, groups, 1);
  ASSERT_EQ(1u, groups.size());
  EXPECT_EQ(heights.size(), groups[0].size());
}

TEST(lws_scan_planner, never_exceeds_thread_budget_across_many_shapes)
{
  // property check over a spread of distributions and budgets
  for (std::size_t threads = 1; threads <= 16; ++threads)
  {
    for (std::size_t count = 1; count <= 40; ++count)
    {
      std::vector<std::uint64_t> heights{};
      heights.reserve(count);
      for (std::size_t i = 0; i < count; ++i)
        heights.push_back(std::uint64_t(i) * 7919); // spread wider than max_span
      std::sort(heights.begin(), heights.end());

      const auto groups = lws::plan_scan_groups(heights, threads, default_span);
      EXPECT_LE(groups.size(), threads)
        << "threads=" << threads << " count=" << count;
      EXPECT_EQ(count, all_indices(groups).size())
        << "threads=" << threads << " count=" << count;
    }
  }
}

TEST(lws_scan_planner, zero_span_forces_one_band_per_distinct_height)
{
  std::vector<std::uint64_t> heights{10, 10, 20, 20, 30};
  const auto groups = lws::plan_scan_groups(heights, 8, 0);

  expect_well_formed(heights, groups, 8);

  /* Spare threads mean same-height bands may be split further, so the count is
     not fixed - the property that matters is that no group ever mixes heights. */
  for (auto const& group : groups)
    EXPECT_EQ(0u, lws::plan_group_span(heights, group))
      << "a zero span budget still produced a group covering several heights";
}
