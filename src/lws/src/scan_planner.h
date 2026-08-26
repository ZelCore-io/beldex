#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lws
{
  /*! Split scan-height-sorted accounts into thread groups of similar height.

    Every account in a group advances from that group's *lowest* height, so an
    account far above it does no work until the laggard catches up. Grouping by
    account count instead of by height is what made a single freshly created
    account stall every account it was bucketed with.

    Accounts sitting at the same height cost nothing to share a thread - they are
    all tested against the same blocks in one pass - so the goal is narrow height
    bands rather than equal group sizes. The plan is built in three steps:

      1. Walk the sorted heights, cutting a new band whenever adding the next
         account would push the band's span past `max_span`.
      2. If that produced more bands than threads, repeatedly merge the adjacent
         pair whose combined span is smallest, until the bands fit.
      3. If threads are left over, split the largest band in half. Both halves
         then fetch the same blocks, so this only happens when a thread would
         otherwise sit idle.

    Kept free of `lws::account` so it can be tested directly on heights.

    \pre `0 < thread_count`
    \pre `sorted_heights` is sorted ascending.
    \return Groups of indices into `sorted_heights`. Every index appears exactly
      once, no group is empty, and there are never more than `thread_count`
      groups. */
  std::vector<std::vector<std::size_t>> plan_scan_groups(
    std::vector<std::uint64_t> const& sorted_heights,
    std::size_t thread_count,
    std::uint64_t max_span);

  //! \return Height span of `group`, given the heights it indexes.
  std::uint64_t plan_group_span(
    std::vector<std::uint64_t> const& sorted_heights,
    std::vector<std::size_t> const& group) noexcept;
} // lws
