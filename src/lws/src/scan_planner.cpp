#include "scan_planner.h"

#include <algorithm>
#include <cassert>
#include <limits>

namespace lws
{
  std::uint64_t plan_group_span(
    std::vector<std::uint64_t> const& sorted_heights,
    std::vector<std::size_t> const& group) noexcept
  {
    if (group.empty())
      return 0;
    return sorted_heights[group.back()] - sorted_heights[group.front()];
  }

  std::vector<std::vector<std::size_t>> plan_scan_groups(
    std::vector<std::uint64_t> const& sorted_heights,
    std::size_t thread_count,
    std::uint64_t max_span)
  {
    assert(0 < thread_count);
    assert(std::is_sorted(sorted_heights.begin(), sorted_heights.end()));

    std::vector<std::vector<std::size_t>> groups{};
    if (sorted_heights.empty())
      return groups;

    // (1) greedily cut a new band whenever the span would exceed `max_span`
    for (std::size_t i = 0; i < sorted_heights.size(); ++i)
    {
      if (groups.empty() ||
          max_span < sorted_heights[i] - sorted_heights[groups.back().front()])
      {
        groups.emplace_back();
      }
      groups.back().push_back(i);
    }

    // (2) too many bands for the thread budget - merge the cheapest adjacent pair
    while (thread_count < groups.size())
    {
      std::size_t best = 0;
      std::uint64_t best_cost = std::numeric_limits<std::uint64_t>::max();
      for (std::size_t i = 0; i + 1 < groups.size(); ++i)
      {
        // cost of merging i and i+1 is the span the combined band would have
        const std::uint64_t cost =
          sorted_heights[groups[i + 1].back()] - sorted_heights[groups[i].front()];
        if (cost < best_cost)
        {
          best_cost = cost;
          best = i;
        }
      }

      auto& target = groups[best];
      auto& source = groups[best + 1];
      target.insert(target.end(), source.begin(), source.end());
      groups.erase(groups.begin() + best + 1);
    }

    /* (3) Spare threads. Scanning cost is linear in the number of accounts a
       thread carries, so the slowest thread sets the pace and the split has to
       be even. Repeatedly halving the largest band does not achieve that: 866
       accounts over 10 threads converges on six groups of 108 and four of 54,
       leaving half the threads idle for half of every batch.

       Instead work out how many threads each band deserves - handing each spare
       thread to whichever band currently has the worst accounts-per-thread
       ratio - then cut each band into that many equal chunks. */
    if (groups.size() < thread_count)
    {
      std::vector<std::size_t> quota(groups.size(), 1);
      std::size_t assigned = groups.size();

      while (assigned < thread_count)
      {
        std::size_t best = 0;
        double best_load = -1.0;
        bool any = false;
        for (std::size_t i = 0; i < groups.size(); ++i)
        {
          if (groups[i].size() <= quota[i])
            continue; // already one account per thread
          const double load = double(groups[i].size()) / double(quota[i] + 1);
          if (best_load < load)
          {
            best_load = load;
            best = i;
            any = true;
          }
        }
        if (!any)
          break; // every band is already split as far as it can go
        ++quota[best];
        ++assigned;
      }

      std::vector<std::vector<std::size_t>> split{};
      split.reserve(assigned);
      for (std::size_t i = 0; i < groups.size(); ++i)
      {
        const std::size_t chunks = quota[i];
        const std::size_t total = groups[i].size();
        std::size_t taken = 0;
        for (std::size_t c = 0; c < chunks; ++c)
        {
          // spread the remainder over the first chunks so sizes differ by at most one
          const std::size_t take = total / chunks + (c < total % chunks ? 1 : 0);
          split.emplace_back(
            groups[i].begin() + taken, groups[i].begin() + taken + take
          );
          taken += take;
        }
      }
      groups = std::move(split);
    }

    return groups;
  }
} // lws
