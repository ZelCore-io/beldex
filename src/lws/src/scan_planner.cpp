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

    /* (3) spare threads - split the largest band in half. Both halves scan the
       same blocks, which doubles the daemon traffic for that band, so only do it
       while there is genuinely an idle thread to hand the work to. */
    while (groups.size() < thread_count)
    {
      const auto largest = std::max_element(
        groups.begin(), groups.end(),
        [] (auto const& l, auto const& r) { return l.size() < r.size(); }
      );
      if (largest == groups.end() || largest->size() < 2)
        break;

      const std::size_t half = largest->size() / 2;
      std::vector<std::size_t> spun_off{largest->begin() + half, largest->end()};
      largest->erase(largest->begin() + half, largest->end());
      groups.push_back(std::move(spun_off));
    }

    return groups;
  }
} // lws
