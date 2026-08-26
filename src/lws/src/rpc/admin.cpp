// Copyright (c) 2023, The Monero Project
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "admin.h"

#include <boost/range/iterator_range.hpp>
#include <functional>
#include <utility>
#include <ctime>
#include <deque>
#include <mutex>
#include <algorithm>
#include "lmdb/util.h"
#include "db/string.h"
#include "error.h"
#include "span.h" // monero/contrib/epee/include
#include "wire.h"
#include "wire/crypto.h"
#include "wire/error.h"
#include "wire/json/write.h"
#include "wire/traits.h"
#include "wire/vector.h"
#include "epee/hex.h"

namespace
{
  // Do not output "full" debug data provided by `db::data.h` header; truncate output
  template<typename T>
  struct truncated
  {
    T value;
  };

  lws::db::account_address wire_unwrap(const boost::string_ref source)
  {
    const expect<lws::db::account_address> address = lws::db::address_string(source);
    if (!address)
      WIRE_DLOG_THROW(wire::error::schema::string, "Bad string to address conversion: " << address.error().message());
    return *address;
  }

  using base58_address = truncated<lws::db::account_address&>;
  void read_bytes(wire::reader& source, base58_address& dest)
  {
    dest.value = wire_unwrap(source.string());
  }

  void write_bytes(wire::writer& dest, const truncated<lws::db::account>& self)
  {
    wire::object(dest,
      wire::field("id", std::uint64_t(lmdb::to_native(self.value.id))),
      wire::field("address", lws::db::address_string(self.value.address)),
      wire::field("scan_height", self.value.scan_height),
      wire::field("start_height", self.value.start_height),
      wire::field("access_time", self.value.access),
      wire::field("creation_time", self.value.creation),
      wire::field("flags", std::uint64_t(self.value.flags))
    );
  }

  void write_bytes(wire::writer& dest, const truncated<lws::db::request_info>& self)
  {
    wire::object(dest,
      wire::field("address", lws::db::address_string(self.value.address)),
      wire::field("start_height", self.value.start_height)
    );
  }

  template<typename V>
  void write_bytes(wire::json_writer& dest, const truncated<boost::iterator_range<lmdb::value_iterator<V>>> self)
  {
    const auto truncate = [] (V src) { return truncated<V>{std::move(src)}; };
    wire::array(dest, std::move(self.value), truncate);
  }

  template<typename K, typename V, typename C>
  expect<void> stream_object(wire::json_writer& dest, expect<lmdb::key_stream<K, V, C>> self)
  {
    using value_range = boost::iterator_range<lmdb::value_iterator<V>>;
    const auto truncate = [] (value_range src) -> truncated<value_range>
    {
      return {std::move(src)};
    };

    if (!self)
      return self.error();

    wire::dynamic_object(dest, self->make_range(), wire::enum_as_string, truncate);
    return success();
  }

  template<typename T, typename U>
  void read_addresses(wire::reader& source, T& self, U field)
  {
    std::vector<std::string> addresses;
    wire::object(source, wire::field("addresses", std::ref(addresses)), std::move(field));

    self.addresses.reserve(addresses.size());
    for (const auto& elem : addresses)
      self.addresses.emplace_back(wire_unwrap(elem));
  }

  void write_addresses(wire::writer& dest, epee::span<const lws::db::account_address> self)
  {
    // writes an array of monero base58 address strings
    wire::object(dest, wire::field("updated", wire::as_array(self, lws::db::address_string)));
  }

  expect<void> write_addresses(wire::writer& dest, const expect<std::vector<lws::db::account_address>>& self)
  {
    if (!self)
      return self.error();
    write_addresses(dest, epee::to_span(*self));
    return success();
  }
} // anonymous

namespace lws { namespace rpc
{
  account_scan_lookup account_scan_slot_of = nullptr;

  void write_bytes(wire::writer& dest, const admin_log_entry& self)
  {
    wire::object(dest,
      wire::field("when", self.when),
      wire::field("caller_id", self.caller_id),
      wire::field("endpoint", std::cref(self.endpoint)),
      wire::field("detail", std::cref(self.detail))
    );
  }

  namespace
  {
    //! \return `status` as the same string the other admin endpoints use.
    const char* status_name(db::account_status status) noexcept
    {
      switch (status)
      {
      case db::account_status::active:   return "active";
      case db::account_status::inactive: return "inactive";
      case db::account_status::hidden:   return "hidden";
      }
      return "unknown";
    }
  }

  void read_bytes(wire::reader& source, add_account_req& self)
  {
    wire::object(source,
      wire::field("address", base58_address{self.address}),
      wire::field("key", std::ref(unwrap(unwrap(self.key))))
    );
  }

  void read_bytes(wire::reader& source, address_requests& self)
  {
    read_addresses(source, self, WIRE_FIELD(type));
  }
  void read_bytes(wire::reader& source, modify_account_req& self)
  {
    read_addresses(source, self, WIRE_FIELD(status));
  }
  void read_bytes(wire::reader& source, rescan_req& self)
  {
    std::vector<std::string> addresses;
    wire::object(source,
      wire::field("addresses", std::ref(addresses)),
      WIRE_FIELD(height),
      wire::optional_field("purge", std::ref(self.purge))
    );
    self.addresses.reserve(addresses.size());
    for (const auto& elem : addresses)
      self.addresses.emplace_back(wire_unwrap(elem));
  }

  void read_bytes(wire::reader& source, rollback_req& self)
  {
    wire::object(source, WIRE_FIELD(height));
  }

  void read_bytes(wire::reader& source, delete_account_req& self)
  {
    std::vector<std::string> addresses;
    wire::object(source, wire::field("addresses", std::ref(addresses)));
    self.addresses.reserve(addresses.size());
    for (const auto& elem : addresses)
      self.addresses.emplace_back(wire_unwrap(elem));
  }

  void read_bytes(wire::reader& source, validate_req& self)
  {
    wire::object(source, WIRE_FIELD(spend_public_hex), WIRE_FIELD(view_public_hex), WIRE_FIELD(view_key_hex));
  }

  void read_bytes(wire::reader& source, account_info_req& self)
  {
    wire::object(source, WIRE_FIELD(address));
  }

  void read_bytes(wire::reader& source, list_accounts_req& self)
  {
    wire::object(source,
      wire::optional_field("status", std::ref(self.status)),
      wire::optional_field("min_height", std::ref(self.min_height)),
      wire::optional_field("max_height", std::ref(self.max_height)),
      wire::optional_field("behind_by", std::ref(self.behind_by)),
      wire::optional_field("stalled_for", std::ref(self.stalled_for)),
      wire::optional_field("offset", std::ref(self.offset)),
      wire::optional_field("limit", std::ref(self.limit))
    );
  }

  expect<void> accept_requests_::operator()(wire::writer& dest, db::storage disk, const request& req) const
  {
    return write_addresses(dest, disk.accept_requests(req.type, epee::to_span(req.addresses)));
  }

  expect<void> add_account_::operator()(wire::writer& out, db::storage disk, const request& req) const
  {
    using span = epee::span<const lws::db::account_address>;
    MONERO_CHECK(disk.add_account(req.address, req.key));
    write_addresses(out, span{std::addressof(req.address), 1});
    return success();
  }

  expect<void> list_accounts_::operator()(wire::json_writer& dest, db::storage disk) const
  {
    return (*this)(dest, std::move(disk), list_accounts_req{});
  }

  namespace
  {
    //! \return True if `user` passes every filter set in `req`.
    bool matches(const list_accounts_req& req, db::account const& user,
                 std::uint64_t chain_height, std::uint64_t last_progress)
    {
      const std::uint64_t height = std::uint64_t(user.scan_height);
      if (req.stalled_for)
      {
        const std::uint64_t now = std::uint64_t(std::time(nullptr));
        const std::uint64_t idle =
          (last_progress && now > last_progress) ? now - last_progress : 0;
        if (idle < *req.stalled_for)
          return false;
      }
      if (req.min_height && height < std::uint64_t(*req.min_height))
        return false;
      if (req.max_height && std::uint64_t(*req.max_height) < height)
        return false;
      if (req.behind_by)
      {
        const std::uint64_t behind = chain_height > height ? chain_height - height : 0;
        if (behind < *req.behind_by)
          return false;
      }
      return true;
    }
  }

  expect<void> list_accounts_::operator()(wire::json_writer& dest, db::storage disk, const request& req) const
  {
    auto reader = disk.start_read();
    if (!reader)
      return reader.error();

    /* Without filters this is the original endpoint - the whole table grouped by
       status. With filters we walk and select, which is what makes "show me
       everything more than N blocks behind" a single call. */
    const bool unfiltered =
      !req.status && !req.min_height && !req.max_height && !req.behind_by &&
      !req.stalled_for && !req.offset && !req.limit;

    const std::uint64_t offset = req.offset.value_or(0);
    const std::uint64_t limit = req.limit.value_or(0);

    if (unfiltered)
      return stream_object(dest, reader->get_accounts());

    std::uint64_t chain_height = 0;
    {
      const auto last = reader->get_last_block();
      if (last)
        chain_height = std::uint64_t(last->id);
    }

    auto accounts = reader->get_accounts();
    if (!accounts)
      return accounts.error();

    std::vector<truncated<lws::db::account>> selected{};
    std::uint64_t seen = 0;
    std::uint64_t total = 0;

    for (auto status_group = accounts->make_iterator(); !status_group.is_end(); ++status_group)
    {
      const db::account_status status = status_group.get_key();
      if (req.status && status != *req.status)
        continue;

      for (db::account const& user : status_group.make_value_range())
      {
        std::uint64_t last_progress = 0;
        {
          const auto progressed = reader->get_last_progress(user.id);
          if (progressed)
            last_progress = lmdb::to_native(*progressed);
        }
        if (!matches(req, user, chain_height, last_progress))
          continue;
        ++total;
        if (seen++ < offset)
          continue;
        if (limit && limit <= selected.size())
          continue;
        selected.push_back(truncated<lws::db::account>{user});
      }
    }

    wire::object(dest,
      wire::field("chain_height", chain_height),
      wire::field("matched", total),
      wire::field("returned", std::uint64_t(selected.size())),
      wire::field("accounts", std::cref(selected))
    );
    return success();
  }

  expect<void> account_info_::operator()(wire::json_writer& dest, db::storage disk, const request& req) const
  {
    const expect<db::account_address> address = db::address_string(req.address);
    if (!address)
      return address.error();

    auto reader = disk.start_read();
    if (!reader)
      return reader.error();

    const auto found = reader->get_account(*address);
    if (!found)
      return found.error();

    const db::account& user = found->second;

    std::uint64_t chain_height = 0;
    {
      const auto last = reader->get_last_block();
      if (last)
        chain_height = std::uint64_t(last->id);
    }

    std::uint64_t output_count = 0;
    std::uint64_t spend_count = 0;
    std::uint64_t received = 0;
    std::uint64_t sent = 0;

    auto outputs = reader->get_outputs(user.id);
    if (outputs)
    {
      for (db::output const& out : outputs->make_range())
      {
        ++output_count;
        received += out.spend_meta.amount;
      }
    }

    auto spends = reader->get_spends(user.id);
    if (spends)
    {
      for (db::spend const& spend : spends->make_range())
      {
        ++spend_count;
        (void)spend;
      }
    }

    std::uint64_t last_progress = 0;
    {
      const auto progressed = reader->get_last_progress(user.id);
      if (progressed)
        last_progress = lmdb::to_native(*progressed);
    }

    const std::uint64_t scan_height = std::uint64_t(user.scan_height);
    const std::uint64_t behind = chain_height > scan_height ? chain_height - scan_height : 0;

    /* Which scan thread is carrying this account, if any. This is the field that
       turns "it is stuck" into "it is stuck behind account N on thread 3". */
    const boost::optional<account_scan_slot> slot =
      account_scan_slot_of ? account_scan_slot_of(user.id) : boost::none;

    wire::object(dest,
      wire::field("address", db::address_string(user.address)),
      wire::field("id", std::uint64_t(lmdb::to_native(user.id))),
      wire::field("status", std::string{status_name(found->first)}),
      wire::field("scan_height", scan_height),
      wire::field("start_height", std::uint64_t(user.start_height)),
      wire::field("chain_height", chain_height),
      wire::field("blocks_behind", behind),
      wire::field("access_time", std::uint64_t(lmdb::to_native(user.access))),
      wire::field("creation_time", std::uint64_t(lmdb::to_native(user.creation))),
      wire::field("last_progress", last_progress),
      wire::field("stalled_for",
        last_progress ? std::uint64_t(std::time(nullptr)) - last_progress : std::uint64_t(0)),
      wire::field("flags", std::uint64_t(user.flags)),
      wire::field("output_count", output_count),
      wire::field("spend_count", spend_count),
      wire::field("total_received", received),
      wire::field("total_sent", sent),
      wire::field("scan_thread", slot ? std::int64_t(slot->thread_index) : std::int64_t(-1)),
      wire::field("scan_thread_low", slot ? slot->group_low : std::uint64_t(0)),
      wire::field("scan_thread_high", slot ? slot->group_high : std::uint64_t(0))
    );
    return success();
  }

  expect<void> list_requests_::operator()(wire::json_writer& dest, db::storage disk) const
  {
    auto reader = disk.start_read();
    if (!reader)
      return reader.error();
    return stream_object(dest, reader->get_requests());
  }

  expect<void> modify_account_::operator()(wire::writer& dest, db::storage disk, const request& req) const
  {
    return write_addresses(dest, disk.change_status(req.status, epee::to_span(req.addresses)));
  }

  expect<void> reject_requests_::operator()(wire::writer& dest, db::storage disk, const request& req) const
  {
    return write_addresses(dest, disk.reject_requests(req.type, epee::to_span(req.addresses)));
  }

  expect<void> rescan_::operator()(wire::writer& dest, db::storage disk, const request& req) const
  {
    /* Bound against the live tip rather than the local chain table, which only
       advances during a sync pass and so rejected valid heights. */
    std::uint64_t chain_height = 0;
    {
      auto reader = disk.start_read();
      if (reader)
      {
        const auto last = reader->get_last_block();
        if (last)
          chain_height = std::uint64_t(last->id);
      }
    }
    return write_addresses(
      dest, disk.rescan(req.height, epee::to_span(req.addresses), req.purge.value_or(true), chain_height)
    );
  }

  expect<void> rollback_::operator()(wire::writer& dest, db::storage disk, const request& req) const
  {
    MONERO_CHECK(disk.rollback(req.height));
    wire::object(dest, wire::field("new_height", req.height));
    return success();
  }

  expect<void> delete_account_::operator()(wire::writer& dest, db::storage disk, const request& req) const
  {
    const expect<std::vector<db::account_address>> removed =
      disk.delete_accounts(epee::to_span(req.addresses));
    if (!removed)
      return removed.error();
    wire::object(dest, wire::field("deleted", wire::as_array(epee::to_span(*removed), lws::db::address_string)));
    return success();
  }

  namespace
  {
    constexpr const std::size_t admin_log_max = 512;

    std::mutex& admin_log_mutex()
    {
      static std::mutex instance{};
      return instance;
    }

    std::deque<admin_log_entry>& admin_log_store()
    {
      static std::deque<admin_log_entry> instance{};
      return instance;
    }
  }

  void record_admin_action(std::uint64_t caller_id, std::string endpoint, std::string detail)
  {
    const std::lock_guard<std::mutex> lock{admin_log_mutex()};
    auto& store = admin_log_store();
    store.push_front(
      admin_log_entry{
        std::int64_t(std::time(nullptr)), caller_id, std::move(endpoint), std::move(detail)
      }
    );
    while (admin_log_max < store.size())
      store.pop_back();
  }

  std::vector<admin_log_entry> admin_log_entries()
  {
    const std::lock_guard<std::mutex> lock{admin_log_mutex()};
    const auto& store = admin_log_store();
    return std::vector<admin_log_entry>{store.begin(), store.end()};
  }

  expect<void> admin_log_::operator()(wire::json_writer& dest, db::storage) const
  {
    const std::vector<admin_log_entry> entries = admin_log_entries();
    wire::object(dest, wire::field("entries", std::cref(entries)));
    return success();
  }

  namespace
  {
    struct validate_error
    {
      std::string field;
      std::string details;
    };

    void write_bytes(wire::writer& dest, const validate_error& self)
    {
      wire::object(dest, WIRE_FIELD(field), WIRE_FIELD(details));
    }

    expect<void> output_error(wire::writer& dest, std::string field, std::string details)
    {
      wire::object(dest, wire::field("error", validate_error{std::move(field), std::move(details)}));
      return success();
    }

    template<typename T>
    bool convert_key(wire::writer& dest, T& out, const boost::string_ref in, const boost::string_ref field)
    {
      if (in.size() != sizeof(out) * 2)
      {
        output_error(dest, std::string{field}, "Expected " + std::to_string(sizeof(out) * 2) + " characters");
        return false;
      }
      if (!epee::from_hex::to_buffer(epee::as_mut_byte_span(out), in))
      {
        output_error(dest, std::string{field}, "Invalid hex");
        return false;
      }
      return true;
    }
  }

  expect<void> validate_::operator()(wire::writer& dest, const db::storage&, const request& req) const
  {
    db::account_address address{};
    crypto::secret_key view_key{};

    if (!convert_key(dest, address.spend_public, req.spend_public_hex, "spend_public_hex"))
      return success(); // error is delivered in JSON as opposed to HTTP codes
    if (!convert_key(dest, address.view_public, req.view_public_hex, "view_public_hex"))
      return success();
    if (!convert_key(dest, unwrap(unwrap(view_key)), req.view_key_hex, "view_key_hex"))
      return success();

    if (!crypto::check_key(address.spend_public))
      return output_error(dest, "spend_public_hex", "Invalid public key format");
    if (!crypto::check_key(address.view_public))
      return output_error(dest, "view_public_hex", "Invalid public key format");

    crypto::public_key test{};
    if (!crypto::secret_key_to_public_key(view_key, test) || test != address.view_public)
      return output_error(dest, "view_key_hex", "view_key and view_public do not match");

    wire::object(dest, wire::field("address", db::address_string(address)));
    return success();
  }
}} // lws // rpc