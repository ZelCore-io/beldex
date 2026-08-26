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

#pragma once

#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include <vector>
#include "common/expect.h" // monero/src
#include "db/data.h"
#include "db/storage.h"
#include "wire/fwd.h"
#include "wire/json/fwd.h"

namespace lws
{
namespace rpc
{
  struct add_account_req
  {
    db::account_address address;
    crypto::secret_key key;
  };
  void read_bytes(wire::reader&, add_account_req&);

  //! Request object for `accept_requests` and `reject_requests` endpoints.
  struct address_requests
  {
    std::vector<db::account_address> addresses;
    db::request type;
  };
  void read_bytes(wire::reader&, address_requests&);

  struct modify_account_req
  {
    std::vector<db::account_address> addresses;
    db::account_status status;
  };
  void read_bytes(wire::reader&, modify_account_req&);

  struct rescan_req
  {
    std::vector<db::account_address> addresses;
    db::block_id height;
    /*! Drop outputs and spends recorded above `height`. Defaults to true so a
        rescan can actually repair an account; set false for a cheap re-walk. */
    boost::optional<bool> purge;
  };
  void read_bytes(wire::reader&, rescan_req&);

  //! Request object for the `rollback` endpoint.
  struct rollback_req
  {
    db::block_id height;
  };
  void read_bytes(wire::reader&, rollback_req&);

  //! Request object for the `delete_account` endpoint.
  struct delete_account_req
  {
    std::vector<db::account_address> addresses;
  };
  void read_bytes(wire::reader&, delete_account_req&);

  struct validate_req
  {
    std::string spend_public_hex;
    std::string view_public_hex;
    std::string view_key_hex;
  };
  void read_bytes(wire::reader&, validate_req&);

  //! Request object for the `account_info` endpoint.
  struct account_info_req
  {
    std::string address;
  };
  void read_bytes(wire::reader&, account_info_req&);

  /*! Optional filters for `list_accounts`.

    All fields default to "no filter", so an empty `params` behaves exactly like
    the original endpoint apart from the extra reported fields. */
  struct list_accounts_req
  {
    boost::optional<db::account_status> status;
    boost::optional<db::block_id> min_height;   //!< Only accounts at or above this scan height.
    boost::optional<db::block_id> max_height;   //!< Only accounts at or below this scan height.
    boost::optional<std::uint64_t> behind_by;   //!< Only accounts at least this far behind the chain tip.
    //! Only accounts whose scan height has not moved for at least this many seconds.
    boost::optional<std::uint64_t> stalled_for;
    boost::optional<std::uint64_t> offset;      //!< Accounts to skip, for paging.
    boost::optional<std::uint64_t> limit;       //!< Maximum accounts to return; unset means no limit.
  };
  void read_bytes(wire::reader&, list_accounts_req&);


  struct accept_requests_
  {
    static constexpr const char* endpoint_name = "accept_requests";
    using request = address_requests;
    expect<void> operator()(wire::writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const accept_requests_ accept_requests{};

  struct add_account_
  {
    static constexpr const char* endpoint_name = "add_account";
    using request = add_account_req;
    expect<void> operator()(wire::writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const add_account_ add_account{};

  struct list_accounts_
  {
    using request = list_accounts_req;
    expect<void> operator()(wire::json_writer& dest, db::storage disk) const;
    expect<void> operator()(wire::json_writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const list_accounts_ list_accounts{};

  //! Where an account currently sits in the scan schedule.
  struct account_scan_slot
  {
    std::size_t thread_index;
    std::uint64_t group_low;
    std::uint64_t group_high;
  };

  /*! Looks up which scan thread carries an account.

    The RPC library does not link the scanner, so the binary that runs one
    installs this at start-up; when it is unset `account_info` simply omits the
    scan-thread fields. */
  using account_scan_lookup = boost::optional<account_scan_slot>(*)(db::account_id);
  extern account_scan_lookup account_scan_slot_of;

  //! Full detail for a single account, for triaging one user report.
  struct account_info_
  {
    using request = account_info_req;
    expect<void> operator()(wire::json_writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const account_info_ account_info{};

  struct list_requests_
  {
    using request = expect<void>;
    expect<void> operator()(wire::json_writer& dest, db::storage disk) const;
    expect<void> operator()(wire::json_writer& dest, db::storage disk, const request&) const
    { return (*this)(dest, std::move(disk)); }
  };
  constexpr const list_requests_ list_requests{};

  struct modify_account_
  {
    static constexpr const char* endpoint_name = "modify_account_status";
    using request = modify_account_req;
    expect<void> operator()(wire::writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const modify_account_ modify_account{};

  struct reject_requests_
  {
    static constexpr const char* endpoint_name = "reject_requests";
    using request = address_requests;
    expect<void> operator()(wire::writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const reject_requests_ reject_requests{};

  struct rescan_
  {
    static constexpr const char* endpoint_name = "rescan";
    using request = rescan_req;
    expect<void> operator()(wire::writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const rescan_ rescan{};

  //! Roll the whole database back to `height`, dropping every account past it.
  struct rollback_
  {
    static constexpr const char* endpoint_name = "rollback";
    using request = rollback_req;
    expect<void> operator()(wire::writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const rollback_ rollback{};

  //! Permanently remove accounts and everything indexed against them.
  struct delete_account_
  {
    static constexpr const char* endpoint_name = "delete_account";
    using request = delete_account_req;
    expect<void> operator()(wire::writer& dest, db::storage disk, const request& req) const;
  };
  constexpr const delete_account_ delete_account{};

  /*! Record of one admin action, for `admin_log`.

    Kept in memory only - enough to answer "who just rescanned everything?"
    without adding a table. */
  struct admin_log_entry
  {
    std::int64_t when;        //!< Unix seconds.
    std::uint64_t caller_id;  //!< Account id of the admin that called.
    std::string endpoint;
    std::string detail;       //!< Affected addresses/heights, already truncated.
  };

  //! Append to the in-memory admin audit log.
  void record_admin_action(std::uint64_t caller_id, std::string endpoint, std::string detail);

  //! \return The audit log, newest first.
  std::vector<admin_log_entry> admin_log_entries();

  struct admin_log_
  {
    using request = expect<void>;
    expect<void> operator()(wire::json_writer& dest, db::storage disk) const;
    expect<void> operator()(wire::json_writer& dest, db::storage disk, const request&) const
    { return (*this)(dest, std::move(disk)); }
  };
  constexpr const admin_log_ admin_log{};

  struct validate_
  {
    using request = validate_req;
    expect<void> operator()(wire::writer& dest, const db::storage&, const request& req) const;
  };
  constexpr const validate_ validate{};

}} // lws // rpc