#pragma once

#include <iosfwd>
#include <list>
#include <memory>
#include <utility>
#include <vector>

#include "common/expect.h"
#include "crypto/crypto.h"
#include "fwd.h"
#include "lmdb/transaction.h"
#include "lmdb/key_stream.h"
#include "lmdb/value_stream.h"

#include "db/data.h"
#include "db/account.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace crypto
{
  struct hash;
}

namespace lws
{
namespace db
 {
  namespace cursor
  {
    MONERO_CURSOR(accounts);
    MONERO_CURSOR(outputs);
    MONERO_CURSOR(spends);
    MONERO_CURSOR(images);
    MONERO_CURSOR(requests);

    MONERO_CURSOR(blocks);
    MONERO_CURSOR(accounts_by_address);
    MONERO_CURSOR(accounts_by_height);
  }

  struct storage_internal;

  //! Per-account result of a single `storage::update` commit.
  struct account_progress
  {
    account_id id;          //!< Account that was examined.
    block_id old_height;    //!< Scan height held before the commit.
    block_id new_height;    //!< Scan height held after the commit.
  };

  //! Outcome of `storage::update`, detailed enough to log and act on.
  struct update_outcome
  {
    //! Accounts whose stored scan height moved forward.
    std::vector<account_progress> advanced;
    /*! Accounts already at or beyond the committed height. Not an error - the
        batch simply had nothing new for them. */
    std::vector<account_progress> unchanged;
    /*! Accounts left untouched because the stored height no longer matches the
        in-memory copy, or because the record could not be found. */
    std::vector<account_id> diverged;
    /*! Accounts for which a *lower* height was offered than the one already
        stored. Always refused, and always also listed in `unchanged`.

        Expected when a scan-thread group spans heights: the batch starts at the
        group's lowest account and simply does not reach the ones above it. A
        persistently non-empty list means the plan is mixing accounts that are
        too far apart. */
    std::vector<account_progress> regressions;

    //! \return Accounts accounted for, i.e. everything except `diverged`.
    std::size_t handled() const noexcept
    { return advanced.size() + unchanged.size(); }
  };
  
  struct reader_internal
  {
    cursor::blocks blocks_cur;
    cursor::accounts_by_address accounts_ba_cur;
    cursor::accounts_by_height accounts_bh_cur;
  };

  //! Wrapper for LMDB read access to on-disk storage of light-weight server data.
  class storage_reader
  {
    std::shared_ptr<storage_internal> db;
    lmdb::read_txn txn;
    reader_internal curs;

  public:
    storage_reader(std::shared_ptr<storage_internal> db, lmdb::read_txn txn) noexcept
      : db(std::move(db)), txn(std::move(txn)), curs{}
    {}

    storage_reader(storage_reader&&) = default;
    storage_reader(storage_reader const&) = delete;

    ~storage_reader() noexcept;

    storage_reader& operator=(storage_reader&&) = default;
    storage_reader& operator=(storage_reader const&) = delete;

    //! \return Last known block.
    expect<block_info> get_last_block() noexcept;

    /*! \return When `id`'s scan height last moved forward, or 0 if never.

      Stored in its own table rather than on the account record, so that adding
      it did not change the account layout on disk. */
    expect<account_time> get_last_progress(account_id id) noexcept;

    //! \return "Our" block hash at `height`.
    expect<crypto::hash> get_block_hash(const block_id height) noexcept;

    //! \return List for `GetHashesFast` to sync blockchain with daemon.
    // expect<std::list<crypto::hash>> get_chain_sync();
    expect<int> get_chain_sync();

    //! \return All registered `account`s.
    expect<lmdb::key_stream<account_status, account, cursor::close_accounts>>
      get_accounts(cursor::accounts cur = nullptr) noexcept;

    //! \return All `account`s currently in `status` or `lmdb::error(MDB_NOT_FOUND)`.
    expect<lmdb::value_stream<account, cursor::close_accounts>>
      get_accounts(account_status status, cursor::accounts cur = nullptr) noexcept;

    //! \return Info for account `id` iff it has `status`.
    expect<account> get_account(const account_status status, const account_id id) noexcept;

    //! \return Info related to `address`.
    expect<std::pair<account_status, account>>
      get_account(account_address const& address) noexcept;

    //! \return All outputs received by `id`.
    expect<lmdb::value_stream<output, cursor::close_outputs>>
      get_outputs(account_id id, cursor::outputs cur = nullptr) noexcept;

    //! \return All potential spends by `id`.
    expect<lmdb::value_stream<spend, cursor::close_spends>>
      get_spends(account_id id, cursor::spends cur = nullptr) noexcept;

    //! \return All key images associated with `id`.
    expect<lmdb::value_stream<db::key_image, cursor::close_images>>
      get_images(output_id id, cursor::images cur = nullptr) noexcept;

    //! \return All `request_info`s.
    expect<lmdb::key_stream<request, request_info, cursor::close_requests>>
      get_requests(cursor::requests cur = nullptr) noexcept;

    //! \return A specific request from `address` of `type`.
    expect<request_info>
      get_request(request type, account_address const& address, cursor::requests cur = nullptr) noexcept;

    //! Dump the contents of the database in JSON format to `out`.
    expect<void> json_debug(std::ostream& out, bool show_keys);

    //! \return Read txn that can be re-used via `storage::start_read`.
    lmdb::suspended_txn finish_read() noexcept;
  };

  //! Wrapper for LMDB on-disk storage of light-weight server data.
  class storage
  {
    std::shared_ptr<storage_internal> db;

    storage(std::shared_ptr<storage_internal> db) noexcept
      : db(std::move(db))
    {}

  public:
    /*!
      Open a light_wallet_server LDMB database.

      \param path Directory for LMDB storage
      \param create_queue_max Maximum number of create account requests allowed.

      \throw std::system_error on any LMDB error (all treated as fatal).
      \throw std::bad_alloc If `std::shared_ptr` fails to allocate.

      \return A ready light-wallet server database.
    */
    static storage open(const char* path, unsigned create_queue_max);

    storage(storage&&) = default;
    storage(storage const&) = delete;

    ~storage() noexcept;

    storage& operator=(storage&&) = default;
    storage& operator=(storage const&) = delete;

    //! \return A copy of the LMDB environment, but not reusable txn/cursors.
    storage clone() const noexcept;

    // ! Rollback chain and accounts to `height`.
   expect<void> rollback(block_id height);

    /*!
      Sync the local blockchain with a remote version. Pops user txes if reorg
      detected.

      \param height The height of the element in `hashes`
      \param hashes List of blockchain hashes starting at `height`.

      \return True if the local blockchain is correctly synced.
    */
    expect<void> sync_chain(block_id height, epee::span<const crypto::hash> hashes);

    /*! Bump the last access time of `address` to now.

      Drives the idle sweep and the `access_time` an operator sees. Callers are
      expected to debounce - see `access_tracker` in rest_server.cpp - because
      this takes the single LMDB write lock, which the scanner also needs. */
    expect<void> update_access_time(account_address const& address) noexcept;

    /*! \return When this database first started recording real access times.

      Before the access-time updater existed, `account.access` was written once
      at creation and never touched, so on an upgraded database it is really the
      creation time. Recorded on first call and used to hold the idle sweep off
      until access data has actually been collected for a full timeout period.

      Written on first call, so this is not a const operation. */
    expect<account_time> access_tracking_since() noexcept;

    /*! Move `active` accounts untouched since `cutoff` to `inactive`.

      Scanning stops for them, but every output, spend, key image and the scan
      height itself are kept, so a later login resumes from where it left off
      rather than rescanning from the start height.

      \return The addresses that were deactivated. */
    expect<std::vector<account_address>> deactivate_idle(account_time cutoff);

    //! Change state of `address` to `status`. \return Updated `addresses`.
    expect<std::vector<account_address>>
      change_status(account_status status, epee::span<const account_address> addresses);


    //! Add an account, for immediate inclusion in the active list.
    expect<void> add_account(account_address const& address, crypto::secret_key const& key, account_flags flags =  static_cast<account_flags>(0)) noexcept;

    /*!
      Move `addresses` to `height` for scanning, in either direction.

      \param height Target scan height; may be above or below the current one.
      \param addresses Accounts to move.
      \param purge Drop outputs, spends and key images recorded above `height`.
        Needed whenever a rescan is meant to *repair* an account rather than just
        re-confirm what is already stored.
      \param chain_height Live chain tip to bound `height` against; pass 0 to use
        the local chain table, which only advances during a sync pass.

      \return The addresses that were moved.
    */
    expect<std::vector<account_address>>
      rescan(block_id height, epee::span<const account_address> addresses, bool purge = true, std::uint64_t chain_height = 0);

    //! Permanently remove `addresses` and everything indexed against them.
    expect<std::vector<account_address>>
      delete_accounts(epee::span<const account_address> addresses);

    //! Add an account for later approval. For use with the login endpoint.
    expect<void> creation_request(account_address const& address, crypto::secret_key const& key, account_flags flags) noexcept;

    /*!
      Request lock height of an existing account. No effect if the `start_height`
      is already older.
    */
    expect<void> import_request(account_address const& address, block_id height) noexcept;

    //! Accept requests by `addresses` of type `req`. \return Accepted addresses.
    expect<std::vector<account_address>>
      accept_requests(request req, epee::span<const account_address> addresses);

    //! Reject requests by `addresses` of type `req`. \return Rejected addresses.
    expect<std::vector<account_address>>
      reject_requests(request req, epee::span<const account_address> addresses);

    /*!
      Updates the status of user accounts, even if inactive or hidden. Duplicate
      receives or spends provided in `accts` are silently ignored. If a gap in
      `height` vs the stored account record is detected, the entire update will
      fail.

      A stored scan height is never lowered. `height + chain.size() - 1` is the
      height this batch reached; an account already beyond it keeps its own
      height and is reported in `update_outcome::unchanged`.

      \param height The first hash in `chain` is at this height.
      \param chain List of block hashes that `accts` were scanned against.
      \param accts Advanced to `height + chain.size() - 1` unless already beyond it.

      \return Per-account outcome, or an LMDB error if the txn failed.
    */
    expect<update_outcome> update(block_id height, epee::span<const crypto::hash> chain, epee::span<const lws::account> accts);

    //! `txn` must have come from a previous call on the same thread.
    expect<storage_reader> start_read(lmdb::suspended_txn txn = nullptr) const;
  };
} // db
} // lws
