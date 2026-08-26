// Tests for the light-wallet-server LMDB layer.
//
// The commit path is the one that caused accounts to appear frozen: it used to
// write a single height, derived from the *lowest* account in a scan-thread
// group, onto every account in that group. An account already further along was
// therefore reset backwards and then skipped forever. Most of what follows pins
// that behaviour down.

#include "gtest/gtest.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

#include <unistd.h>

#include "common/fs.h"

#include "crypto/crypto.h"
#include "db/data.h"
#include "db/storage.h"
#include "error.h"
#include "lmdb/util.h"

namespace
{
  //! \return A unique directory under the system temp dir, already created.
  fs::path make_temp_dir()
  {
    static std::atomic<unsigned> counter{0};
    const auto unique =
      "lws-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++);
    const fs::path path = fs::temp_directory_path() / unique;

    std::error_code ignored{};
    fs::remove_all(path, ignored);
    fs::create_directories(path);
    return path;
  }

  //! A storage instance in a directory that cleans itself up.
  class temp_storage
  {
    fs::path path_;

  public:
    lws::db::storage disk;

    temp_storage()
      : path_(make_temp_dir())
      , disk(lws::db::storage::open(path_.string().c_str(), 100))
    {}

    ~temp_storage() noexcept
    {
      std::error_code ignored{};
      fs::remove_all(path_, ignored);
    }

    temp_storage(temp_storage const&) = delete;
    temp_storage& operator=(temp_storage const&) = delete;
  };

  //! \return A fresh, self-consistent account address plus its view key.
  std::pair<lws::db::account_address, crypto::secret_key> make_credentials()
  {
    lws::db::account_address address{};
    crypto::secret_key view_key{};
    crypto::generate_keys(address.view_public, view_key);

    // spend key never has to match anything for storage-level tests
    crypto::secret_key ignored{};
    crypto::generate_keys(address.spend_public, ignored);
    return {address, view_key};
  }

  //! Add an active account and \return its address and database id.
  std::pair<lws::db::account_address, lws::db::account_id>
  add_active_account(lws::db::storage& disk, lws::db::account_flags flags = lws::db::default_account)
  {
    const auto credentials = make_credentials();
    const auto added = disk.add_account(credentials.first, credentials.second, flags);
    EXPECT_TRUE(bool(added)) << "add_account failed";

    auto reader = disk.start_read();
    EXPECT_TRUE(bool(reader));
    const auto stored = reader->get_account(credentials.first);
    EXPECT_TRUE(bool(stored));
    return {credentials.first, stored->second.id};
  }

  //! \return The stored record for `address`.
  lws::db::account read_account(lws::db::storage& disk, lws::db::account_address const& address)
  {
    auto reader = disk.start_read();
    EXPECT_TRUE(bool(reader));
    const auto stored = reader->get_account(address);
    EXPECT_TRUE(bool(stored));
    return stored->second;
  }

  //! \return The stored status for `address`.
  lws::db::account_status read_status(lws::db::storage& disk, lws::db::account_address const& address)
  {
    auto reader = disk.start_read();
    EXPECT_TRUE(bool(reader));
    const auto stored = reader->get_account(address);
    EXPECT_TRUE(bool(stored));
    return stored->first;
  }

  //! \return An in-memory scan account seeded from what is on disk.
  lws::account scan_account(lws::db::storage& disk, lws::db::account_address const& address)
  {
    return lws::account{read_account(disk, address), {}, {}};
  }

  //! \return `count` distinct block hashes, as a batch covering `count` blocks.
  std::vector<crypto::hash> make_chain(std::size_t count, std::uint8_t seed = 1)
  {
    std::vector<crypto::hash> chain(count, crypto::hash{});
    for (std::size_t i = 0; i < count; ++i)
    {
      chain[i].data[0] = char(seed);
      chain[i].data[1] = char(i & 0xff);
      chain[i].data[2] = char((i >> 8) & 0xff);
    }
    return chain;
  }
}

// ---------------------------------------------------------------------------
// on-disk layout - these guard the ability to roll back to an older binary
// ---------------------------------------------------------------------------

TEST(lws_storage, record_layout_is_frozen)
{
  /* Growing any of these changes the on-disk record size. LMDB tables here are
     DUPFIXED, so a size change makes every existing database unreadable by an
     older binary and the upgrade one-way. Add a side table instead. */
  EXPECT_EQ(128u, sizeof(lws::db::account));
  EXPECT_EQ(64u, sizeof(lws::db::account_address));
  EXPECT_EQ(112u, sizeof(lws::db::request_info));
}

// ---------------------------------------------------------------------------
// storage::update - the height commit path
// ---------------------------------------------------------------------------

TEST(lws_storage, update_advances_a_matching_account)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);

  std::vector<lws::account> users{};
  users.push_back(scan_account(store.disk, account.first));

  const auto chain = make_chain(100);
  const auto outcome = store.disk.update(
    lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
  );

  ASSERT_TRUE(bool(outcome));
  EXPECT_EQ(1u, outcome->advanced.size());
  EXPECT_TRUE(outcome->unchanged.empty());
  EXPECT_TRUE(outcome->diverged.empty());
  EXPECT_TRUE(outcome->regressions.empty());
  EXPECT_EQ(99u, std::uint64_t(read_account(store.disk, account.first).scan_height));
}

// The regression that froze accounts. An account ahead of the batch must keep
// its own height rather than being dragged down to the group's.
TEST(lws_storage, update_never_lowers_a_scan_height)
{
  temp_storage store{};
  const auto laggard = add_active_account(store.disk);
  const auto ahead = add_active_account(store.disk);

  // put `ahead` far forward, as a completed scan would leave it
  const auto ahead_only = std::vector<lws::db::account_address>{ahead.first};
  ASSERT_TRUE(bool(store.disk.rescan(
    lws::db::block_id(500'000), epee::to_span(ahead_only), true, 1'000'000
  )));
  ASSERT_EQ(500'000u, std::uint64_t(read_account(store.disk, ahead.first).scan_height));

  // now commit a low batch covering both, exactly as a mixed group would
  std::vector<lws::account> users{};
  users.push_back(scan_account(store.disk, laggard.first));
  users.push_back(scan_account(store.disk, ahead.first));

  const auto chain = make_chain(1000);
  const auto outcome = store.disk.update(
    lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
  );

  ASSERT_TRUE(bool(outcome));
  EXPECT_EQ(500'000u, std::uint64_t(read_account(store.disk, ahead.first).scan_height))
    << "an account ahead of the batch was dragged backwards";
  EXPECT_EQ(999u, std::uint64_t(read_account(store.disk, laggard.first).scan_height));

  EXPECT_EQ(1u, outcome->advanced.size());
  ASSERT_EQ(1u, outcome->unchanged.size());
  EXPECT_EQ(ahead.second, outcome->unchanged.front().id);
  EXPECT_TRUE(outcome->diverged.empty()) << "no re-plan should be needed";

  // the batch offered a lower height, so it is reported - but only as a signal
  ASSERT_EQ(1u, outcome->regressions.size());
  EXPECT_EQ(ahead.second, outcome->regressions.front().id);
}

// The tripwire: offering a lower height is refused *and* reported.
TEST(lws_storage, update_reports_a_refused_regression)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);

  // scan a normal batch, then jump the account forward past it
  {
    std::vector<lws::account> users{};
    users.push_back(scan_account(store.disk, account.first));
    const auto chain = make_chain(1000);
    ASSERT_TRUE(bool(store.disk.update(
      lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
    )));
  }
  const auto addresses = std::vector<lws::db::account_address>{account.first};
  ASSERT_TRUE(bool(store.disk.rescan(
    lws::db::block_id(10'000), epee::to_span(addresses), true, 1'000'000
  )));
  ASSERT_EQ(10'000u, std::uint64_t(read_account(store.disk, account.first).scan_height));

  /* Re-offer a batch that only reaches height 49. The same hashes are used so
     this is not a reorg - purely a lower height being offered. */
  std::vector<lws::account> users{};
  users.push_back(scan_account(store.disk, account.first));
  const auto chain = make_chain(50);
  const auto outcome = store.disk.update(
    lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
  );

  ASSERT_TRUE(bool(outcome));
  ASSERT_EQ(1u, outcome->regressions.size()) << "a lowered height was not reported";
  EXPECT_EQ(account.second, outcome->regressions.front().id);
  EXPECT_EQ(10'000u, std::uint64_t(outcome->regressions.front().old_height));
  EXPECT_EQ(10'000u, std::uint64_t(read_account(store.disk, account.first).scan_height))
    << "the refused write still changed the stored height";
}

TEST(lws_storage, update_reports_accounts_that_moved_underneath_it)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);

  // in-memory copy taken before an admin action moves the stored height
  std::vector<lws::account> users{};
  users.push_back(scan_account(store.disk, account.first));

  const auto addresses = std::vector<lws::db::account_address>{account.first};
  ASSERT_TRUE(bool(store.disk.rescan(
    lws::db::block_id(7), epee::to_span(addresses), true, 1'000'000
  )));

  const auto chain = make_chain(100);
  const auto outcome = store.disk.update(
    lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
  );

  ASSERT_TRUE(bool(outcome));
  ASSERT_EQ(1u, outcome->diverged.size()) << "divergence was not detected";
  EXPECT_EQ(account.second, outcome->diverged.front());
  EXPECT_TRUE(outcome->advanced.empty());
  EXPECT_EQ(7u, std::uint64_t(read_account(store.disk, account.first).scan_height))
    << "the diverged account was overwritten anyway";
}

TEST(lws_storage, update_stamps_progress_only_when_a_height_moves)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);

  {
    auto reader = store.disk.start_read();
    ASSERT_TRUE(bool(reader));
    const auto progress = reader->get_last_progress(account.second);
    ASSERT_TRUE(bool(progress));
    EXPECT_EQ(0u, lmdb::to_native(*progress)) << "progress recorded before any scan";
  }

  std::vector<lws::account> users{};
  users.push_back(scan_account(store.disk, account.first));
  const auto chain = make_chain(100);
  ASSERT_TRUE(bool(store.disk.update(
    lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
  )));

  auto reader = store.disk.start_read();
  ASSERT_TRUE(bool(reader));
  const auto progress = reader->get_last_progress(account.second);
  ASSERT_TRUE(bool(progress));
  EXPECT_NE(0u, lmdb::to_native(*progress)) << "forward movement was not stamped";
}

TEST(lws_storage, update_detects_a_reorg)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);

  {
    std::vector<lws::account> users{};
    users.push_back(scan_account(store.disk, account.first));
    const auto chain = make_chain(500);
    ASSERT_TRUE(bool(store.disk.update(
      lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
    )));
  }

  // same heights, different hashes: the chain these accounts were scanned
  // against is no longer the chain we hold
  const auto addresses = std::vector<lws::db::account_address>{account.first};
  ASSERT_TRUE(bool(store.disk.rescan(
    lws::db::block_id(0), epee::to_span(addresses), true, 1'000'000
  )));

  std::vector<lws::account> users{};
  users.push_back(scan_account(store.disk, account.first));
  const auto chain = make_chain(500, 9);
  const auto outcome = store.disk.update(
    lws::db::block_id(0), epee::to_span(chain), epee::to_span(users)
  );

  ASSERT_FALSE(bool(outcome)) << "a conflicting chain was committed silently";
  EXPECT_TRUE(outcome == lws::error::blockchain_reorg)
    << "reorg was not reported as such: " << outcome.error().message();
}

// ---------------------------------------------------------------------------
// rescan - must move in both directions, and purge what it invalidates
// ---------------------------------------------------------------------------

TEST(lws_storage, rescan_moves_an_account_forward)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);
  const auto addresses = std::vector<lws::db::account_address>{account.first};

  const auto moved = store.disk.rescan(
    lws::db::block_id(50'000), epee::to_span(addresses), true, 1'000'000
  );
  ASSERT_TRUE(bool(moved));
  EXPECT_EQ(1u, moved->size());
  EXPECT_EQ(50'000u, std::uint64_t(read_account(store.disk, account.first).scan_height))
    << "rescan could not move an account forward";
}

TEST(lws_storage, rescan_moves_an_account_backward)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);
  const auto addresses = std::vector<lws::db::account_address>{account.first};

  ASSERT_TRUE(bool(store.disk.rescan(
    lws::db::block_id(50'000), epee::to_span(addresses), true, 1'000'000
  )));
  ASSERT_TRUE(bool(store.disk.rescan(
    lws::db::block_id(120), epee::to_span(addresses), true, 1'000'000
  )));

  const auto stored = read_account(store.disk, account.first);
  EXPECT_EQ(120u, std::uint64_t(stored.scan_height));
  EXPECT_LE(std::uint64_t(stored.start_height), 120u)
    << "start_height should never sit above scan_height";
}

TEST(lws_storage, rescan_rejects_a_height_beyond_the_chain)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);
  const auto addresses = std::vector<lws::db::account_address>{account.first};

  const auto moved = store.disk.rescan(
    lws::db::block_id(900), epee::to_span(addresses), true, 500
  );
  EXPECT_FALSE(bool(moved)) << "rescan accepted a height above the chain tip";
}

// ---------------------------------------------------------------------------
// delete_accounts
// ---------------------------------------------------------------------------

TEST(lws_storage, delete_accounts_removes_the_record)
{
  temp_storage store{};
  const auto kept = add_active_account(store.disk);
  const auto doomed = add_active_account(store.disk);

  const auto addresses = std::vector<lws::db::account_address>{doomed.first};
  const auto removed = store.disk.delete_accounts(epee::to_span(addresses));
  ASSERT_TRUE(bool(removed));
  EXPECT_EQ(1u, removed->size());

  auto reader = store.disk.start_read();
  ASSERT_TRUE(bool(reader));
  EXPECT_FALSE(bool(reader->get_account(doomed.first))) << "deleted account still readable";
  EXPECT_TRUE(bool(reader->get_account(kept.first))) << "the wrong account was removed";
}

TEST(lws_storage, delete_accounts_ignores_unknown_addresses)
{
  temp_storage store{};
  const auto unknown = make_credentials().first;

  const auto addresses = std::vector<lws::db::account_address>{unknown};
  const auto removed = store.disk.delete_accounts(epee::to_span(addresses));
  ASSERT_TRUE(bool(removed)) << "deleting an unknown address should not be an error";
  EXPECT_TRUE(removed->empty());
}

// ---------------------------------------------------------------------------
// access time and the idle sweep
// ---------------------------------------------------------------------------

TEST(lws_storage, update_access_time_bumps_the_stored_value)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);

  // rewind access so the bump is observable without sleeping
  const lws::db::account_time original = read_account(store.disk, account.first).access;
  ASSERT_TRUE(bool(store.disk.update_access_time(account.first)));

  const lws::db::account_time bumped = read_account(store.disk, account.first).access;
  EXPECT_GE(lmdb::to_native(bumped), lmdb::to_native(original));
}

TEST(lws_storage, update_access_time_rejects_unknown_addresses)
{
  temp_storage store{};
  const auto unknown = make_credentials().first;
  EXPECT_FALSE(bool(store.disk.update_access_time(unknown)));
}

TEST(lws_storage, idle_sweep_deactivates_only_stale_accounts)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);
  ASSERT_EQ(lws::db::account_status::active, read_status(store.disk, account.first));

  // a cutoff in the distant past matches nothing
  {
    const auto swept = store.disk.deactivate_idle(lws::db::account_time(1));
    ASSERT_TRUE(bool(swept));
    EXPECT_TRUE(swept->empty()) << "a fresh account was swept";
    EXPECT_EQ(lws::db::account_status::active, read_status(store.disk, account.first));
  }

  // a cutoff in the future matches everything
  {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()
    ).count();
    const auto swept =
      store.disk.deactivate_idle(lws::db::account_time(std::uint32_t(now + 60)));
    ASSERT_TRUE(bool(swept));
    EXPECT_EQ(1u, swept->size());
    EXPECT_EQ(lws::db::account_status::inactive, read_status(store.disk, account.first))
      << "the sweep did not deactivate a stale account";
  }
}

TEST(lws_storage, idle_sweep_never_touches_admin_accounts)
{
  temp_storage store{};
  const auto admin = add_active_account(store.disk, lws::db::admin_account);
  const auto ordinary = add_active_account(store.disk);

  // admin accounts are created hidden; make it active so the sweep would see it
  const auto admin_addresses = std::vector<lws::db::account_address>{admin.first};
  ASSERT_TRUE(bool(store.disk.change_status(
    lws::db::account_status::active, epee::to_span(admin_addresses)
  )));

  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()
  ).count();
  const auto swept =
    store.disk.deactivate_idle(lws::db::account_time(std::uint32_t(now + 60)));

  ASSERT_TRUE(bool(swept));
  EXPECT_EQ(lws::db::account_status::active, read_status(store.disk, admin.first))
    << "the sweep locked an operator out of their own admin account";
  EXPECT_EQ(lws::db::account_status::inactive, read_status(store.disk, ordinary.first));
}

TEST(lws_storage, deactivated_accounts_keep_their_scan_height)
{
  temp_storage store{};
  const auto account = add_active_account(store.disk);
  const auto addresses = std::vector<lws::db::account_address>{account.first};

  ASSERT_TRUE(bool(store.disk.rescan(
    lws::db::block_id(4321), epee::to_span(addresses), true, 1'000'000
  )));

  const auto now = std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()
  ).count();
  ASSERT_TRUE(bool(
    store.disk.deactivate_idle(lws::db::account_time(std::uint32_t(now + 60)))
  ));

  EXPECT_EQ(4321u, std::uint64_t(read_account(store.disk, account.first).scan_height))
    << "deactivation lost scan progress; reactivation would rescan from scratch";

  // and reactivation restores it to the scan set at the same height
  ASSERT_TRUE(bool(store.disk.change_status(
    lws::db::account_status::active, epee::to_span(addresses)
  )));
  EXPECT_EQ(lws::db::account_status::active, read_status(store.disk, account.first));
  EXPECT_EQ(4321u, std::uint64_t(read_account(store.disk, account.first).scan_height));
}

TEST(lws_storage, access_tracking_marker_is_stable_once_written)
{
  temp_storage store{};

  const auto first = store.disk.access_tracking_since();
  ASSERT_TRUE(bool(first));
  EXPECT_NE(0u, lmdb::to_native(*first));

  const auto second = store.disk.access_tracking_since();
  ASSERT_TRUE(bool(second));
  EXPECT_EQ(lmdb::to_native(*first), lmdb::to_native(*second))
    << "the sweep grace period would restart on every daemon start";
}

// ---------------------------------------------------------------------------
// account creation
// ---------------------------------------------------------------------------

TEST(lws_storage, accounts_can_be_created_before_any_chain_sync)
{
  temp_storage store{};
  const auto credentials = make_credentials();

  // the chain table is empty here - this used to fail with MDB_NOTFOUND,
  // making a fresh deployment unusable until the first sync completed
  const auto added = store.disk.add_account(credentials.first, credentials.second);
  ASSERT_TRUE(bool(added)) << "could not create an account on a fresh database";
  EXPECT_EQ(0u, std::uint64_t(read_account(store.disk, credentials.first).scan_height));
}

TEST(lws_storage, duplicate_accounts_are_rejected)
{
  temp_storage store{};
  const auto credentials = make_credentials();

  ASSERT_TRUE(bool(store.disk.add_account(credentials.first, credentials.second)));
  EXPECT_FALSE(bool(store.disk.add_account(credentials.first, credentials.second)));
}

TEST(lws_storage, a_mismatched_view_key_is_rejected)
{
  temp_storage store{};
  auto credentials = make_credentials();
  const auto other = make_credentials();

  EXPECT_FALSE(bool(store.disk.add_account(credentials.first, other.second)))
    << "an account was created whose view key does not match its address";
}
