#include "scanner.h"
#include "scan_planner.h"

#include <algorithm>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/range/combine.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <cpr/cpr.h>
#include <cassert>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <map>
#include <type_traits>
#include <utility>
#include <fstream>

#include "common/error.h"
#include "common/hex.h"                               // monero/src
#include "crypto/crypto.h"                            // monero/src
#include "crypto/wallet/crypto.h"                     // monero/src
#include "cryptonote_basic/cryptonote_basic.h"        // monero/src
#include "cryptonote_basic/cryptonote_format_utils.h" // monero/src
#include "epee/span.h"                                // monero/src
#include "epee/misc_log_ex.h"                         // monero/src

#include "error.h"
#include "scanner.h"
#include "db/account.h"
#include "util/transactions.h"
#include "rpc/daemon_zmq.h"
#include "rpc/json.h"
#include "wire/json/read.h"
#include "lmdb/util.h"
#include "wallet/node_rpc_proxy.h"
#include "wallet/wallet2.h"
#include <oxenmq/oxenmq.h>
#include <oxenc/hex.h>

// #include "common/types.h"
#include "rpc/core_rpc_server_commands_defs.h"

namespace lws
{
  std::atomic<bool> scanner::running{true};
  std::atomic<bool> scanner::failed{false};

  namespace
  {
    //! \return Current time as Unix seconds.
    std::int64_t unix_now() noexcept
    {
      return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
      ).count();
    }

    /*! Process-wide record of what every scan thread is doing.

      Scan threads write to it at batch boundaries; the admin REST server reads a
      copy. Guarded by a plain mutex because writes happen once per batch, not
      per block. */
    class scan_registry
    {
      mutable std::mutex mutex_{};
      std::map<std::size_t, scan_thread_status> threads_{};
      std::uint64_t daemon_height_{0};
      std::uint64_t restarts_{0};
      std::uint64_t deactivated_{0};
      std::int64_t last_sweep_{0};
      std::int64_t last_restart_{0};
      std::string last_restart_reason_{};

    public:
      //! Register a thread and the accounts it is responsible for.
      void begin(std::size_t index, std::vector<db::account_id> accounts,
                 std::uint64_t low, std::uint64_t high)
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        scan_thread_status entry{};
        entry.index = index;
        entry.accounts = std::move(accounts);
        entry.group_low = low;
        entry.group_high = high;
        entry.current_height = low;
        entry.alive = true;
        threads_[index] = std::move(entry);
      }

      //! Record a committed batch.
      void progress(std::size_t index, std::uint64_t height, std::uint64_t blocks,
                    double rate, std::uint64_t batch_ms)
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        auto entry = threads_.find(index);
        if (entry == threads_.end())
          return;
        entry->second.current_height = height;
        entry->second.blocks_scanned += blocks;
        entry->second.blocks_per_second = rate;
        entry->second.last_batch_ms = batch_ms;
        entry->second.last_commit = unix_now();
        entry->second.last_error.clear();
        entry->second.consecutive_failures = 0;
      }

      //! Record a failed batch.
      void failure(std::size_t index, std::string what, unsigned failures)
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        auto entry = threads_.find(index);
        if (entry == threads_.end())
          return;
        entry->second.last_error = std::move(what);
        entry->second.consecutive_failures = failures;
      }

      //! Mark a thread as exited, keeping its last known state visible.
      void end(std::size_t index)
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        auto entry = threads_.find(index);
        if (entry != threads_.end())
          entry->second.alive = false;
      }

      //! Forget every thread record; called when a scan pass is re-planned.
      void clear_threads()
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        threads_.clear();
      }

      void note_daemon_height(std::uint64_t height)
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        daemon_height_ = std::max(daemon_height_, height);
      }

      void note_sweep(std::size_t deactivated)
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        deactivated_ += deactivated;
        last_sweep_ = unix_now();
      }

      void note_restart(std::string reason)
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        ++restarts_;
        last_restart_ = unix_now();
        last_restart_reason_ = std::move(reason);
      }

      scanner_status snapshot() const
      {
        const std::lock_guard<std::mutex> lock{mutex_};
        scanner_status out{};
        out.running = scanner::is_running();
        out.daemon_height = daemon_height_;
        out.restarts = restarts_;
        out.deactivated = deactivated_;
        out.last_sweep = last_sweep_;
        out.last_restart = last_restart_;
        out.last_restart_reason = last_restart_reason_;
        out.threads.reserve(threads_.size());
        for (const auto& entry : threads_)
          out.threads.push_back(entry.second);
        return out;
      }
    };

    scan_registry& registry()
    {
      static scan_registry instance{};
      return instance;
    }
  } // anonymous

  scanner_status scanner::status()
  {
    return registry().snapshot();
  }

  namespace
  {
    constexpr const std::chrono::seconds account_poll_interval{10};

    //! Smallest batch the adaptive sizing will shrink to.
    constexpr const std::uint64_t min_batch_size = 20;

    //! Consecutive good batches before the batch size is ramped back up.
    constexpr const unsigned batch_ramp_after = 4;

    //! Longest a scan thread waits after a failed batch before retrying.
    constexpr const std::chrono::seconds max_scan_backoff{60};

    /*! Consecutive failed batches before a scan thread stops retrying and lets
        `check_loop` re-read the account list and re-plan. */
    constexpr const unsigned max_consecutive_failures = 10;

    /*! Scan threads deliberately left out of the initial plan.

        Accounts that appear while scanning is under way are handed to a spare
        thread; without any spare, every new login costs a full teardown, chain
        sync and re-plan. Holding two back trades a little parallelism for
        logins that cost nothing, which matters a great deal more when the
        server is fronting a wallet. */
    constexpr const std::size_t pickup_reserve = 2;

    /*! A scan pass shorter than this is treated as a failure to make progress,
        and the next pass is delayed. */
    constexpr const std::chrono::seconds min_healthy_pass{5};

    /*! \return The process-wide OxenMQ instance.

      OxenMQ runs its own proxy thread and is safe to use from several threads,
      so one instance is shared; each scan thread opens its own connection on it. */
    oxenmq::OxenMQ& shared_lmq()
    {
      static oxenmq::OxenMQ instance{nullptr, oxenmq::LogLevel::warn};
      static std::once_flag started;
      std::call_once(started, [] {
        instance.MAX_MSG_SIZE = 200 * 1024 * 1024;
        instance.start();
      });
      return instance;
    }
    constexpr const std::chrono::minutes block_rpc_timeout{2};
    constexpr const std::chrono::seconds send_timeout{30};
    constexpr const std::chrono::seconds sync_rpc_timeout{30};

    struct thread_sync
    {
      boost::mutex sync;
      boost::condition_variable user_poll;
      std::atomic<bool> update;
    };
    struct thread_data
    {
      explicit thread_data(db::storage disk, std::vector<lws::account> users, std::size_t index, scanner_options options)
          : disk(std::move(disk)), users(std::move(users)), index(index), options(options)
      {}

      db::storage disk;
      std::vector<lws::account> users;
      std::size_t index; //!< Position in the scan-thread list; used in log lines.
      scanner_options options;
    };

    //! Wall-clock helper for the per-phase batch timings in `scan_loop`.
    struct stopwatch
    {
      std::chrono::steady_clock::time_point mark;

      stopwatch() noexcept : mark(std::chrono::steady_clock::now()) {}

      //! \return Milliseconds since the last call (or construction), and reset.
      std::int64_t lap() noexcept
      {
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - mark);
        mark = now;
        return elapsed.count();
      }
    };

    //! \return `ids` as a comma separated list, truncated so log lines stay readable.
    std::string format_ids(std::vector<db::account_id> const& ids, std::size_t max_shown = 12)
    {
      std::string out{};
      const std::size_t shown = std::min(max_shown, ids.size());
      for (std::size_t i = 0; i < shown; ++i)
      {
        if (i)
          out += ",";
        out += std::to_string(lmdb::to_native(ids[i]));
      }
      if (shown < ids.size())
        out += ",... (+" + std::to_string(ids.size() - shown) + " more)";
      return out;
    }

    /*! One decoded `get_blocks_fast` batch.

      Both the blob and the legacy JSON transport produce this, so the scan loop
      below does not care which one the daemon answered with. */
    struct fetched_batch
    {
      std::vector<cryptonote::rpc::block_with_transactions> blocks;
      std::vector<std::vector<std::vector<std::uint64_t>>> output_indices;
      std::uint64_t start_height;
      std::uint64_t current_height;
    };

    //! \return `hex` decoded into a blob. \throw std::runtime_error on bad hex.
    std::string blob_from_hex(const std::string& hex, const char* what)
    {
      if (!oxenc::is_hex(hex))
        throw std::runtime_error{std::string{"Daemon sent invalid hex for "} + what};
      std::string out{};
      out.reserve(hex.size() / 2);
      oxenc::from_hex(hex.begin(), hex.end(), std::back_inserter(out));
      return out;
    }

    /*! Decode a `"blob": true` response.

      The daemon hands back the same blobs it holds in LMDB, so this is a single
      binary deserialisation per block and per transaction - no JSON round trip
      of the block contents at either end. */
    fetched_batch parse_blob_batch(const nlohmann::json& result)
    {
      fetched_batch out{};
      out.start_height   = result.at("start_height").get<std::uint64_t>();
      out.current_height = result.at("current_height").get<std::uint64_t>();

      const auto& blocks = result.at("blocks");
      out.blocks.reserve(blocks.size());

      for (const auto& entry : blocks)
      {
        cryptonote::rpc::block_with_transactions bwt{};

        const std::string block_blob =
          blob_from_hex(entry.at("block").get<std::string>(), "block");
        if (!cryptonote::parse_and_validate_block_from_blob(block_blob, bwt.block))
          throw std::runtime_error{"Daemon sent an unparseable block blob"};

        const auto& txs = entry.at("transactions");
        bwt.transactions.reserve(txs.size());
        for (const auto& tx_hex : txs)
        {
          const std::string tx_blob =
            blob_from_hex(tx_hex.get<std::string>(), "transaction");

          cryptonote::transaction tx{};
          /* Requests are sent with prune:true, so the daemon returns transaction
             base blobs. Everything the scanner reads - tx pubkey, key offsets,
             key images, output keys, ecdhInfo and outPk - lives in the base. */
          tx.pruned = true;
          if (!cryptonote::parse_and_validate_tx_base_from_blob(tx_blob, tx))
          {
            tx = cryptonote::transaction{};
            if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx))
              throw std::runtime_error{"Daemon sent an unparseable transaction blob"};
          }
          bwt.transactions.push_back(std::move(tx));
        }

        out.blocks.push_back(std::move(bwt));
      }

      out.output_indices =
        result.at("output_indices")
          .get<std::vector<std::vector<std::vector<std::uint64_t>>>>();

      return out;
    }

    static bool is_ipc_uri(const std::string& uri)
    {
      return uri.rfind("ipc://", 0) == 0;
    }

    static bool is_http_uri(const std::string& uri)
    {
      return uri.rfind("http://", 0) == 0 ||
             uri.rfind("https://", 0) == 0;
    }

    // -------------------------------------------------------------------------
    // IPC helper — logs all parts, throws with daemon's error message on failure
    // -------------------------------------------------------------------------
    static std::string ipc_request(
        oxenmq::OxenMQ& lmq,
        oxenmq::ConnectionID& conn,
        const std::string& method,
        const std::string& params_json,
        std::chrono::seconds timeout = std::chrono::seconds{60})
    {
      std::promise<std::string> prom;
      auto fut = prom.get_future();

      lmq.request(
        conn,
        method,
        [&prom, &method](bool success, std::vector<std::string> data)
        {
          try {
            if (!success)
            {
              std::string err = data.empty() ? "(no data)" : data[0];
              throw std::runtime_error{
                "IPC daemon rejected '" + method + "': " + err};
            }
            if (data.size() < 2)
              throw std::runtime_error{
                "IPC response missing body for '" + method + "'"};
            prom.set_value(data[1]);
          } catch (...) {
            prom.set_exception(std::current_exception());
          }
        },
        params_json,
        oxenmq::send_option::request_timeout{timeout}
      );

      if (fut.wait_for(timeout + std::chrono::seconds{30}) != std::future_status::ready)
        throw std::runtime_error{"IPC timeout: " + method};

      return fut.get();
    }

    void checked_wait(const std::chrono::nanoseconds wait)
    {
      static constexpr const std::chrono::milliseconds interval{500};

      const auto start = std::chrono::steady_clock::now();
      while (scanner::is_running())
      {
        const auto current = std::chrono::steady_clock::now() - start;
        if (wait <= current)
          break;
        const auto sleep_time = std::min(wait - current, std::chrono::nanoseconds{interval});
        std::this_thread::sleep_for(std::chrono::nanoseconds{sleep_time.count()});
      }
    }

    //! How often the idle sweep runs when it is enabled.
    constexpr const std::chrono::minutes account_sweep_interval{60};

    /*! Move accounts nobody has touched recently out of the active set.

      Every active account costs a `generate_key_derivation` per transaction per
      block, forever, so a deployment that only ever adds accounts pays a growing
      per-block tax for wallets that were opened once and abandoned. Deactivating
      keeps all of the account's data - a later login reactivates it and resumes
      from its stored height. */
    void sweep_loop(db::storage disk, std::uint64_t idle_timeout)
    {
      if (!idle_timeout)
        return;

      MINFO("Idle account sweep enabled: deactivating accounts untouched for "
        << idle_timeout << "s, checking every "
        << account_sweep_interval.count() << " minute(s)");

      /* `account.access` only became meaningful when the access-time updater was
         added; on an upgraded database it still holds the creation time. Sweeping
         immediately would therefore deactivate the entire user base at once, so
         hold off until a full timeout of real access data has been collected. */
      std::uint64_t tracking_since = 0;
      {
        const auto since = disk.access_tracking_since();
        if (since)
          tracking_since = lmdb::to_native(*since);
        else
          MWARNING("Could not read access-tracking marker: " << since.error().message());
      }

      while (scanner::is_running())
      {
        checked_wait(account_sweep_interval);
        if (!scanner::is_running())
          return;

        try
        {
          const std::int64_t now = unix_now();
          if (now <= std::int64_t(idle_timeout))
            continue; // clock is not sane enough to compute a cutoff

          const std::int64_t eligible_from =
            std::int64_t(tracking_since) + std::int64_t(idle_timeout);
          if (tracking_since && now < eligible_from)
          {
            MINFO("Idle sweep holding off for another " << (eligible_from - now)
              << "s while access times are collected");
            continue;
          }

          const auto cutoff = db::account_time(std::uint32_t(now - std::int64_t(idle_timeout)));
          const auto swept = disk.deactivate_idle(cutoff);
          if (!swept)
          {
            MWARNING("Idle account sweep failed: " << swept.error().message());
            continue;
          }

          registry().note_sweep(swept->size());
          if (!swept->empty())
          {
            MINFO("Idle sweep deactivated " << swept->size()
              << " account(s); they will reactivate on their next login");
          }
        }
        catch (const std::exception& e)
        {
          MERROR("Idle account sweep threw: " << e.what());
        }
      }
    }

    /*! Load an account plus the outputs it can already spend.

      Shared by the initial plan and by the incremental pick-up of accounts that
      appear while scanning is already under way. */
    lws::account load_account(db::storage_reader& reader, db::account const& user)
    {
      std::vector<db::output_id> receives{};
      std::vector<crypto::public_key> pubs{};
      auto receive_list = MONERO_UNWRAP(reader.get_outputs(user.id));

      const std::size_t elems = receive_list.count();
      receives.reserve(elems);
      pubs.reserve(elems);

      for (auto output = receive_list.make_iterator(); !output.is_end(); ++output)
      {
        receives.emplace_back(output.get_value<MONERO_FIELD(db::output, spend_meta.id)>());
        pubs.emplace_back(output.get_value<MONERO_FIELD(db::output, pub)>());
      }
      return lws::account{user, std::move(receives), std::move(pubs)};
    }

    struct by_height
    {
      bool operator()(account const& left, account const& right) const noexcept
      {
        return left.scan_height() < right.scan_height();
      }
    };

    //! \return Height span covered by `group`, which must be sorted by height.
    std::uint64_t group_span(std::vector<lws::account> const& group) noexcept
    {
      if (group.empty())
        return 0;
      return std::uint64_t(group.back().scan_height()) -
             std::uint64_t(group.front().scan_height());
    }

    /*! Split `users` into at most `thread_count` groups of similar scan height.

      Thin wrapper over `plan_scan_groups`, which holds the actual policy and is
      unit tested against plain heights in tests/lws/scan_planner.cpp.

      \pre `0 < thread_count`
      \return Groups, each sorted ascending by scan height, none empty. */
    std::vector<std::vector<lws::account>>
    partition_by_height(std::vector<lws::account> users, std::size_t thread_count, std::uint64_t max_span)
    {
      assert(0 < thread_count);

      std::vector<std::vector<lws::account>> out{};
      if (users.empty())
        return out;

      std::sort(users.begin(), users.end(), by_height{});

      std::vector<std::uint64_t> heights{};
      heights.reserve(users.size());
      for (account const& user : users)
        heights.push_back(std::uint64_t(user.scan_height()));

      const auto plan = plan_scan_groups(heights, thread_count, max_span);
      out.reserve(plan.size());
      for (auto const& group : plan)
      {
        std::vector<lws::account> members{};
        members.reserve(group.size());
        for (const std::size_t index : group)
          members.push_back(std::move(users[index]));
        out.push_back(std::move(members));
      }
      return out;
    }


    void scan_transaction(
        epee::span<lws::account> users,
        const db::block_id height,
        const std::uint64_t timestamp,
      crypto::hash const& tx_hash,
      cryptonote::transaction const& tx,
      std::vector<std::uint64_t> const& out_ids)
    {
      boost::optional<crypto::key_image> locked_key_image;  
      if (cryptonote::txversion::v4_tx_types < tx.version)
        throw std::runtime_error{"Unsupported tx version"};

      cryptonote::tx_extra_pub_key key;
      boost::optional<crypto::hash> prefix_hash;
      boost::optional<cryptonote::tx_extra_nonce> extra_nonce;
      std::pair<std::uint8_t, db::output::payment_id_> payment_id;

      {
        std::vector<cryptonote::tx_extra_field> extra;
        cryptonote::parse_tx_extra(tx.extra, extra);

        size_t pk_index = 0;
        while(true)
        {
          if (!cryptonote::find_tx_extra_field_by_type(extra, key, pk_index++))
          {
            if (pk_index > 1)
              break;
          }
        }

        extra_nonce.emplace();
        if (cryptonote::find_tx_extra_field_by_type(extra, *extra_nonce))
        {
          if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce->nonce, payment_id.second.long_))
            payment_id.first = sizeof(crypto::hash);
        }
        else
          extra_nonce = boost::none;
      } // destruct `extra` vector
      {

        cryptonote::tx_extra_tx_key_image_proofs key_image_proofs;
        get_field_from_tx_extra(tx.extra, key_image_proofs);

        if (!key_image_proofs.proofs.empty())
        {
          // Assign the key_image from the first proof to locked_key_image
          locked_key_image = key_image_proofs.proofs.front().key_image;
        }
      }

      for (account &user : users)
      {
        // std::cout << "entered in users " << std::endl;
        if (height <= user.scan_height())
          continue; // to next user

        crypto::key_derivation derived;
        if (!crypto::wallet::generate_key_derivation(key.pub_key, user.view_key(), derived))
          continue; // to next user

        db::extra ext{};
        std::uint32_t mixin = 0;
        for (auto const& in : tx.vin)
        {
          // std::cout << "entered in vin " << std::endl;
          cryptonote::txin_to_key const* const in_data =
              std::get_if<cryptonote::txin_to_key>(std::addressof(in));
          if (in_data)
          {
            mixin = boost::numeric_cast<std::uint32_t>(
              std::max(std::size_t(1), in_data->key_offsets.size()) - 1
            );

            std::uint64_t goffset = 0;
            for (std::uint64_t offset : in_data->key_offsets)
            {
              goffset += offset;
              if (user.has_spendable(db::output_id{in_data->amount, goffset}))
              {
                user.add_spend(
                    db::spend{
                        db::transaction_link{height, tx_hash},
                        in_data->k_image,
                        db::output_id{in_data->amount, goffset},
                        timestamp,
                        tx.unlock_time,
                        mixin,
                        {0, 0, 0}, // reserved
                        payment_id.first,
                    payment_id.second.long_
                  }
                );
              }
            }
          }
          else if (std::get_if<cryptonote::txin_gen>(std::addressof(in)))
            ext = db::extra(ext | db::coinbase_output);
        }

        std::size_t index = -1;
        for (auto const& out : tx.vout)
        {
          // std::cout << "entered in vout " << std::endl;
          ++index;

          cryptonote::txout_to_key const* const out_data =
              std::get_if<cryptonote::txout_to_key>(std::addressof(out.target));
          if (!out_data)
            continue; // to next output

          crypto::public_key derived_pub;
          const bool received =
              crypto::wallet::derive_subaddress_public_key(out_data->key, derived, index, derived_pub) &&
              derived_pub == user.spend_public();

          if (!received)
            continue; // to next output

          if (!prefix_hash)
          {
            prefix_hash.emplace();
            cryptonote::get_transaction_prefix_hash(tx, *prefix_hash);
          }

          std::uint64_t amount = out.amount;
          
          rct::key mask = rct::identity();
          if (!amount && !(ext & db::coinbase_output) && cryptonote::txversion::v1 < tx.version)
          {
            
            const bool bulletproof2 = true;
            const auto decrypted = lws::decode_amount(
              tx.rct_signatures.outPk.at(index).mask, tx.rct_signatures.ecdhInfo.at(index), derived, index, bulletproof2
            );
            if (!decrypted)
            {
              MWARNING(user.address() << " failed to decrypt amount for tx " << tx_hash << ", skipping output");
              continue; // to next output
            }
            amount = decrypted->first;
            // std::cout << "amount after decrypt : " << amount << std::endl;
            mask = decrypted->second;
            ext = db::extra(ext | db::ringct_output);
          }

          if (extra_nonce)
          {
            if (!payment_id.first && cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce->nonce, payment_id.second.short_))
            {
              payment_id.first = sizeof(crypto::hash8);
              lws::decrypt_payment_id(payment_id.second.short_, derived);
            }
          }

          const bool added = user.add_out(
              db::output{
                  db::transaction_link{height, tx_hash},
                  db::output::spend_meta_{
                      db::output_id{0, out_ids.at(index)},
                      amount,
                      mixin,
                      boost::numeric_cast<std::uint32_t>(index),
                key.pub_key
              },
                  timestamp,
                  tx.unlock_time,
                  *prefix_hash,
                  locked_key_image ? *locked_key_image : crypto::key_image{},
                  out_data->key,
                  mask,
                  {0, 0, 0, 0, 0, 0, 0}, // reserved bytes
                  db::pack(ext, payment_id.first),
                  payment_id.second
            }
          );

          if (!added)
            MWARNING("Output not added, duplicate public key encountered");
        } // for all tx outs
      } // for all users
    }

    // -------------------------------------------------------------------------
    // scan_loop
    //
    // IPC adaptive batch sizing:
    //   This self-tunes to the largest batch the daemon can handle without
    //   timing out, giving throughput close to HTTP.
    // -------------------------------------------------------------------------
    static void scan_loop(thread_sync& self,
                          std::string daemon_rpc,
                          std::shared_ptr<thread_data> data) noexcept
    {
      const std::size_t thread_index = data ? data->index : 0;
      const scanner_options options = data ? data->options : scanner_options{};
      try
      {
        // boost::thread doesn't support move-only types + attributes
        // rpc::client client{std::move(data->client)};
        db::storage disk{std::move(data->disk)};
        std::vector<lws::account> users{std::move(data->users)};

        assert(!users.empty());
        assert(std::is_sorted(users.begin(), users.end(), by_height{}));

        data.reset();

        const std::uint64_t group_low =
          std::uint64_t(users.front().scan_height());
        const std::uint64_t group_high =
          std::uint64_t(users.back().scan_height());

        MINFO("scan[" << thread_index << "] starting: " << users.size()
          << " account(s), heights " << group_low << "-" << group_high
          << " (span " << (group_high - group_low) << ")");

        {
          std::vector<db::account_id> ids{};
          ids.reserve(users.size());
          for (const account& user : users)
            ids.push_back(user.id());
          registry().begin(thread_index, std::move(ids), group_low, group_high);
        }

        struct deregister_
        {
          std::size_t index;
          ~deregister_() noexcept { registry().end(index); }
        } deregister{thread_index};

        struct stop_
        {
          thread_sync& self;
          ~stop_() noexcept
          {
            self.update = true;
            self.user_poll.notify_one();
          }
        } stop{self};

        uint64_t start_height =
            std::max<uint64_t>(1, static_cast<uint64_t>(users.begin()->scan_height()));

        const bool use_ipc = is_ipc_uri(daemon_rpc);

        /* One OxenMQ instance for the process (it is internally threaded and
           thread-safe), but a connection per scan thread. The previous code
           shared a single connection behind a mutex held across the whole
           round trip, which serialised every thread onto one in-flight fetch
           and made --scan-threads meaningless. */
        oxenmq::ConnectionID conn{};
        if (use_ipc)
        {
          oxenmq::OxenMQ& lmq = shared_lmq();
          conn = lmq.connect_remote(
            daemon_rpc,
            [thread_index](oxenmq::ConnectionID) {
              MINFO("scan[" << thread_index << "] IPC connected");
            },
            [thread_index](oxenmq::ConnectionID, std::string_view err) {
              MERROR("scan[" << thread_index << "] IPC connection failed: " << err);
            }
          );
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        /* Blocks requested per batch. Halved on timeout and ramped back up on
           success, so a range of dense blocks does not wedge the loop. */
        std::uint64_t batch_size = options.batch_size;
        unsigned consecutive_successes = 0;

        /* Ask for raw blobs. A daemon that predates the flag rejects the unknown
           request key, in which case we fall back to the legacy JSON transport
           for the rest of this thread's life. */
        bool blob_mode = options.blob_transport;

        // ---- Transport abstraction ----
        auto fetch_blocks = [&](uint64_t height) -> std::string
        {
          if (use_ipc)
          {
            nlohmann::json params = {
              {"start_height", height},
              {"max_count",    batch_size},
              {"prune",        true}
            };
            if (blob_mode)
              params["blob"] = true;

            MDEBUG("scan[" << thread_index << "] fetch height=" << height
              << " max_count=" << batch_size);

            const std::string raw = ipc_request(shared_lmq(), conn,
                                                "rpc.get_blocks_fast",
                                                params.dump(),
                                                std::chrono::seconds{60});

            nlohmann::json wrapped = {
              {"jsonrpc", "2.0"},
              {"id", 0},
              {"result", nlohmann::json::parse(raw)}
            };
            return wrapped.dump();
          }
          else // HTTP
          {
            nlohmann::json request = {
              {"jsonrpc", "2.0"},
              {"id",      "0"},
              {"method",  "get_blocks_fast"},
              {"params",  {{"start_height", height},
                           {"max_count",    batch_size},
                           {"prune",        true}}}
            };
            if (blob_mode)
              request["params"]["blob"] = true;

            auto response = cpr::Post(
              cpr::Url{daemon_rpc},
              cpr::Body{request.dump()},
              cpr::Header{{"Content-Type", "application/json"}}
            );

            if (response.text.empty())
              throw std::runtime_error{"Block retrieval timeout,HTTP daemon connection failed"};

            return response.text;
          }
        };

        // ---- Main scan loop ----
        std::vector<crypto::hash> blockchain{};
        json details;

        unsigned consecutive_failures = 0;

        while (!self.update && scanner::is_running())
        {
          try
          {
          blockchain.clear();

          stopwatch timer{};
          std::string raw_response = fetch_blocks(start_height);
          const std::int64_t fetch_ms = timer.lap();

          json res = json::parse(raw_response);
          details = res["result"];
          if(details["status"]=="Failed")
          {
            throw std::runtime_error{"Daemon unexpectedly returned zero blocks and status failed"};
          }

          fetched_batch fetched{};
          std::map<uint, crypto::hash> heightWithHash;

          if (details.value("blob", false))
          {
            /* Fast path: the daemon handed back raw blobs. Deserialise them and
               skip the whole JSON reshaping block below. The miner tx hash that
               `minor_tx_hashes` carries in the legacy path is recomputed locally
               from the exact block blob instead. */
            fetched = parse_blob_batch(details);
          }
          else
          {
          if (blob_mode)
          {
            MWARNING("scan[" << thread_index << "] daemon did not honour blob mode,"
              << " falling back to the legacy JSON transport");
            blob_mode = false;
          }
          // ---- Parse minor_tx_hashes ----
          if (details.contains("minor_tx_hashes") &&
              !details["minor_tx_hashes"].is_null())
          {
            json minorTxHashes = details["minor_tx_hashes"];
          // std::cout<<"details  :: "<<details["minor_tx_hashes"]<<std::endl;
          details.erase("minor_tx_hashes");

          for (const auto& it : minorTxHashes)
          {
            if (it.is_array() && it.size() == 2)
            {
              uint h = it[0].get<uint>();
              std::string mHash = it[1].get<std::string>();
              crypto::hash minorHash;
              tools::hex_to_type(mHash, minorHash);
              heightWithHash[h] = minorHash;
            }
            else
              throw std::runtime_error("Invalid format in minor_tx_hashes entry");
            }
          }
          else
          {
            if (details.contains("minor_tx_hashes"))
              details.erase("minor_tx_hashes");
          }

          // ---- Parse output_indices ----
          if (details["output_indices"].is_string())
          {
            std::string s = details["output_indices"];
            details["output_indices"] = json::parse(s);
          }

          // ---- Parse blocks ----
          int ch =0;
          for (auto& t : details["blocks"])
          {
            if (t["block"].is_string())
            {
              std::string blk_str = t["block"];
              t["block"] = json::parse(blk_str);
            }
            if(!t["block"]["miner_tx"].contains("rct_signatures"))
            {
              t["block"]["miner_tx"]["rct_signatures"]["type"] = 0;
            }
            json tx_hash_arr;
            int tx_num = 0;
            for(auto data :t["block"]["tx_hashes"])
            {
              if(!data.is_null())
                tx_hash_arr[tx_num] = data;
              tx_num++;
            }
            t["block"]["tx_hashes"] = tx_hash_arr;

            for (auto& data : t["transactions"])
            {
              if (data.is_string())
              {
                std::string tx_str = data;
                data = json::parse(tx_str);
              }

              if (!data.empty())
              {
                for (auto& it : data["rct_signatures"]["ecdhInfo"])
                {
                  it["mask"] = "0000000000000000000000000000000000000000000000000000000000000000";
                      std::string s1=it["amount"];
                      if (s1.length()!=64)
                  {
                      s1 = s1+"000000000000000000000000000000000000000000000000";
                      it["amount"]= s1;
                  }

                }
                  if(data["rct_signatures"].is_null())
                {
                  data["rct_signatures"] = json::value_t::object;
                }
              }
            }

            if(t["block"]["tx_hashes"].size() == 0 || t["transactions"].size() == 0)
            {
              t["transactions"] = json::array();
              t["block"]["tx_hashes"] = json::array();
            }
            if(t["transactions"].size() != (details["output_indices"][ch].size()-1))
            {
              json indis;
              for (auto& it : details["output_indices"][ch])
              {
                if (!it.empty())
                  indis.push_back(it);
              }
              details["output_indices"][ch] = indis;
            }
            ch++;
          }
          // std::cout << "entered in" << std::endl;
          // std::cout <<"detat: "<< details << std::endl;
          json final_res = {{"jsonnrpc", "2.0"}, {"id", 0}, {"result",details}};
          // final_res["result"].erase("status");
          // final_res["result"].erase("untrusted");
          std::string resp = final_res.dump();

          auto decoded = MONERO_UNWRAP(wire::json::from_bytes<rpc::json<rpc::get_blocks_fast>::response>(std::move(resp)));
          fetched.blocks         = std::move(decoded.result.blocks);
          fetched.output_indices = std::move(decoded.result.output_indices);
          fetched.start_height   = decoded.result.start_height;
          fetched.current_height = decoded.result.current_height;
          } // legacy JSON transport

          const std::int64_t parse_ms = timer.lap();

          if (fetched.blocks.empty())
            throw std::runtime_error{"Daemon unexpectedly returned zero blocks"};

          if (fetched.start_height != start_height)   //req.start_height
          {
            MWARNING("Daemon sent wrong blocks, resetting state");
            return;
          }

          // prep for next blocks retrieval
          start_height = fetched.start_height + fetched.blocks.size() - 1;
          // block_request = rpc::client::make_message("get_blocks_fast", req);

          if (fetched.blocks.size() <= 1)
          {
            MINFO("At chain tip, waiting for next block...");
            std::this_thread::sleep_for(10s);
            continue; // to next get_blocks_fast read
          }

          if (fetched.blocks.size() != fetched.output_indices.size())
            throw std::runtime_error{"Bad daemon response - need same number of blocks and indices"};

          blockchain.push_back(cryptonote::get_block_hash(fetched.blocks.front().block));

          const std::uint64_t batch_first = fetched.start_height;

          auto blocks = epee::to_span(fetched.blocks);
          auto indices = epee::to_span(fetched.output_indices);

          if (fetched.start_height != 1)
          {
            // skip overlap block
            blocks.remove_prefix(1);
            indices.remove_prefix(1);
          }
          else
            fetched.start_height = 0;

          for (auto block_data : boost::combine(blocks, indices))
          {
            ++(fetched.start_height);

            cryptonote::block const& block = boost::get<0>(block_data).block;
            auto const& txes              = boost::get<0>(block_data).transactions;

            if (block.tx_hashes.size() != txes.size())
              throw std::runtime_error{
                "Bad daemon response - need same number of txes and tx hashes"};

            auto local_indices = epee::to_span(boost::get<1>(block_data));
            if (local_indices.empty())
              throw std::runtime_error{
                "Bad daemon response - missing coinbase tx indices"};

            crypto::hash miner_tx_hash;
            if (!cryptonote::get_transaction_hash(block.miner_tx, miner_tx_hash))
              throw std::runtime_error{"Failed to calculate miner tx hash"};

            const crypto::hash& block_hash =
                heightWithHash.count(fetched.start_height)
                  ? heightWithHash[fetched.start_height]
                  : miner_tx_hash;

            scan_transaction(
              epee::to_mut_span(users),
              db::block_id(fetched.start_height),
              block.timestamp,
              block_hash,
              block.miner_tx,
              *(local_indices.begin())
            );

            local_indices.remove_prefix(1);

            if (txes.size() != local_indices.size())
              throw std::runtime_error{
                "Bad daemon response - need same number of txes and indices"};

            for (auto tx_data : boost::combine(block.tx_hashes, txes, local_indices))
            {
              scan_transaction(
                  epee::to_mut_span(users),
                  db::block_id(fetched.start_height),
                  block.timestamp,
                  boost::get<0>(tx_data),
                  boost::get<1>(tx_data),
                  boost::get<2>(tx_data)
                );
            }

            blockchain.push_back(cryptonote::get_block_hash(block));
          }

          const std::int64_t scan_ms = timer.lap();

          expect<db::update_outcome> updated = disk.update(
            users.front().scan_height(), epee::to_span(blockchain), epee::to_span(users)
          );
          const std::int64_t commit_ms = timer.lap();

          if (!updated)
          {
            if (updated == lws::error::blockchain_reorg)
            {
              /* The blocks these accounts were scanned against are no longer on
                 the chain. Drop everything at or above the batch start so the
                 re-plan rescans the replacement blocks. */
              MWARNING("scan[" << thread_index << "] blockchain reorg detected at height "
                << batch_first << ", rolling back");
              const expect<void> rolled = disk.rollback(db::block_id(batch_first));
              if (!rolled)
                MERROR("scan[" << thread_index << "] rollback failed: " << rolled.error().message());
              registry().note_restart("blockchain reorg");
              return;
            }
            MONERO_THROW(updated.error(), "Failed to update accounts on disk");
          }

          const std::int64_t total_ms = fetch_ms + parse_ms + scan_ms + commit_ms;
          const std::uint64_t batch_last = fetched.start_height;
          const double blocks_per_sec = total_ms > 0
            ? (double(blocks.size()) * 1000.0) / double(total_ms)
            : 0.0;

          MINFO("scan[" << thread_index << "] blocks " << batch_first << "-" << batch_last
            << " (" << blocks.size() << ") in " << total_ms << "ms"
            << " [fetch " << fetch_ms << " parse " << parse_ms
            << " scan " << scan_ms << " commit " << commit_ms << "]"
            << " " << std::uint64_t(blocks_per_sec) << " blk/s"
            << " | accounts " << updated->advanced.size() << " advanced, "
            << updated->unchanged.size() << " already ahead, "
            << updated->diverged.size() << " diverged");

          /* The batch offered a height below what the account already had, and
             the write was refused. This is expected when a group spans heights -
             the batch simply did not reach the accounts near the top of it - so
             it is a warning rather than an error. Seeing it every batch means
             the plan is mixing accounts that are far apart, which is what
             `--max-group-span` exists to prevent. */
          for (const auto& bad : updated->regressions)
          {
            MWARNING("scan[" << thread_index << "] kept account "
              << lmdb::to_native(bad.id) << " at height " << std::uint64_t(bad.old_height)
              << "; this batch only reached " << std::uint64_t(bad.new_height)
              << " (group spans heights - lower --max-group-span if persistent)");
          }

          // MDEBUG is compiled out / short-circuited unless the level is enabled
          for (const auto& moved : updated->advanced)
          {
            MDEBUG("scan[" << thread_index << "] account " << lmdb::to_native(moved.id)
              << ": " << std::uint64_t(moved.old_height)
              << " -> " << std::uint64_t(moved.new_height));
          }

          if (!updated->diverged.empty())
          {
            MWARNING("scan[" << thread_index << "] " << updated->diverged.size()
              << " of " << users.size() << " account(s) changed underneath this thread"
              << " (ids " << format_ids(updated->diverged) << "), resetting");
            registry().note_restart("accounts changed underneath a scan thread");
            return;
          }

          for (account& user : users)
            user.updated(db::block_id(fetched.start_height));

          registry().progress(
            thread_index, batch_last, blocks.size(), blocks_per_sec, std::uint64_t(total_ms)
          );
          registry().note_daemon_height(fetched.current_height);

          // batch succeeded - ramp the request size back up if it was reduced
          consecutive_failures = 0;
          if (batch_size < options.batch_size && batch_ramp_after <= ++consecutive_successes)
          {
            consecutive_successes = 0;
            batch_size = std::min(options.batch_size, batch_size * 2);
            MINFO("scan[" << thread_index << "] batch size raised to " << batch_size);
          }
          }
          catch (std::exception const& e)
          {
            /* A bad batch is not a reason to take the process down. Shrink the
               request, wait, and try the same height again. Only a thread that
               cannot make progress at all eventually gives up and lets
               `check_loop` re-plan from disk. */
            ++consecutive_failures;
            consecutive_successes = 0;

            if (min_batch_size < batch_size)
            {
              batch_size = std::max(min_batch_size, batch_size / 2);
              MWARNING("scan[" << thread_index << "] batch size reduced to " << batch_size);
            }

            const auto backoff = std::min(
              std::chrono::seconds{max_scan_backoff},
              std::chrono::seconds{1} * (1u << std::min(consecutive_failures, 6u))
            );

            MERROR("scan[" << thread_index << "] batch at height " << start_height
              << " failed (" << consecutive_failures << " in a row): " << e.what()
              << " - retrying in " << backoff.count() << "s");

            registry().failure(thread_index, e.what(), consecutive_failures);

            if (max_consecutive_failures <= consecutive_failures)
            {
              MERROR("scan[" << thread_index << "] giving up after "
                << consecutive_failures << " consecutive failures; "
                << "accounts will be re-planned from disk");
              registry().note_restart("scan thread exhausted retries");
              return;
            }

            checked_wait(backoff);
            continue;
          }

        } // while scan loop
      }
      catch (std::exception const& e)
      {
        /* Reached only for failures outside the retry arm - a moved-from account,
           an LMDB failure, a bad_alloc. Let the thread die; `scanner::run` will
           re-read the account list and start over. */
        MERROR("scan[" << thread_index << "] thread aborted: " << e.what());
      }
      catch (...)
      {
        MERROR("scan[" << thread_index << "] thread aborted: unknown exception");
      }
    }

    /*!
      Launches `thread_count` threads to run `scan_loop`, and then polls for
      active account changes in background
    */
    void check_loop(db::storage disk, scanner_options options, std::string daemon_rpc,std::vector<lws::account> users, std::vector<db::account_id> active)
    {
      const std::size_t thread_count = options.thread_count;
      assert(0 < thread_count);
      assert(0 < users.size());
      // std::cout << "thread_count : " << thread_count << std::endl;
      // std::cout << "users.size() : " << users.size() << std::endl;
      thread_sync self{};
      std::vector<boost::thread> threads{};

      struct join_
      {
        thread_sync& self;
        std::vector<boost::thread>& threads;
        // rpc::context& ctx;

        ~join_() noexcept
        {
          self.update = true;
          // ctx.raise_abort_scan();
          for (auto& thread : threads)
            thread.join();
        }
      } join{self, threads/*, ctx*/};

      /*
        Accounts are grouped into narrow scan-height bands rather than into equal
        sized buckets. Every account in a group advances from the group's lowest
        height, so mixing a far-behind account with synced ones stalls the synced
        ones for as long as the laggard takes to catch up. `partition_by_height`
        keeps that span bounded and gives laggards their own thread.

        Each thread still works independently rather than cooperatively. Sharing
        fetched blocks between threads would cut daemon traffic and LMDB write
        pressure, but needs more synchronisation, so it is left for later.

        New accounts appearing mid-pass are handed to a spare thread rather than
        triggering a teardown - see the poll loop below. Only a removal, or an
        exhausted thread budget, re-plans everything.
      */

      boost::thread::attributes attrs;
      attrs.set_stack_size(5 * 1024 * 1024);

      const std::size_t total_users = users.size();
      registry().clear_threads();

      // hold a couple of threads back so later arrivals do not force a re-plan
      const std::size_t planned_threads =
        (pickup_reserve < thread_count) ? thread_count - pickup_reserve : thread_count;
      auto groups =
        partition_by_height(std::move(users), planned_threads, options.max_group_span);

      // room for the initial groups plus any picked up while scanning
      threads.reserve(thread_count);
      MINFO("Starting scan loops on " << groups.size() << " thread(s) with "
        << total_users << " account(s); " << (thread_count - groups.size())
        << " thread(s) held back for accounts that appear later");

      for (std::size_t i = 0; i < groups.size(); ++i)
      {
        auto& group = groups[i];
        assert(!group.empty());

        const std::uint64_t low = std::uint64_t(group.front().scan_height());
        const std::uint64_t span = group_span(group);
        if (options.max_group_span < span)
        {
          /* Only reachable when there are more distinct bands than threads, so
             bands had to be merged. Say so - it is the condition that makes
             accounts appear stuck. */
          MWARNING("scan[" << i << "] group spans " << span
            << " blocks (" << group.size() << " accounts from height " << low
            << "); accounts near the top of this group will not advance until the"
            << " lowest catches up. Consider raising --scan-threads or lowering"
            << " --max-group-span");
        }

        auto data = std::make_shared<thread_data>(disk.clone(), std::move(group), i, options);
        threads.emplace_back(attrs, std::bind(&scan_loop, std::ref(self), daemon_rpc, std::move(data)));
      }

      auto last_check = std::chrono::steady_clock::now();

      lmdb::suspended_txn read_txn{};
      db::cursor::accounts accounts_cur{};
      boost::unique_lock<boost::mutex> lock{self.sync};

      while (scanner::is_running())
      {
        for (;;)
        {
          //! \TODO use signalfd + ZMQ? Windows is the difficult case...
          // self.user_poll.wait_for(lock, boost::chrono::seconds{1});
          std::this_thread::sleep_for(1s);
          if (self.update || !scanner::is_running())
            return;
          auto this_check = std::chrono::steady_clock::now();
          if (account_poll_interval <= (this_check - last_check))
          {
            last_check = this_check;
            break;
          }
        }

        auto reader = disk.start_read(std::move(read_txn));
        if (!reader)
        {
          if (reader.matches(std::errc::no_lock_available))
          {
            MWARNING("Failed to open DB read handle, retrying later");
            continue;
          }
          MONERO_THROW(reader.error(), "Failed to open DB read handle");
        }

        auto current_users = MONERO_UNWRAP(
          reader->get_accounts(db::account_status::active, std::move(accounts_cur))
        );

        /* Classify the change instead of tearing everything down for it.

           A purely additive change - which is what every new wallet login is -
           does not invalidate the work the running threads are doing, so those
           accounts are handed to a new thread and the existing ones are left
           alone. Only a removal (or a status change) actually invalidates the
           current plan, because a running thread would keep scanning for an
           account that is no longer active. Polling every
           `account_poll_interval` also means a burst of logins costs one
           pick-up rather than one teardown each. */
        std::vector<db::account> added{};
        std::size_t current_count = 0;

        for (auto user = current_users.make_iterator(); !user.is_end(); ++user)
        {
          ++current_count;
          const db::account_id user_id = user.get_value<MONERO_FIELD(db::account, id)>();
          if (!std::binary_search(active.begin(), active.end(), user_id))
            added.push_back(*user);
        }

        const bool removals = (current_count - added.size()) != active.size();
        if (removals)
        {
          registry().note_restart("active accounts were removed or changed status");
          MINFO("Active accounts removed (" << active.size() << " -> " << current_count
            << "), re-planning scan threads...");
          return;
        }

        if (!added.empty())
        {
          if (thread_count <= threads.size())
          {
            /* No spare thread to hand them to. Re-plan, which redistributes
               everything - the expensive path, but now only reached when the
               thread budget is genuinely exhausted. */
            registry().note_restart("no spare scan thread for " + std::to_string(added.size()) + " new account(s)");
            MINFO(added.size() << " new account(s) and no spare scan thread, re-planning...");
            return;
          }

          std::vector<lws::account> new_users{};
          new_users.reserve(added.size());
          for (db::account const& user : added)
          {
            new_users.push_back(load_account(*reader, user));
            active.insert(
              std::lower_bound(active.begin(), active.end(), user.id), user.id
            );
          }
          std::sort(new_users.begin(), new_users.end(), by_height{});

          const std::size_t index = threads.size();
          const std::uint64_t low = std::uint64_t(new_users.front().scan_height());
          const std::uint64_t high = std::uint64_t(new_users.back().scan_height());

          MINFO("Picked up " << new_users.size() << " new account(s) on scan[" << index
            << "] at heights " << low << "-" << high
            << "; existing scan threads left running");

          auto data = std::make_shared<thread_data>(disk.clone(), std::move(new_users), index, options);
          threads.emplace_back(attrs, std::bind(&scan_loop, std::ref(self), daemon_rpc, std::move(data)));
        }

        read_txn = reader->finish_read();
        accounts_cur = current_users.give_cursor();
      } // while scanning
    }

  } // anonymous 

  // ---------------------------------------------------------------------------
  // scanner::sync
  // ---------------------------------------------------------------------------
  void scanner::sync(db::storage disk, std::string daemon_rpc)
  {
    MINFO("Starting blockchain sync with daemon");

    const bool use_ipc = is_ipc_uri(daemon_rpc);

    static oxenmq::ConnectionID conn;
    static bool lmq_started = false;

    if (use_ipc && !lmq_started)
    {
      conn = shared_lmq().connect_remote(
        daemon_rpc,
        [](oxenmq::ConnectionID) { MINFO("chain sync: IPC connected"); },
        [](oxenmq::ConnectionID, std::string_view err) {
          MERROR("chain sync: IPC connection failed: " << err);
        }
      );
      lmq_started = true;
    }

    try
    {
      json details;
        int a =0;
      std::vector<crypto::hash> blk_ids;

      {
        auto reader = disk.start_read();
        if (!reader)
          throw std::runtime_error("DB read failed");

        auto chain = reader->get_chain_sync();
        if (!chain)
          throw std::runtime_error("Failed to get chain height");

        a = *chain;
        MINFO("Last_height_from Db : " << a);
      }

      for (;;)
      {
        json response_json;

        if (!use_ipc)
        {
          json request = {
            {"jsonrpc", "2.0"},
            {"id",      "0"},
            {"method",  "get_hashes"},
            {"params",  {{"start_height", a}}}
          };

          auto response = cpr::Post(
            cpr::Url{daemon_rpc},
            cpr::Body{request.dump()},
            cpr::Header{{"Content-Type", "application/json"}}
          );

          if (response.text.empty())
            throw std::runtime_error{"daemon connection failed"};

          response_json = json::parse(response.text);

          if (!response_json.contains("result"))
            throw std::runtime_error("Invalid JSON-RPC response");

          details = response_json["result"];
        }
        else
        {
          json params = {{"start_height", a}};
          std::string result = ipc_request(shared_lmq(), conn, "rpc.get_hashes",
                                           params.dump(),
                                           std::chrono::seconds{10});
          details = json::parse(result);
        }

            if(details["status"]=="Failed")
        {
          throw std::runtime_error{"Daemon unexpectedly returned zero hashes and status failed"};
        }
        for (auto block_data : details["m_block_ids"])
        {
          std::string id = block_data;
          tools::hex_to_type(id, blk_ids.emplace_back());
        }

        int block_ids_size = details["m_block_ids"].size();
        int start_height = details["start_height"];
        int current_height = details["current_height"];

        if (blk_ids.size() <= 1 || (current_height - start_height) <= 1)
        {
          MINFO("synced daemon upto the top chain");
          break;
        }

        disk.sync_chain(db::block_id(details["start_height"]), epee::to_span(blk_ids));
        blk_ids.clear();
        a = block_ids_size + start_height - 1;
      }
    }
    catch (const std::exception& e)
    {
      /* Chain sync is best-effort: it only maintains the local block-hash index.
         Failing it must not stop scanning - the next pass retries. */
      MERROR("Chain sync failed, will retry: " << e.what());
    }
    catch (...)
    {
      MERROR("Chain sync failed, will retry: unknown exception");
    }
  }

  // ---------------------------------------------------------------------------
  // scanner::run — unchanged
  // ---------------------------------------------------------------------------
   void scanner::run(db::storage disk, std::string daemon_rpc, scanner_options options)
  {
    options.thread_count = std::max(std::size_t(1), options.thread_count);
    options.batch_size = std::max(min_batch_size, options.batch_size);
    unsigned short_passes = 0;

    boost::thread sweeper{};
    struct join_sweeper
    {
      boost::thread& thread;
      ~join_sweeper() noexcept { if (thread.joinable()) thread.join(); }
    } join_sweeper_guard{sweeper};

    if (options.account_idle_timeout)
    {
      // db::storage is move-only, so std::bind cannot carry it
      const std::uint64_t idle_timeout = options.account_idle_timeout;
      sweeper = boost::thread{
        [store = disk.clone(), idle_timeout] () mutable
        { sweep_loop(std::move(store), idle_timeout); }
      };
    }

    MINFO("Scanner starting: " << options.thread_count << " thread(s), batch "
      << options.batch_size << " block(s), max group span " << options.max_group_span
      << ", transport " << (options.blob_transport ? "blob" : "json"));

    for (;;)
    {
      const auto last = std::chrono::steady_clock::now();

      std::vector<db::account_id> active;
      std::vector<lws::account>   users;

      {
        MINFO("Retrieving current active account list");

        auto reader   = MONERO_UNWRAP(disk.start_read());
        auto accounts = MONERO_UNWRAP(reader.get_accounts(db::account_status::active));

        for (db::account user : accounts.make_range())
        {
          users.push_back(load_account(reader, user));
          active.insert(
            std::lower_bound(active.begin(), active.end(), user.id), user.id
          );
        }

        reader.finish_read();
      } // cleanup DB reader

      if (users.empty())
      {
        MINFO("No active accounts");
        checked_wait(account_poll_interval - (std::chrono::steady_clock::now() - last));
      }
      else
        check_loop(disk.clone(), options, daemon_rpc, std::move(users), std::move(active));

      if (!scanner::is_running())
        return;

      /* If a whole pass collapsed immediately, something upstream is wrong (the
         daemon is down, or every batch is failing). Back off before re-planning
         so the log stays readable and the daemon is not hammered. */
      const auto pass_duration = std::chrono::steady_clock::now() - last;
      if (pass_duration < min_healthy_pass)
      {
        ++short_passes;
        const auto backoff = std::min(
          std::chrono::seconds{max_scan_backoff},
          std::chrono::seconds{1} * (1u << std::min(short_passes, 6u))
        );
        MWARNING("Scan pass ended after "
          << std::chrono::duration_cast<std::chrono::milliseconds>(pass_duration).count()
          << "ms; restarting in " << backoff.count() << "s");
        checked_wait(backoff);
      }
      else
        short_passes = 0;

      sync(disk.clone(), daemon_rpc);
    }
  }

} // namespace lws