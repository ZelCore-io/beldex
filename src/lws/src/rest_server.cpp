#include "rest_server.h"

#include <ctime>
#include "scanner.h"
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include <algorithm>
#include <boost/utility/string_ref.hpp>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <cpr/cpr.h>

#include "common/error.h"                       // beldex/src
#include "common/hex.h"
#include "common/expect.h"
#include "crypto/crypto.h"                      // beldex/src
#include "cryptonote_config.h"                  // beldex/src
#include "lmdb/util.h"                          // beldex/src
#include "rpc/core_rpc_server_commands_defs.h"  // beldex/src

#include "error.h"
#include "db/data.h"
#include "db/storage.h"
#include "rpc/admin.h"
#include "rpc/client.h"
#include "util/http_server.h"
#include "util/gamma_picker.h"
#include "util/random_outputs.h"
#include "util/source_location.h"
#include "wire/crypto.h"
#include "rpc/light_wallet.h"
#include "wire/json.h"
#include "wire/vector.h"
#include "config.h"
namespace lws
{
  void write_bytes(wire::json_writer& dest, const scan_thread_status& self)
  {
    std::vector<std::uint64_t> accounts{};
    accounts.reserve(self.accounts.size());
    for (const db::account_id id : self.accounts)
      accounts.push_back(lmdb::to_native(id));

    wire::object(dest,
      wire::field("index", self.index),
      wire::field("alive", self.alive),
      wire::field("accounts", std::move(accounts)),
      wire::field("group_low", self.group_low),
      wire::field("group_high", self.group_high),
      wire::field("group_span", std::uint64_t(self.group_high - self.group_low)),
      wire::field("current_height", self.current_height),
      wire::field("blocks_scanned", self.blocks_scanned),
      wire::field("blocks_per_second", std::uint64_t(self.blocks_per_second)),
      wire::field("last_batch_ms", self.last_batch_ms),
      wire::field("last_commit", self.last_commit),
      wire::field("seconds_since_commit",
        self.last_commit ? std::int64_t(std::time(nullptr)) - self.last_commit : std::int64_t(-1)),
      wire::field("consecutive_failures", std::uint64_t(self.consecutive_failures)),
      wire::field("last_error", std::cref(self.last_error))
    );
  }

  void write_bytes(wire::json_writer& dest, const scanner_status& self)
  {
    std::uint64_t lowest = 0;
    bool have_lowest = false;
    for (const auto& thread : self.threads)
    {
      if (!thread.alive)
        continue;
      if (!have_lowest || thread.current_height < lowest)
      {
        lowest = thread.current_height;
        have_lowest = true;
      }
    }

    wire::object(dest,
      wire::field("running", self.running),
      wire::field("daemon_height", self.daemon_height),
      wire::field("lowest_scan_height", lowest),
      wire::field("blocks_behind",
        (self.daemon_height > lowest) ? self.daemon_height - lowest : std::uint64_t(0)),
      wire::field("restarts", self.restarts),
      wire::field("accounts_deactivated", self.deactivated),
      wire::field("last_sweep", self.last_sweep),
      wire::field("last_restart", self.last_restart),
      wire::field("last_restart_reason", std::cref(self.last_restart_reason)),
      wire::field("threads", std::cref(self.threads))
    );
  }

  namespace
  {
    namespace http = epee::net_utils::http;

    struct context : epee::net_utils::connection_context_base
    {
      context()
          : epee::net_utils::connection_context_base()
      {}
    };

    bool is_hidden(db::account_status status) noexcept
    {
      switch (status)
      {
      case db::account_status::active:
      case db::account_status::inactive:
        return false;
      default:
      case db::account_status::hidden:
        break;
      }
      return true;
    }

    /*! \return The best known chain tip.

      The local `blocks` table only reflects what the scanner has committed, so
      on its own it under-reports the tip to wallets. The scanner also records
      the `current_height` the daemon reported on its last batch; take whichever
      is further along. */
    std::uint64_t best_chain_height(const db::block_info& last) noexcept
    {
      return std::max(std::uint64_t(last.id), lws::scanner::status().daemon_height);
    }

    bool is_locked(std::uint64_t unlock_time, db::block_id last) noexcept
    {
      if (unlock_time > cryptonote::MAX_BLOCK_NUMBER)
        return std::chrono::seconds{unlock_time} > std::chrono::system_clock::now().time_since_epoch();
      return db::block_id(unlock_time) > last;
    }

    bool key_check(const rpc::account_credentials& creds)
    {
      crypto::public_key verify{};
      if (!crypto::secret_key_to_public_key(creds.key, verify))
        return false;
      if (verify != creds.address.view_public)
        return false;
      return true;
    }

    std::vector<db::output::spend_meta_>::const_iterator
    find_metadata(std::vector<db::output::spend_meta_> const& metas, db::output_id id)
    {
      struct by_output_id
      {
        bool operator()(db::output::spend_meta_ const& left, db::output_id right) const noexcept
        {
          return left.id < right;
        }
        bool operator()(db::output_id left, db::output::spend_meta_ const& right) const noexcept
        {
          return left < right.id;
        }
      };
      return std::lower_bound(metas.begin(), metas.end(), id, by_output_id{});
    }

    expect<json> post_json_rpc(std::string method, json params = json::object())
    {
      json request_body = {
        {"jsonrpc", "2.0"},
        {"id", "0"},
        {"method", std::move(method)}
      };
      if (!params.empty())
        request_body["params"] = std::move(params);

      auto response = cpr::Post(
        cpr::Url{lws::daemon_add},
        cpr::Body{request_body.dump()},
        cpr::Header{{"Content-Type", "application/json"}}
      );

      if (response.status_code != 200)
      {
        MERROR("daemon RPC call failed with HTTP code: " << response.status_code);
        return make_error_code(std::errc::io_error);
      }

      try
      {
        json parsed = json::parse(response.text);
        return parsed;
      }
      catch (const std::exception& e)
      {
        MERROR("daemon RPC JSON parse failed: " << e.what());
        return make_error_code(std::errc::invalid_argument);
      }
    }

    /*! Master node lock data, indexed for lookup.

      The wallet endpoints below need to answer "is this output locked into a
      master node?" once per output. Walking the blacklist and then every
      contributor of every master node for each output made those endpoints
      quadratic in the size of the node list; these maps are built once per cache
      refresh instead. */
    struct master_node_cache
    {
      json master_nodes;
      json blacklist;

      //! Blacklisted key image -> locked amount.
      std::unordered_map<crypto::key_image, std::uint64_t> blacklisted;
      //! Wallet address -> its locked contributions, keyed by key image.
      std::unordered_map<
        std::string, std::unordered_map<crypto::key_image, std::uint64_t>
      > locked_contributions;

      //! \return The contribution locked against `image` for `address`, if any.
      boost::optional<std::uint64_t>
      contribution_amount(const std::string& address, const crypto::key_image& image) const
      {
        const auto by_address = locked_contributions.find(address);
        if (by_address == locked_contributions.end())
          return boost::none;

        const auto contribution = by_address->second.find(image);
        if (contribution == by_address->second.end())
          return boost::none;
        return contribution->second;
      }

      /*! \return The amount locked against `image` for `address`, or nothing.
          Blacklist first, matching the original ordering. */
      boost::optional<std::uint64_t>
      locked_amount(const std::string& address, const crypto::key_image& image) const
      {
        const auto blacklisted_entry = blacklisted.find(image);
        if (blacklisted_entry != blacklisted.end())
          return blacklisted_entry->second;
        return contribution_amount(address, image);
      }

      /*! \return True if `image` is locked for exactly `amount`.

          Both sources are checked independently rather than short-circuiting on
          the blacklist, because the original code fell through to the
          contributor list whenever the blacklisted amount did not match. */
      bool locks_exactly(const std::string& address, const crypto::key_image& image, std::uint64_t amount) const
      {
        const auto blacklisted_entry = blacklisted.find(image);
        if (blacklisted_entry != blacklisted.end() && blacklisted_entry->second == amount)
          return true;

        const auto contribution = contribution_amount(address, image);
        return bool(contribution) && *contribution == amount;
      }
    };

    //! Populate the lookup maps in `cache` from its freshly fetched JSON.
    void index_master_node_cache(master_node_cache& cache)
    {
      cache.blacklisted.clear();
      cache.locked_contributions.clear();

      const auto blacklist = cache.blacklist.find("result");
      if (blacklist != cache.blacklist.end())
      {
        const auto entries = blacklist->find("blacklist");
        if (entries != blacklist->end() && entries->is_array())
        {
          for (const auto& entry : *entries)
          {
            crypto::key_image image{};
            const auto image_hex = entry.find("key_image");
            const auto amount = entry.find("amount");
            if (image_hex == entry.end() || amount == entry.end())
              continue;
            if (!tools::hex_to_type(image_hex->get<std::string>(), image))
            {
              MWARNING("Skipping unparseable blacklist key image");
              continue;
            }
            cache.blacklisted.emplace(image, amount->get<std::uint64_t>());
          }
        }
      }

      const auto nodes = cache.master_nodes.find("result");
      if (nodes == cache.master_nodes.end())
        return;
      const auto states = nodes->find("master_node_states");
      if (states == nodes->end() || !states->is_array())
        return;

      for (const auto& node : *states)
      {
        const auto contributors = node.find("contributors");
        if (contributors == node.end() || !contributors->is_array())
          continue;

        for (const auto& contributor : *contributors)
        {
          const auto address = contributor.find("address");
          const auto contributions = contributor.find("locked_contributions");
          if (address == contributor.end() || contributions == contributor.end())
            continue;
          if (!contributions->is_array())
            continue;

          auto& by_image = cache.locked_contributions[address->get<std::string>()];
          for (const auto& contribution : *contributions)
          {
            crypto::key_image image{};
            const auto image_hex = contribution.find("key_image");
            const auto amount = contribution.find("amount");
            if (image_hex == contribution.end() || amount == contribution.end())
              continue;
            if (!tools::hex_to_type(image_hex->get<std::string>(), image))
              continue;
            by_image.emplace(image, amount->get<std::uint64_t>());
          }
        }
      }
    }

    expect<master_node_cache> get_master_node_cache()
    {
      static constexpr const auto cache_ttl = std::chrono::seconds{10};
      static std::mutex cache_mutex;
      static master_node_cache cache{};
      static auto last_update = std::chrono::steady_clock::now();
      static bool cache_initialized = false;

      const auto now = std::chrono::steady_clock::now();
      {
        const std::lock_guard<std::mutex> lock{cache_mutex};
        if (cache_initialized && now - last_update < cache_ttl)
          return cache;
      }

      auto master_nodes = post_json_rpc("get_master_nodes");
      if (!master_nodes)
        return master_nodes.error();

      auto blacklist = post_json_rpc("get_master_node_blacklisted_key_images");
      if (!blacklist)
        return blacklist.error();

      const std::lock_guard<std::mutex> lock{cache_mutex};
      if (master_nodes->is_array() && !master_nodes->empty())
        cache.master_nodes = std::move(master_nodes->at(0));
      else
        cache.master_nodes = std::move(*master_nodes);

      if (blacklist->is_array() && !blacklist->empty())
        cache.blacklist = std::move(blacklist->at(0));
      else
        cache.blacklist = std::move(*blacklist);

      index_master_node_cache(cache);

      last_update = std::chrono::steady_clock::now();
      cache_initialized = true;
      return cache;
    }


    /*! Rate limiter for `access` timestamp writes.

      Wallets poll `get_address_info` continuously, and every bump takes the
      single LMDB write lock that the scanner needs to commit batches. One write
      per account per `access_write_interval` is plenty to drive a sweep measured
      in days. */
    class access_tracker
    {
      static constexpr const std::chrono::minutes access_write_interval{15};

      std::mutex mutex_{};
      std::unordered_map<std::uint32_t, std::chrono::steady_clock::time_point> last_{};

    public:
      //! \return True if `id` is due a write, marking it written.
      bool claim(db::account_id id)
      {
        const auto now = std::chrono::steady_clock::now();
        const std::uint32_t key = lmdb::to_native(id);

        const std::lock_guard<std::mutex> lock{mutex_};
        const auto existing = last_.find(key);
        if (existing != last_.end() && now - existing->second < access_write_interval)
          return false;
        last_[key] = now;
        return true;
      }
    };

    access_tracker& access_writes()
    {
      static access_tracker instance{};
      return instance;
    }

    /*! Record that `user` was just used, at most once per debounce window.

      Failures are logged and swallowed: a missed access stamp delays a sweep,
      it must never fail a wallet request. */
    void note_account_access(db::storage& disk, db::account const& user)
    {
      if (!access_writes().claim(user.id))
        return;
      const expect<void> updated = disk.update_access_time(user.address);
      if (!updated)
        MWARNING("Failed to record access time for account "
          << lmdb::to_native(user.id) << ": " << updated.error().message());
    }

    //! \return Account info from the DB, iff key matches address AND address is NOT hidden.
    expect<std::pair<db::account, db::storage_reader>> open_account(const rpc::account_credentials& creds, db::storage disk)
    {
      if (!key_check(creds))
        return {lws::error::bad_view_key};

      auto reader = disk.start_read();
      if (!reader)
        return reader.error();

      const auto user = reader->get_account(creds.address);
      if (!user)
        return user.error();
      if (is_hidden(user->first))
        return {lws::error::account_not_found};
      return {std::make_pair(user->second, std::move(*reader))};
    }

    struct daemon_status
    {
        using request = rpc::daemon_status_request;
        using response = rpc::daemon_status_response;
    
        static expect<response> handle(const request&, db::storage)
        {
            // Build JSON request
            nlohmann::json request_body = {
                {"jsonrpc", "2.0"},
                {"id", "0"},
                {"method", "get_info"}
            };
    
            // Call the daemon
            auto response_http = cpr::Post(
                cpr::Url{lws::daemon_add},
                cpr::Body{request_body.dump()},
                cpr::Header{{"Content-Type", "application/json"}}
            );
    
            if (response_http.status_code != 200)
            {
                MERROR("get_info call failed with HTTP code: " << response_http.status_code);
                return make_error_code(std::errc::io_error);
            }
    
            // Parse JSON
            nlohmann::json full_response;
            try
            {
                full_response = nlohmann::json::parse(response_http.text);
            }
            catch (const std::exception& e)
            {
                MERROR("JSON parse failed: " << e.what());
                return make_error_code(std::errc::invalid_argument);
            }
    
            if (!full_response.contains("result"))
            {
                MERROR("Missing 'result' in get_info response");
                return make_error_code(std::errc::protocol_error);
            }
    
            const auto& result = full_response["result"];
    
            try
            {
                rpc::daemon_status_response resp;
    
                // Extract only required values
                resp.height = result.at("height").get<uint64_t>();
                resp.target_height = result.at("target_height").get<uint64_t>();
                resp.outgoing_connections_count = result.at("outgoing_connections_count").get<uint32_t>();
                resp.incoming_connections_count = result.at("incoming_connections_count").get<uint32_t>();
    
                // Determine network type
                std::string net = result.at("nettype").get<std::string>();
                if (net == "mainnet") resp.network = rpc::network_type::main;
                else if (net == "testnet") resp.network = rpc::network_type::test;
                else {
                    MERROR("Unknown nettype: " << net);
                    return make_error_code(std::errc::invalid_argument);
                }
    
                // Determine daemon state
                if (resp.outgoing_connections_count == 0 && resp.incoming_connections_count == 0)
                    resp.state = rpc::daemon_state::no_connections;
                else if (resp.target_height && (resp.target_height - resp.height) >= 5)
                    resp.state = rpc::daemon_state::synchronizing;
                else
                    resp.state = rpc::daemon_state::ok;
    
                return resp;
            }
            catch (const std::exception& e)
            {
                MERROR("Error parsing fields from get_info: " << e.what());
                return make_error_code(std::errc::invalid_argument);
            }
        }
    };
     
    
    struct get_address_info
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_info_response;

      static expect<response> handle(const request &req, db::storage disk)
      {
        auto user = open_account(req, disk.clone());
        if (!user)
          return user.error();

        note_account_access(disk, user->first);

        std::unordered_set<crypto::key_image> processed;

        lws::db::account_address primary_address{req.address.view_public, req.address.spend_public};
        cryptonote::account_public_address crypto_address;
        crypto_address.m_view_public_key = primary_address.view_public;
        crypto_address.m_spend_public_key = primary_address.spend_public;

        std::string wallet_address = cryptonote::get_account_address_as_str(lws::config::network, false, crypto_address);

        auto master_node_data = get_master_node_cache();
        if (!master_node_data)
          return master_node_data.error();

        response resp{};

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        resp.blockchain_height = best_chain_height(*last);
        resp.transaction_height = resp.blockchain_height;
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);

        std::vector<db::output::spend_meta_> metas{};
        metas.reserve(outputs->count());

        for (auto output = outputs->make_iterator(); !output.is_end(); ++output)
        {
          const db::output::spend_meta_ meta =
              output.get_value<MONERO_FIELD(db::output, spend_meta)>(); // For each output, it extracts metadata which includes the amount of that output (meta.amount).

          // these outputs will usually be in correct order post ringct
          if (metas.empty() || metas.back().id < meta.id)
            metas.push_back(meta);
          else
            metas.insert(find_metadata(metas, meta.id), meta);

          resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + meta.amount);

          const crypto::key_image locked_key_image =
              output.get_value<MONERO_FIELD(db::output, locked_key_image)>();

          if (locked_key_image != crypto::key_image{} && !processed.count(locked_key_image))
          {
            const auto locked =
              master_node_data->locked_amount(wallet_address, locked_key_image);
            if (locked)
            {
              resp.locked_funds =
                rpc::safe_uint64(std::uint64_t(resp.locked_funds) + *locked);
              processed.insert(locked_key_image);
            }
          }

          /* Compare the unlock time against the chain tip, not against how far
             this account happens to have scanned. Using scan_height made a
             lagging account report already-spendable outputs as locked, so funds
             appeared to vanish into "pending" while it caught up. */
          if (is_locked(output.get_value<MONERO_FIELD(db::output, unlock_time)>(), db::block_id(resp.blockchain_height)))
          {
            resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + meta.amount);
          }
        }

        resp.spent_outputs.reserve(spends->count());
        for (auto const &spend : spends->make_range())
        {
          const auto meta = find_metadata(metas, spend.source);
          if (meta == metas.end() || meta->id != spend.source)
          {
            throw std::logic_error{
              "Serious database error, no receive for spend"
            };
          }

          resp.spent_outputs.push_back({*meta, spend});
          resp.total_sent = rpc::safe_uint64(std::uint64_t(resp.total_sent) + meta->amount);
        }

        return resp;
      }
    };//get_address_info

    struct get_unspent_outs
    {
      using request = rpc::get_unspent_outs_request;
      using response = rpc::get_unspent_outs_response;

      static expect<response> handle(request req, db::storage disk)
      {
        auto user = open_account(req.creds, std::move(disk));
        if (!user)
          return user.error();

        lws::db::account_address primary_address{req.creds.address.view_public, req.creds.address.spend_public};
        cryptonote::account_public_address crypto_address;
        crypto_address.m_view_public_key = primary_address.view_public;
        crypto_address.m_spend_public_key = primary_address.spend_public;
        std::string wallet_address = cryptonote::get_account_address_as_str(lws::config::network, false, crypto_address);

        auto master_node_data = get_master_node_cache();
        if (!master_node_data)
          return master_node_data.error();

        uint64_t grace_blocks = 10;

        json dynamic_fee = {
            {"jsonrpc", "2.0"},
            {"id", "0"},
            {"method", "get_fee_estimate"},
            {"params", {{"grace_blocks", grace_blocks}}}};

        auto fee_data = cpr::Post(cpr::Url{lws::daemon_add},
                                  cpr::Body{dynamic_fee.dump()},
                                  cpr::Header{{"Content-Type", "application/json"}});

        json resp = json::parse(fee_data.text);

        if ((req.use_dust && req.use_dust) || !req.dust_threshold)
          req.dust_threshold = rpc::safe_uint64(0);

        if (!req.mixin)
          req.mixin = 0;

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        std::uint64_t received = 0;
        std::vector<std::pair<db::output, std::vector<crypto::key_image>>> unspent;

        unspent.reserve(outputs->count());
        for (db::output const& out : outputs->make_range())
        {
          const std::pair<db::extra, std::uint8_t> unpacked = db::unpack(out.extra);
          const bool coinbase = (unpacked.first & lws::db::coinbase_output);
          if (out.spend_meta.amount < std::uint64_t(*req.dust_threshold) ||  (out.spend_meta.mixin_count < *req.mixin && !(coinbase == 1)))
            continue;
          
          const std::uint64_t value_l = out.spend_meta.amount;
          const crypto::key_image locked_key_image = out.locked_key_image;

          /* An output whose key image is locked into a master node for exactly
             this amount is not spendable, so it is left out of the unspent set. */
          bool should_skip_output = false;
          if (locked_key_image != crypto::key_image{})
            should_skip_output = master_node_data->locks_exactly(wallet_address, locked_key_image, value_l);

          if (!should_skip_output)
          {
            received += out.spend_meta.amount;
            unspent.push_back({out, {}});

            auto images = user->second.get_images(out.spend_meta.id);
            if (!images)
              return images.error();

            unspent.back().second.reserve(images->count());
            auto range = images->make_range<MONERO_FIELD(db::key_image, value)>();
            std::copy(range.begin(), range.end(), std::back_inserter(unspent.back().second));
          }

        }

        if (received < std::uint64_t(req.amount))
          return {lws::error::account_not_found};

        if (resp["status"] == "Failed")
        {
          return {lws::error::bad_daemon_response};
        }

        const std::uint64_t fee_per_byte = resp["result"]["fee_per_byte"];
        const std::uint64_t fee_per_output = resp["result"]["fee_per_output"];
        const std::uint64_t flash_fee_per_byte = resp["result"]["flash_fee_per_byte"];
        const std::uint64_t flash_fee_per_output = resp["result"]["flash_fee_per_output"];
        const std::uint64_t flash_fee_fixed = resp["result"]["flash_fee_fixed"];
        const std::uint64_t quantization_mask = resp["result"]["quantization_mask"];

        return response{fee_per_byte, fee_per_output,flash_fee_per_byte,flash_fee_per_output,flash_fee_fixed,quantization_mask,17,rpc::safe_uint64(received), std::move(unspent), std::move(req.creds.key)};
      }
    };//get_unspent_outs

    struct get_address_txs
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_txs_response;

      static expect<response> handle(const request& req, db::storage disk)
      {
        auto user = open_account(req, disk.clone());
        if (!user)
          return user.error();

        note_account_access(disk, user->first);

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        response resp{};
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);
        resp.blockchain_height = best_chain_height(*last);
        resp.transaction_height = resp.blockchain_height;

        // merge input and output info into a single set of txes.

        auto output = outputs->make_iterator();
        auto spend = spends->make_iterator();

        std::vector<db::output::spend_meta_> metas{};

        resp.transactions.reserve(outputs->count());
        metas.reserve(resp.transactions.capacity());

        db::transaction_link next_output{};
        db::transaction_link next_spend{};

        if (!output.is_end())
          next_output = output.get_value<MONERO_FIELD(db::output, link)>();
        if (!spend.is_end())
          next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();

        while (!output.is_end() || !spend.is_end())
        {
          if (!resp.transactions.empty())
          {
            db::transaction_link const& last = resp.transactions.back().info.link;

            if ((!output.is_end() && next_output < last) || (!spend.is_end() && next_spend < last))
            {
              throw std::logic_error{"DB has unexpected sort order"};
            }
          }

          if (spend.is_end() || (!output.is_end() && next_output <= next_spend))
          {
            std::uint64_t amount = 0;
            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_output.tx_hash)
            {
              resp.transactions.push_back({*output});
              amount = resp.transactions.back().info.spend_meta.amount;
            }
            else
            {
              amount = output.get_value<MONERO_FIELD(db::output, spend_meta.amount)>();
              resp.transactions.back().info.spend_meta.amount += amount;
            }

            const db::output::spend_meta_ meta = output.get_value<MONERO_FIELD(db::output, spend_meta)>();
            if (metas.empty() || metas.back().id < meta.id)
              metas.push_back(meta);
            else
              metas.insert(find_metadata(metas, meta.id), meta);

            resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + amount);

            ++output;
            if (!output.is_end())
              next_output = output.get_value<MONERO_FIELD(db::output, link)>();
          }
          else if (output.is_end() || (next_spend < next_output))
          {
            const db::output_id source_id = spend.get_value<MONERO_FIELD(db::spend, source)>();
            const auto meta = find_metadata(metas, source_id);
            if (meta == metas.end() || meta->id != source_id)
            {
              throw std::logic_error{
                "Serious database error, no receive for spend"
              };
            }

            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_spend.tx_hash)
            {
              resp.transactions.push_back({});
              resp.transactions.back().spends.push_back({*meta, *spend});
              resp.transactions.back().info.link.height = resp.transactions.back().spends.back().possible_spend.link.height;
              resp.transactions.back().info.link.tx_hash = resp.transactions.back().spends.back().possible_spend.link.tx_hash;
              resp.transactions.back().info.spend_meta.mixin_count =
                  resp.transactions.back().spends.back().possible_spend.mixin_count;
              resp.transactions.back().info.timestamp = resp.transactions.back().spends.back().possible_spend.timestamp;
              resp.transactions.back().info.unlock_time = resp.transactions.back().spends.back().possible_spend.unlock_time;
            }
            else
              resp.transactions.back().spends.push_back({*meta, *spend});

            resp.transactions.back().spent += meta->amount;

            ++spend;
            if (!spend.is_end())
              next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();
          }
        }

        return resp;
      }
    };

    struct get_random_outs
    {
      using request = rpc::get_random_outs_request;
      using response = rpc::get_random_outs_response;

      static expect<response> handle(request req, const db::storage&)
      {
        using distribution_rpc = cryptonote::rpc::GET_OUTPUT_DISTRIBUTION;
        using histogram_rpc = cryptonote::rpc::GET_OUTPUT_HISTOGRAM;
        
        std::vector<std::uint64_t> amounts = std::move(req.amounts.values);

        // if (50 < req.count || 20 < amounts.size())
        //   return {lws::error::exceeded_rest_request_limit};

        const std::greater<std::uint64_t> rsort{};
        std::sort(amounts.begin(), amounts.end(), rsort);
        const std::size_t ringct_count = amounts.end() - std::lower_bound(amounts.begin(), amounts.end(), 0, rsort);
        std::vector<lws::histogram> histograms{};
        if (ringct_count < amounts.size())
        {
          // reuse allocated vector memory
          amounts.resize(amounts.size() - ringct_count);

          histogram_rpc histogram_req{};
          histogram_req.request.amounts = std::move(amounts);
          histogram_req.request.min_count = 0;
          histogram_req.request.max_count = 0;
          histogram_req.request.unlocked = true;
          histogram_req.request.recent_cutoff = 0;

          // epee::byte_slice msg = rpc::client::make_message("get_output_histogram", histogram_req.request);
          // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
          json output_histogram = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","get_output_histogram"},
            {"params",{{"amounts",histogram_req.request.amounts},{"min_count",histogram_req.request.min_count},{"max_count",histogram_req.request.max_count},{"unlocked",histogram_req.request.unlocked},{"recent_cutoff",histogram_req.request.recent_cutoff}}}
          };
          // std::cout << "output_histogram : " << output_histogram.dump() << std::endl;
          // auto histogram_resp = client->receive<histogram_rpc::Response>(std::chrono::minutes{3}, MLWS_CURRENT_LOCATION);
          auto histogram_data = cpr::Post(cpr::Url{lws::daemon_add},
                                          cpr::Body{output_histogram.dump()},
                                          cpr::Header{{"Content-Type", "application/json"}});

          json resp = json::parse(histogram_data.text);
          // if (!histogram_resp)
          //   return histogram_resp.error();
          // std::cout << "output_histogram resp : " << resp << std::endl;
          for(auto it :resp["result"]["histogram"])
          {
            lws::histogram histogram_resp{};
            histogram_resp.amount = it["amount"];
            histogram_resp.total_count = it["total_instances"];
            histogram_resp.unlocked_count = it["unlocked_instances"];
            histogram_resp.recent_count = it["recent_instances"];
            histograms.push_back(histogram_resp);
          }

          if (histograms.size() != histogram_req.request.amounts.size())
            return {lws::error::bad_daemon_response};

          // histograms = std::move(histogram_resp->histogram);

          amounts = std::move(histogram_req.request.amounts);
          amounts.insert(amounts.end(), ringct_count, 0);
        }

        std::vector<std::uint64_t> distributions{};
        if (ringct_count)
        {
          // std::cout << "print the function " << ringct_count << "\n";
          distribution_rpc distribution_req{};
          if (ringct_count == amounts.size())
            distribution_req.request.amounts = std::move(amounts);

          distribution_req.request.amounts.resize(1);
          distribution_req.request.from_height = 0;
          distribution_req.request.to_height = 0;
          distribution_req.request.cumulative = true;

          //       // epee::byte_slice msg =
          //       //   rpc::client::make_message("get_output_distribution", distribution_req.request);
          //       // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
          json output_distribution = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","get_output_distribution"},
            {"params",{{"amounts",distribution_req.request.amounts},{"from_height",distribution_req.request.from_height},{"to_height",distribution_req.request.to_height},{"cumulative",distribution_req.request.cumulative}}}
          };

          // auto distribution_resp =
          //   client->receive<distribution_rpc::Response>(std::chrono::minutes{3}, MLWS_CURRENT_LOCATION);
          auto distribution_data = cpr::Post(cpr::Url{lws::daemon_add},
                                             cpr::Body{output_distribution.dump()},
               cpr::Header{ { "Content-Type", "application/json" }});

          json resp = json::parse(distribution_data.text);
          // std::cout << "get_output_distribution : " << resp << std::endl;
          // if (!distribution_resp)
          //   return distribution_resp.error();
          for(auto it :resp["result"]["distributions"][0]["distribution"])
          {
            distributions.push_back(it);
          }
          if (resp["result"]["distributions"].size() != 1)
            return {lws::error::bad_daemon_response};
          if (resp["result"]["distributions"][0]["amount"] != 0)
            return {lws::error::bad_daemon_response};

          // distributions = std::move(distribution_resp->distributions[0].data.distribution);

          if (amounts.empty())
          {
            amounts = std::move(distribution_req.request.amounts);
            amounts.insert(amounts.end(), ringct_count - 1, 0);
          }
        }

        class zmq_fetch_keys
        {
          /* `std::function` needs a copyable functor. The functor was made
             const and copied in the function instead of using a reference to
             make the callback in `std::function` thread-safe. This shouldn't
             be a problem now, but this is just-in-case of a future refactor. */
          // rpc::client gclient;
        public:
          zmq_fetch_keys() noexcept
          // : gclient(std::move(src))
          {}

          zmq_fetch_keys(zmq_fetch_keys&&) = default;
          zmq_fetch_keys(zmq_fetch_keys const& rhs)
          {}
          //     : gclient(MONERO_UNWRAP(rhs.gclient.clone()))
          //   {}

          expect<std::vector<output_keys>> operator()(std::vector<lws::output_ref> ids) const
          {
            // std::cout <<"operator overload" << std::endl;

            // using get_keys_rpc = cryptonote::rpc::GET_OUTPUTS;

            // get_keys_rpc::request keys_req{};
            // keys_req.outputs = std::move(ids);
            json output_indices;
            int i =0;
            for(auto it :ids)
            {
              output_indices.push_back(it.index);
              i++;
            }
            // std::cout << "amount index in get_outs : " << amount_index << std::endl;
            json out_keys = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","get_outs"},
            {"params",{{"output_indices",output_indices},{"get_txid",false}}}
           };
            // std::cout << "out_keys : " << out_keys.dump() << std::endl;
            // std::cout << "ids.size() :" << ids.size() << std::endl;
            // expect<rpc::client> client = gclient.clone();
            // if (!client)
            //   return client.error();

            // epee::byte_slice msg = rpc::client::make_message("get_output_keys", keys_req);
            // MONERO_CHECK(client->send(std::move(msg), std::chrono::seconds{10}));
            auto out_keys_data = cpr::Post(cpr::Url{lws::daemon_add},
                                           cpr::Body{out_keys.dump()},
                 cpr::Header{ { "Content-Type", "application/json" }});

            json resp = json::parse(out_keys_data.text);
            // std::cout << "get_outs response : " << resp << std::endl;
            using get_keys_rpc = cryptonote::rpc::output_key_mask_unlocked;
            std::vector <get_keys_rpc> keys{};
            // auto keys_resp = client->receive<get_keys_rpc::Response>(std::chrono::seconds{10}, MLWS_CURRENT_LOCATION);
            // if (!keys_resp)
            //   return keys_resp.error();
            for(auto it : resp["result"]["outs"])
            {
              get_keys_rpc key;
              std::string key_p = it["key"];
              tools::hex_to_type(key_p,key.key);
              tools::hex_to_type((std::string)it["mask"],key.mask);
              key.unlocked = it["unlocked"];
              keys.push_back(key);
            }
            return {std::move(keys)};
          }
        };

        lws::gamma_picker pick_rct{std::move(distributions)};
        auto rings = pick_random_outputs(
            req.count,
            epee::to_span(amounts),
            pick_rct,
            epee::to_mut_span(histograms),
          zmq_fetch_keys{/*std::move(*client)*/}
        );
        if (!rings)
          return rings.error();

        return response{std::move(*rings)};
      }
    };

    struct import_request
    {
      using request = rpc::account_credentials;
      using response = rpc::import_response;

      static expect<response> handle(request req, db::storage disk)
      {
        bool new_request = false;
        bool fulfilled = false;
        {
          auto user = open_account(req, disk.clone());
          if (!user)
            return user.error();

          if (user->first.start_height == db::block_id(0))
            fulfilled = true;
          else
          {
            const expect<db::request_info> info =
                user->second.get_request(db::request::import_scan, req.address);

            if (!info)
            {
              if (info != lmdb::error(MDB_NOTFOUND))
                return info.error();

              new_request = true;
            }
          }
        } // close reader

        if (new_request)
          MONERO_CHECK(disk.import_request(req.address, db::block_id(0)));

        const char* status = new_request ?
          "Accepted, waiting for approval" : (fulfilled ? "Approved" : "Waiting for Approval");
        return response{rpc::safe_uint64(0), status, new_request, fulfilled};
      }
    };

    struct login
    {
      using request = rpc::login_request;
      using response = rpc::login_response;

      static expect<response> handle(request req, db::storage disk)
      {
        // std::cout <<"inside the login\n";
        if (!key_check(req.creds))
          return {lws::error::bad_view_key};

        {
          auto reader = disk.start_read();
          if (!reader)
            return reader.error();

          const auto account = reader->get_account(req.creds.address);
          reader->finish_read();

          if (account)
          {
            if (is_hidden(account->first))
              return {lws::error::account_not_found};

            const bool reactivate = (account->first == db::account_status::inactive);
            const db::account found = account->second;
            reader->finish_read();

            /* An idle-swept account comes back to life here. Without this it
               would log in successfully and then silently never scan again,
               because `is_hidden` treats `inactive` as visible. Scanning resumes
               from the stored height, so only the idle gap is re-scanned. */
            if (reactivate)
            {
              const db::account_address address = found.address;
              const auto changed = disk.change_status(
                db::account_status::active, epee::span<const db::account_address>{std::addressof(address), 1}
              );
              if (!changed)
                return changed.error();
              MINFO("Reactivated idle account " << lmdb::to_native(found.id)
                << " on login; resuming scan from height " << std::uint64_t(found.scan_height));
            }

            note_account_access(disk, found);

            // Do not count a request for account creation as login
            return response{false, bool(found.flags & db::account_generated_locally)};
          }
          else if (!req.create_account || account != lws::error::account_not_found)
            return account.error();
        }

        const auto flags = req.generated_locally ? db::account_generated_locally : db::default_account;

        if (lws::config::auto_accept_accounts)
        {
          // create and start scanning immediately
          MONERO_CHECK(disk.add_account(req.creds.address, req.creds.key, flags));
        }
        else
        {
          /* Queue for admin approval instead. This is the path that gives
             --create-queue-max an effect and keeps `list_requests` /
             `accept_requests create` meaningful. */
          MONERO_CHECK(disk.creation_request(req.creds.address, req.creds.key, flags));
        }
        return response{true, req.generated_locally};
      }
    };//login

    struct submit_raw_tx
    {
      using request = rpc::submit_raw_tx_request;
      using response = rpc::submit_raw_tx_response;

      static expect<response> handle(request req, const db::storage &disk)
      {
        using transaction_rpc = cryptonote::rpc::SUBMIT_TRANSACTION;

        // expect<rpc::client> client = gclient.clone();
        // if (!client)
        //   return client.error();

        transaction_rpc daemon_req{};
        daemon_req.request.tx = std::move(req.tx);
        if(req.fee == "5")
        {
          daemon_req.request.flash = true;
        }else{
          daemon_req.request.flash =false;
        }// Handles Flash Method from Client

        // epee::byte_slice message = rpc::client::make_message("send_raw_tx_hex", daemon_req);
        // MONERO_CHECK(client->send(std::move(message), std::chrono::seconds{10}));
        json message = {
            {"jsonrpc","2.0"},
            {"id","0"},
            {"method","send_raw_transaction"},
            {"params",{{"tx",daemon_req.request.tx},{"flash",daemon_req.request.flash}}}
          };
          // std::cout <<"message : " << message.dump() << std::endl;
        auto resp = cpr::Post(cpr::Url{lws::daemon_add},
                              cpr::Body{message.dump()},
                         cpr::Header{ { "Content-Type", "application/json" }});

        json daemon_resp = json::parse(resp.text);
        // std::cout <<"daemon_resp : " << daemon_resp << std::endl;
        // const auto daemon_resp = client->receive<transaction_rpc::Response>(std::chrono::seconds{20}, MLWS_CURRENT_LOCATION);
        // if (!daemon_resp)
        //   return daemon_resp.error();
        if (daemon_resp["result"]["not_relayed"] == true)
          return {lws::error::tx_relay_failed};

        if(daemon_resp["result"]["status"] == "Failed")
          return {lws::error::status_failed};

        return response{"OK"};
      }
    }; //submit_raw_tx

    template<typename E>
    expect<epee::byte_slice> call(std::string&& root, db::storage disk)
    {
      using request = typename E::request;
      using response = typename E::response;

      expect<request> req = wire::json::from_bytes<request>(std::move(root));
      if (!req)
        return req.error();

      expect<response> resp = E::handle(std::move(*req), std::move(disk));
      if (!resp)
        return resp.error();
      return wire::json::to_bytes<response>(*resp);
    }

    //! Admin endpoint: live view of every scan thread.
    struct scanner_status_
    {
      using request = expect<void>;

      expect<void> operator()(wire::json_writer& dest, db::storage disk) const
      {
        const lws::scanner_status status = lws::scanner::status();

        // report the chain tip the DB believes in alongside the daemon's
        std::uint64_t db_height = 0;
        auto reader = disk.start_read();
        if (reader)
        {
          const auto last = reader->get_last_block();
          if (last)
            db_height = std::uint64_t(last->id);
        }

        wire::object(dest,
          wire::field("scanner", std::cref(status)),
          wire::field("db_chain_height", db_height)
        );
        return success();
      }

      expect<void> operator()(wire::json_writer& dest, db::storage disk, const request&) const
      { return (*this)(dest, std::move(disk)); }
    };

    template<typename T>
    struct admin
    {
      T params;
      crypto::secret_key auth;
    };

    template<typename T>
    void read_bytes(wire::json_reader& source, admin<T>& self)
    {
      wire::object(
        source, wire::field("auth", std::ref(unwrap(unwrap(self.auth)))), WIRE_FIELD(params)
      );
    }
    void read_bytes(wire::json_reader& source, admin<expect<void>>& self)
    {
      // params optional
      wire::object(source, wire::field("auth", std::ref(unwrap(unwrap(self.auth)))));
    }

    //! \return The admin account's id iff `auth` belongs to one.
    expect<db::account_id> check_admin_auth(const crypto::secret_key& auth, db::storage& disk)
    {
      db::account_address address{};
      if (!crypto::secret_key_to_public_key(auth, address.view_public))
        return {error::crypto_failure};

      auto reader = disk.start_read();
      if (!reader)
        return reader.error();
      const auto account = reader->get_account(address);
      if (!account)
        return account.error();
      if (account->first == db::account_status::inactive)
        return {error::account_not_found};
      if (!(account->second.flags & db::account_flags::admin_account))
        return {error::account_not_found};
      return account->second.id;
    }

    template<typename E>
    expect<epee::byte_slice> call_admin(std::string&& root, db::storage disk)
    {
      using request = typename E::request;
      const expect<admin<request>> req = wire::json::from_bytes<admin<request>>(std::move(root));
      if (!req)
        return req.error();

      const expect<db::account_id> caller = check_admin_auth(req->auth, disk);
      if (!caller)
        return caller.error();

      wire::json_slice_writer dest{};
      MONERO_CHECK(E{}(dest, std::move(disk), req->params));
      return dest.take_bytes();
    }

    /*! `call_admin`, plus an audit entry naming the caller and the request.

      Used for the endpoints that change state; read-only ones are left
      unlogged so the log stays useful. */
    template<typename E>
    expect<epee::byte_slice> call_admin_audited(std::string&& root, db::storage disk)
    {
      using request = typename E::request;
      // keep a copy for the audit entry before the reader consumes it
      std::string body{root};
      const expect<admin<request>> req = wire::json::from_bytes<admin<request>>(std::move(root));
      if (!req)
        return req.error();

      const expect<db::account_id> caller = check_admin_auth(req->auth, disk);
      if (!caller)
        return caller.error();

      // never record the caller's secret key
      const auto auth_at = body.find("\"auth\"");
      if (auth_at != std::string::npos)
      {
        const auto end = body.find_first_of(",}", auth_at);
        body.replace(auth_at, (end == std::string::npos ? body.size() : end) - auth_at, "\"auth\":\"<redacted>\"");
      }
      if (512 < body.size())
        body.resize(512);

      wire::json_slice_writer dest{};
      const expect<void> result = E{}(dest, std::move(disk), req->params);

      rpc::record_admin_action(
        std::uint64_t(lmdb::to_native(*caller)),
        std::string{E::endpoint_name},
        (result ? std::string{"ok "} : std::string{"failed "}) + body
      );

      MONERO_CHECK(result);
      return dest.take_bytes();
    }

    struct endpoint
    {
      char const* const name;
      expect<epee::byte_slice> (*const run)(std::string&&, db::storage);
      const unsigned max_size;
      //! Response MIME type; Prometheus needs plain text, everything else is JSON.
      char const* const mime = "application/json";
    };

    /*! Admin endpoint: Prometheus exposition of scanner health.

      Deliberately not routed through the `wire` JSON writer - the point of this
      endpoint is that an existing scrape config can consume it unchanged. */
    expect<epee::byte_slice> serve_metrics(std::string&& root, db::storage disk)
    {
      // still require admin auth; parse and validate the credential the same way
      const expect<admin<expect<void>>> req =
        wire::json::from_bytes<admin<expect<void>>>(std::move(root));
      if (!req)
        return req.error();
      const expect<db::account_id> caller = check_admin_auth(req->auth, disk);
      if (!caller)
        return caller.error();

      const lws::scanner_status status = lws::scanner::status();

      std::uint64_t lowest = 0;
      bool have_lowest = false;
      std::uint64_t alive = 0;
      for (const auto& thread : status.threads)
      {
        if (!thread.alive)
          continue;
        ++alive;
        if (!have_lowest || thread.current_height < lowest)
        {
          lowest = thread.current_height;
          have_lowest = true;
        }
      }
      const std::uint64_t behind =
        (status.daemon_height > lowest) ? status.daemon_height - lowest : 0;

      std::ostringstream out{};
      const auto metric = [&out] (const char* name, const char* help, const char* type)
      {
        out << "# HELP " << name << ' ' << help << '\n'
            << "# TYPE " << name << ' ' << type << '\n';
      };

      metric("lws_scanner_running", "1 when the scanner is running.", "gauge");
      out << "lws_scanner_running " << (status.running ? 1 : 0) << '\n';

      metric("lws_scan_threads", "Scan threads currently alive.", "gauge");
      out << "lws_scan_threads " << alive << '\n';

      metric("lws_daemon_height", "Chain tip last seen by a scan thread.", "gauge");
      out << "lws_daemon_height " << status.daemon_height << '\n';

      metric("lws_blocks_behind", "Blocks between the chain tip and the slowest scan thread.", "gauge");
      out << "lws_blocks_behind " << behind << '\n';

      metric("lws_scan_restarts_total", "Scan-thread teardowns since start.", "counter");
      out << "lws_scan_restarts_total " << status.restarts << '\n';

      metric("lws_accounts_deactivated_total", "Accounts idle-swept since start.", "counter");
      out << "lws_accounts_deactivated_total " << status.deactivated << '\n';

      metric("lws_last_sweep_timestamp", "Unix time of the last idle sweep; 0 if never.", "gauge");
      out << "lws_last_sweep_timestamp " << status.last_sweep << '\n';

      metric("lws_thread_height", "Height of the most recent committed batch.", "gauge");
      for (const auto& thread : status.threads)
        out << "lws_thread_height{thread=\"" << thread.index << "\"} " << thread.current_height << '\n';

      metric("lws_thread_blocks_per_second", "Scan rate of the most recent batch.", "gauge");
      for (const auto& thread : status.threads)
        out << "lws_thread_blocks_per_second{thread=\"" << thread.index << "\"} "
            << std::uint64_t(thread.blocks_per_second) << '\n';

      metric("lws_thread_accounts", "Accounts carried by a scan thread.", "gauge");
      for (const auto& thread : status.threads)
        out << "lws_thread_accounts{thread=\"" << thread.index << "\"} " << thread.accounts.size() << '\n';

      metric("lws_thread_group_span", "Height span of a scan thread's account group.", "gauge");
      for (const auto& thread : status.threads)
        out << "lws_thread_group_span{thread=\"" << thread.index << "\"} "
            << (thread.group_high - thread.group_low) << '\n';

      metric("lws_thread_consecutive_failures", "Failed batches since the last good one.", "gauge");
      for (const auto& thread : status.threads)
        out << "lws_thread_consecutive_failures{thread=\"" << thread.index << "\"} "
            << thread.consecutive_failures << '\n';

      metric("lws_thread_seconds_since_commit", "Seconds since a thread last committed; -1 if never.", "gauge");
      const std::int64_t now = std::int64_t(std::time(nullptr));
      for (const auto& thread : status.threads)
        out << "lws_thread_seconds_since_commit{thread=\"" << thread.index << "\"} "
            << (thread.last_commit ? now - thread.last_commit : -1) << '\n';

      const std::string body = out.str();
      return epee::byte_slice{{epee::strspan<std::uint8_t>(body)}};
    }

    constexpr const endpoint endpoints[] =
        {
      {"/daemon_status",         call<daemon_status>,          1024},
      {"/get_address_info",      call<get_address_info>, 2 * 1024},
      {"/get_address_txs",       call<get_address_txs>,  2 * 1024},
      {"/get_random_outs",       call<get_random_outs>,  2 * 1024},
            // {"/get_txt_records",       nullptr,                0       },
      {"/get_unspent_outs",      call<get_unspent_outs>, 2 * 1024},
      {"/import_request",        call<import_request>,   2 * 1024},
      {"/login",                 call<login>,            2 * 1024},
      {"/submit_raw_tx",         call<submit_raw_tx>,   50 * 1024}
    };
    constexpr const endpoint admin_endpoints[] =
    {
      {"/accept_requests",       call_admin_audited<rpc::accept_requests_>, 50 * 1024},
      {"/account_info",          call_admin<rpc::account_info_>,      1024},
      {"/add_account",           call_admin_audited<rpc::add_account_>,     50 * 1024},
      {"/admin_log",             call_admin<rpc::admin_log_>,         1024},
      {"/delete_account",        call_admin_audited<rpc::delete_account_>, 50 * 1024},
      {"/list_accounts",         call_admin<rpc::list_accounts_>,   4 * 1024},
      {"/list_requests",         call_admin<rpc::list_requests_>,   100},
      {"/metrics",               serve_metrics,                      1024, "text/plain; version=0.0.4"},
      {"/modify_account_status", call_admin_audited<rpc::modify_account_>,  50 * 1024},
      {"/reject_requests",       call_admin_audited<rpc::reject_requests_>, 50 * 1024},
      {"/rescan",                call_admin_audited<rpc::rescan_>,          50 * 1024},
      {"/rollback",              call_admin_audited<rpc::rollback_>,          1024},
      {"/scanner_status",        call_admin<scanner_status_>,       100},
      {"/validate",              call_admin<rpc::validate_>,        50 * 1024}
    };

    struct by_name_
    {
      bool operator()(endpoint const& left, endpoint const& right) const noexcept
      {
        if (left.name && right.name)
          return std::strcmp(left.name, right.name) < 0;
        return false;
      }
      bool operator()(const boost::string_ref left, endpoint const& right) const noexcept
      {
        if (right.name)
          return left < right.name;
        return false;
      }
      bool operator()(endpoint const& left, const boost::string_ref right) const noexcept
      {
        if (left.name)
          return left.name < right;
        return false;
      }
    };
    constexpr const by_name_ by_name{};

  } //anonymous
  struct rest_server::internal final : public lws::http_server_impl_base<rest_server::internal, context>
  {
    db::storage disk;
    boost::optional<std::string> prefix;
    boost::optional<std::string> admin_prefix;


    explicit internal(boost::asio::io_service& io_service, lws::db::storage disk)
      : lws::http_server_impl_base<rest_server::internal, context>(io_service)
      , disk(std::move(disk))
      , prefix()
      , admin_prefix()
    {
      assert(std::is_sorted(std::begin(endpoints), std::end(endpoints), by_name));
      assert(std::is_sorted(std::begin(admin_endpoints), std::end(admin_endpoints), by_name));
    }

    const endpoint* get_endpoint(boost::string_ref uri) const
    {
      using span = epee::span<const endpoint>;
      span handlers = nullptr;

      if (admin_prefix && uri.starts_with(*admin_prefix))
      {
        uri.remove_prefix(admin_prefix->size());
        handlers = span{admin_endpoints};
      }
      else if (prefix && uri.starts_with(*prefix))
      {
        uri.remove_prefix(prefix->size());
        handlers = span{endpoints};
      }
      else
        return nullptr;

      const auto handler = std::lower_bound(
        std::begin(handlers), std::end(handlers), uri, by_name
      );
      if (handler == std::end(handlers) || handler->name != uri)
        return nullptr;
      return handler;
    }

    virtual bool
      handle_http_request(const http::http_request_info& query, http::http_response_info& response, context& ctx)
        override final
    {
     endpoint const* const handler = get_endpoint(query.m_URI);
      if (!handler)
      {
        response.m_response_code = 404;
        response.m_response_comment = "Not Found";
        return true;
      }

      if (handler->run == nullptr)
      {
        response.m_response_code = 501;
        response.m_response_comment = "Not Implemented";
        return true;
      }

      if (handler->max_size < query.m_body.size())
      {
        MINFO("Client exceeded maximum body size for " << handler->name
          << " (" << query.m_body.size() << " > " << handler->max_size << " bytes) from "
          << ctx.m_remote_address.str());
        response.m_response_code = 400;
        response.m_response_comment = "Bad Request";
        return true;
      }

      if (query.m_http_method != http::http_method_post)
      {
        response.m_response_code = 405;
        response.m_response_comment = "Method Not Allowed";
        return true;
      }

      /* Handlers throw on corrupt database state (see the `no receive for spend`
         logic error) and on MONERO_UNWRAP failures. Letting that escape into the
         epee HTTP layer drops the connection instead of answering; contain it. */
      expect<epee::byte_slice> body{common_error::kInvalidArgument};
      try
      {
        // \TODO remove copy of json string here :/
        body = handler->run(std::string{query.m_body}, disk.clone());
      }
      catch (const std::exception& e)
      {
        MERROR("Unhandled exception in " << handler->name << " from "
          << ctx.m_remote_address.str() << ": " << e.what());
        response.m_response_code = 500;
        response.m_response_comment = "Internal Server Error";
        return true;
      }
      catch (...)
      {
        MERROR("Unhandled exception in " << handler->name << " from "
          << ctx.m_remote_address.str() << ": unknown");
        response.m_response_code = 500;
        response.m_response_comment = "Internal Server Error";
        return true;
      }

      if (!body)
      {
        MINFO(body.error().message() << " from " << ctx.m_remote_address.str() << " on " << handler->name);

        if (body.error().category() == wire::error::rapidjson_category())
        {
          response.m_response_code = 400;
          response.m_response_comment = "Bad Request";
        }
        else if (body == lws::error::account_not_found || body == lws::error::duplicate_request)
        {
          response.m_response_code = 403;
          response.m_response_comment = "Forbidden";
        }
        else if (body.matches(std::errc::timed_out) || body.matches(std::errc::no_lock_available))
        {
          response.m_response_code = 503;
          response.m_response_comment = "Service Unavailable";
        }
        else
        {
          response.m_response_code = 500;
          response.m_response_comment = "Internal Server Error";
        }
        return true;
      }

      response.m_response_code = 200;
      response.m_response_comment = "OK";
      response.m_mime_tipe = handler->mime;
      response.m_header_info.m_content_type = handler->mime;
        response.m_body.assign(reinterpret_cast<const char*>(body->data()), body->size()); // \TODO Remove copy here too!s
      return true;
    }
  };
  rest_server::rest_server(epee::span<const std::string> addresses, std::vector<std::string> admin, db::storage disk, configuration config)
      : io_service_(), ports_()
  {
    if (addresses.empty())
      MONERO_THROW(common_error::kInvalidArgument, "REST server requires 1 or more addresses");

    std::sort(admin.begin(), admin.end());
    const auto init_port = [&admin] (internal& port, const std::string& address, configuration config, const bool is_admin) -> bool
  
    {
      epee::net_utils::http::url_content url{};
      if (!epee::net_utils::parse_url(address, url))
      MONERO_THROW(lws::error::configuration, "REST server URL/address is invalid");

      const bool https = url.schema == "https";
      if (!https && url.schema != "http")
        MONERO_THROW(lws::error::configuration, "Unsupported scheme, only http or https supported");

      if (std::numeric_limits<std::uint16_t>::max() < url.port)
      MONERO_THROW(lws::error::configuration, "Specified port for REST server is out of range");

      if (!url.uri.empty() && url.uri.front() != '/')
        MONERO_THROW(lws::error::configuration, "First path prefix character must be '/'");


      if (!https)
      {
        boost::system::error_code error{};
        const auto ip_host = boost::asio::ip::make_address(url.host, error);
        if (error)
          MONERO_THROW(lws::error::configuration, "Invalid IP address for REST server");
        if (!ip_host.is_loopback() && !config.allow_external)
          MONERO_THROW(lws::error::configuration, "Binding to external interface with http - consider using https or secure tunnel (ssh, etc). Use --confirm-external-bind to override");
      }

      if (url.port == 0)
        url.port = https ? 8443 : 8080;

      if (!is_admin)
        {
          epee::net_utils::http::url_content admin_url{};
          const boost::string_ref start{address.c_str(), address.rfind(url.uri)};
          while (true) // try to merge 1+ admin prefixes
          {
            const auto mergeable = std::lower_bound(admin.begin(), admin.end(), start);
            if (mergeable == admin.end())
              break;
  
            if (!epee::net_utils::parse_url(*mergeable, admin_url))
              MONERO_THROW(lws::error::configuration, "Admin REST URL/address is invalid");
            if (admin_url.port == 0)
              admin_url.port = https ? 8443 : 8080;
            if (url.host != admin_url.host || url.port != admin_url.port)
              break; // nothing is mergeable
  
            if (port.admin_prefix)
              MONERO_THROW(lws::error::configuration, "Two admin REST servers cannot be merged onto one REST server");
  
            if (url.uri.size() < 2 || admin_url.uri.size() < 2)
              MONERO_THROW(lws::error::configuration, "Cannot merge REST server and admin REST server - a prefix must be specified for both");
            if (admin_url.uri.front() != '/')
              MONERO_THROW(lws::error::configuration, "Admin REST first path prefix character must be '/'");
            if (admin_url.uri != admin_url.m_uri_content.m_path)
              MONERO_THROW(lws::error::configuration, "Admin REST server must have path only prefix");
  
            MINFO("Merging admin and non-admin REST servers: " << address << " + " << *mergeable);
            port.admin_prefix = admin_url.m_uri_content.m_path;
            admin.erase(mergeable);
          } // while multiple mergable admins
        }
  
        if (url.uri != url.m_uri_content.m_path)
          MONERO_THROW(lws::error::configuration, "REST server must have path only prefix");
  
        if (url.uri.size() < 2)
          url.m_uri_content.m_path.clear();
        if (is_admin)
          port.admin_prefix = url.m_uri_content.m_path;
        else
          port.prefix = url.m_uri_content.m_path;
     

      epee::net_utils::ssl_options_t ssl_options = https ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;
      ssl_options.verification = epee::net_utils::ssl_verification_t::none; // clients verified with view key
      ssl_options.auth = std::move(config.auth);

      if (!port.init(std::to_string(url.port), std::move(url.host), std::move(config.access_controls), std::move(ssl_options)))
        MONERO_THROW(lws::error::http_server, "REST server failed to initialize");
      return https;
    };

    bool any_ssl = false;

    for (const std::string& address : addresses)
    {
      ports_.emplace_back(io_service_, disk.clone());
      any_ssl |= init_port(ports_.back(), address, config, false);
    }

    for (const std::string& address : admin)
    {
      ports_.emplace_back(io_service_, disk.clone());
      any_ssl |= init_port(ports_.back(), address, config, true);
    }

    const bool expect_ssl = !config.auth.private_key_path.empty();
    const std::size_t threads = config.threads;
    if (!any_ssl && expect_ssl)
      MONERO_THROW(lws::error::configuration, "Specified SSL key/cert without specifying https capable REST server");

    if (!ports_.front().run(threads, false))
      MONERO_THROW(lws::error::http_server, "REST server failed to run");
  }

  rest_server::~rest_server() noexcept
  {
  }
} // lws
