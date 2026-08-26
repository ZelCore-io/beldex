#include <algorithm>
#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common/command_line.h" // beldex/src
#include "common/expect.h"       // beldex/src
#include "epee/misc_log_ex.h"         // beldex/contrib/epee/include/epee
#include "epee/span.h"                // beldex/contrib/epee/include
#include "epee/string_tools.h"        // beldex/contrib/epee/include
#include <boost/thread/thread.hpp>
#include <limits>
#include "lmdb/util.h"
#include "options.h"
#include "config.h"
#include "rpc/admin.h"
#include "error.h"
#include "db/storage.h"
#include "db/string.h"
#include "db/data.h"
#include "wire/crypto.h"
#include "wire/filters.h"
#include "wire/json/write.h"

namespace
{
  // wrapper for custom output for admin accounts
  template<typename T>
  struct admin_display
  {
    T value;
  };

  void write_bytes(wire::json_writer& dest, const admin_display<lws::db::account>& source)
  {
    wire::object(dest,
      wire::field("address", lws::db::address_string(source.value.address)),
      wire::field("key", std::cref(source.value.key))  
    );
  
  }

  void write_bytes(wire::json_writer& dest, admin_display<boost::iterator_range<lmdb::value_iterator<lws::db::account>>> source)
  {
    const auto filter = [](const lws::db::account& src)
    { return bool(src.flags & lws::db::account_flags::admin_account); };
    const auto transform = [] (lws::db::account src)
    { return admin_display<lws::db::account>{std::move(src)}; };


    wire::array(dest, (source.value | boost::adaptors::filtered(filter)), transform);


  }


  template<typename F, typename... T>
  void run_command(F f, std::ostream& dest, T&&... args)
  {

    wire::json_stream_writer stream{dest};
    MONERO_UNWRAP(f(stream, std::forward<T>(args)...));
    stream.finish();
  }

  struct options : lws::options
  {
    const command_line::arg_descriptor<bool> show_sensitive;
    const command_line::arg_descriptor<bool> no_purge;
    const command_line::arg_descriptor<std::string> command;
    const command_line::arg_descriptor<std::vector<std::string>> arguments;

    options()
      : lws::options()
      , show_sensitive{"show-sensitive", "Show view keys", false}
      , no_purge{"no-purge", "rescan: keep outputs/spends above the target height", false}
      , command{"command", "Admin command to execute", ""}
      , arguments{"arguments", "Arguments to command"}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      lws::options::prepare(description);
      command_line::add_arg(description, show_sensitive);
      command_line::add_arg(description, no_purge);
      command_line::add_arg(description, command);
      command_line::add_arg(description, arguments);
    }
  };

  struct program
  {
    lws::db::storage disk;
    std::vector<std::string> arguments;
    bool show_sensitive;
    bool no_purge;
  };

  crypto::secret_key get_key(std::string const& hex)
  {
    crypto::secret_key out{};
    if (!epee::string_tools::hex_to_pod(hex, out))
      MONERO_THROW(lws::error::bad_view_key, "View key has invalid hex");
    return out;
  }

  std::vector<lws::db::account_address> get_addresses(epee::span<const std::string> arguments)
  {
    // first entry is currently always some other option
    assert(!arguments.empty());
    arguments.remove_prefix(1);

    std::vector<lws::db::account_address> addresses{};
    addresses.reserve(arguments.size());
    for (std::string const& address : arguments)
      addresses.push_back(lws::db::address_string(address).value());
    return addresses;
  }

  void accept_requests(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2){
    throw std::runtime_error{"accept_requests requires 2 or more arguments"};
    }  

      lws::rpc::address_requests req{
        get_addresses(epee::to_span(prog.arguments)),
        MONERO_UNWRAP(lws::db::request_from_string(prog.arguments[0]))
      };
      run_command(lws::rpc::accept_requests, out, std::move(prog.disk), std::move(req));
  }

  void add_account(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 2){
    throw std::runtime_error{"add_account needs exactly two arguments"};
    }
      

      lws::rpc::add_account_req req{
        lws::db::address_string(prog.arguments[0]).value(),
        get_key(prog.arguments[1])
    };
    run_command(lws::rpc::add_account, out, std::move(prog.disk), std::move(req));
  }

  void create_admin(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty()){
    throw std::runtime_error{"create_admin takes zero arguments"};
    }
      

      admin_display<lws::db::account> account{};
      {
        crypto::secret_key auth{};
        crypto::generate_keys(account.value.address.view_public, auth);
        MONERO_UNWRAP(prog.disk.add_account(account.value.address, auth, lws::db::account_flags::admin_account));
  
        static_assert(sizeof(auth) == sizeof(account.value.key), "bad memcpy");
        std::memcpy(std::addressof(account.value.key), std::addressof(auth), sizeof(auth));
      }
  
      wire::json_stream_writer json{out};
      write_bytes(json, account);
      json.finish();
  }

  void debug_database(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"debug_database takes zero arguments"};

    auto reader = prog.disk.start_read().value();
    reader.json_debug(out, prog.show_sensitive);
  }

  void list_accounts(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_accounts takes zero arguments"};

    run_command(lws::rpc::list_accounts, out, std::move(prog.disk));
  }  

  void list_admin(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_admin takes zero arguments"};

    using value_range = boost::iterator_range<lmdb::value_iterator<lws::db::account>>;
    const auto transform = [] (value_range user)
    { return admin_display<value_range>{std::move(user)}; };

    auto reader = MONERO_UNWRAP(prog.disk.start_read());
    wire::json_stream_writer json{out};
    wire::dynamic_object(
      json, reader.get_accounts().value().make_range(), wire::enum_as_string, transform
    );
    json.finish();
  }

  void list_requests(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"list_requests takes zero arguments"};

    run_command(lws::rpc::list_requests, out, std::move(prog.disk));
  }

  void modify_account(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2){
    throw std::runtime_error{"modify_account_status requires 2 or more arguments"};
    }
      

      lws::rpc::modify_account_req req{
        get_addresses(epee::to_span(prog.arguments)),
        lws::db::account_status_from_string(prog.arguments[0]).value()
      };
      run_command(lws::rpc::modify_account, out, std::move(prog.disk), std::move(req));
  }

  void reject_requests(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      MONERO_THROW(common_error::kInvalidArgument, "reject_requests requires 2 or more arguments");
     
    lws::rpc::address_requests req{
        get_addresses(epee::to_span(prog.arguments)),
        lws::db::request_from_string(prog.arguments[0]).value()
      };
      run_command(lws::rpc::reject_requests, out, std::move(prog.disk), std::move(req));
  
  }

  void rescan(program prog, std::ostream& out)
  {
    if (prog.arguments.size() < 2)
      throw std::runtime_error{"rescan requires 2 or more arguments"};

    lws::rpc::rescan_req req{
        get_addresses(epee::to_span(prog.arguments)),
        lws::db::block_id(std::stoull(prog.arguments[0])),
        prog.no_purge ? boost::optional<bool>{false} : boost::optional<bool>{true}
      };
    run_command(lws::rpc::rescan, out, std::move(prog.disk), std::move(req));
  }

  void delete_account(program prog, std::ostream& out)
  {
    if (prog.arguments.empty())
      throw std::runtime_error{"delete_account requires 1 or more addresses"};

    std::vector<lws::db::account_address> addresses{};
    addresses.reserve(prog.arguments.size());
    for (std::string const& address : prog.arguments)
      addresses.push_back(lws::db::address_string(address).value());

    lws::rpc::delete_account_req req{std::move(addresses)};
    run_command(lws::rpc::delete_account, out, std::move(prog.disk), std::move(req));
  }

  void account_info(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 1)
      throw std::runtime_error{"account_info takes exactly one address"};

    lws::rpc::account_info_req req{prog.arguments[0]};
    run_command(lws::rpc::account_info, out, std::move(prog.disk), std::move(req));
  }

  /*! Print the thread partition the scanner would choose right now.

    Mirrors `partition_by_height` in scanner.cpp. Groups whose height span is
    wide are the ones where accounts near the top sit idle waiting for the
    lowest to catch up, so they are flagged. */
  void scan_plan(program prog, std::ostream& out)
  {
    if (1 < prog.arguments.size())
      throw std::runtime_error{"scan_plan takes an optional thread count"};

    const std::size_t thread_count = prog.arguments.empty()
      ? std::max(1u, boost::thread::hardware_concurrency())
      : std::stoul(prog.arguments[0]);
    constexpr const std::uint64_t max_span = 10000;

    std::vector<std::pair<std::uint64_t, std::uint64_t>> accounts{}; // (height, id)
    std::uint64_t chain_height = 0;
    {
      auto reader = MONERO_UNWRAP(prog.disk.start_read());
      const auto last = reader.get_last_block();
      if (last)
        chain_height = std::uint64_t(last->id);

      auto active = reader.get_accounts(lws::db::account_status::active);
      if (active)
      {
        for (lws::db::account const& user : active->make_range())
        {
          accounts.emplace_back(
            std::uint64_t(user.scan_height), std::uint64_t(lmdb::to_native(user.id))
          );
        }
      }
    }

    std::sort(accounts.begin(), accounts.end());

    // greedy bands, then merge cheapest adjacent pairs down to the thread budget
    std::vector<std::vector<std::pair<std::uint64_t, std::uint64_t>>> groups{};
    for (const auto& entry : accounts)
    {
      if (groups.empty() || max_span < entry.first - groups.back().front().first)
        groups.emplace_back();
      groups.back().push_back(entry);
    }
    while (thread_count < groups.size())
    {
      std::size_t best = 0;
      std::uint64_t best_cost = std::numeric_limits<std::uint64_t>::max();
      for (std::size_t i = 0; i + 1 < groups.size(); ++i)
      {
        const std::uint64_t cost = groups[i + 1].back().first - groups[i].front().first;
        if (cost < best_cost) { best_cost = cost; best = i; }
      }
      groups[best].insert(groups[best].end(), groups[best + 1].begin(), groups[best + 1].end());
      groups.erase(groups.begin() + best + 1);
    }

    wire::json_stream_writer json{out};
    json.start_object(0);
    json.key("chain_height");     json.unsigned_integer(std::uintmax_t(chain_height));
    json.key("active_accounts");  json.unsigned_integer(std::uintmax_t(accounts.size()));
    json.key("thread_count");     json.unsigned_integer(std::uintmax_t(thread_count));
    json.key("max_group_span");   json.unsigned_integer(std::uintmax_t(max_span));
    json.key("groups");
    json.start_array(0);
    for (std::size_t i = 0; i < groups.size(); ++i)
    {
      const auto& group = groups[i];
      const std::uint64_t low = group.front().first;
      const std::uint64_t high = group.back().first;

      json.start_object(0);
      json.key("thread");     json.unsigned_integer(std::uintmax_t(i));
      json.key("accounts");   json.unsigned_integer(std::uintmax_t(group.size()));
      json.key("low");        json.unsigned_integer(std::uintmax_t(low));
      json.key("high");       json.unsigned_integer(std::uintmax_t(high));
      json.key("span");       json.unsigned_integer(std::uintmax_t(high - low));
      json.key("stalls_accounts"); json.boolean(max_span < high - low);
      json.key("account_ids");
      json.start_array(0);
      for (const auto& entry : group)
        json.unsigned_integer(std::uintmax_t(entry.second));
      json.end_array();
      json.end_object();
    }
    json.end_array();
    json.end_object();
    json.finish();
  }

  /*! Run the idle sweep once, by hand.

    Same code path the daemon's hourly sweep uses, so an operator can see exactly
    who would be deactivated before turning `--account-idle-days` on. */
  void sweep_idle(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 1)
      throw std::runtime_error{"sweep_idle requires <days> (0 sweeps everything not touched right now)"};

    const std::uint64_t days = std::stoull(prog.arguments[0]);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()
    ).count();

    const std::int64_t idle_seconds = std::int64_t(days) * 24 * 60 * 60;
    if (now <= idle_seconds)
      throw std::runtime_error{"threshold is further back than the epoch"};

    const auto cutoff = lws::db::account_time(std::uint32_t(now - idle_seconds));
    const auto swept = MONERO_UNWRAP(prog.disk.deactivate_idle(cutoff));

    wire::json_stream_writer json{out};
    json.start_object(0);
    json.key("cutoff");       json.unsigned_integer(std::uintmax_t(lmdb::to_native(cutoff)));
    json.key("deactivated");  json.unsigned_integer(std::uintmax_t(swept.size()));
    json.key("addresses");
    json.start_array(0);
    for (auto const& address : swept)
      json.string(lws::db::address_string(address));
    json.end_array();
    json.end_object();
    json.finish();
  }

  void rollback(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 1)
      throw std::runtime_error{"rollback requires 1 argument"};

    const auto height = lws::db::block_id(std::stoull(prog.arguments[0]));
    MONERO_UNWRAP(prog.disk.rollback(height));

    wire::json_stream_writer json{out};
    wire::object(json, wire::field("new_height", height));
    json.finish();
  }

  struct command
  {
    char const* const name;
    void (*const handler)(program, std::ostream&);
    char const* const parameters;
    };

  static constexpr const command commands[] =
  {
    {"accept_requests",       &accept_requests, "\t<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    {"account_info",          &account_info,    "\t\t<base58 address>"},
    {"add_account",           &add_account,     "\t\t<base58 address> <view key hex>"},
    {"create_admin",          &create_admin,    ""},
    {"debug_database",        &debug_database,  ""},
    {"delete_account",        &delete_account,  "\t<base58 address> [base 58 address]..."},
    {"list_accounts",         &list_accounts,   ""},
    {"list_admin",            &list_admin,      ""},
    {"list_requests",         &list_requests,   ""},
    {"modify_account_status", &modify_account,  "\t<\"active\"|\"inactive\"|\"hidden\"> <base58 address> [base 58 address]..."},
    {"reject_requests",       &reject_requests, "\t<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    {"rescan",                &rescan,          "\t\t<height> <base58 address> [base 58 address]... (use --no-purge to keep later outputs)"},
    {"rollback",              &rollback,        "\t\t<height>"},
    {"scan_plan",             &scan_plan,       "\t\t[thread count]"},
    {"sweep_idle",            &sweep_idle,      "\t\t<days> - deactivate accounts untouched for <days>"}
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options] [command] [arguments]" << std::endl;
    out << description << std::endl;
    out << "Commands:" << std::endl;
    for (command cmd : commands)
    {
      out << "  " << cmd.name << "\t\t" << cmd.parameters << std::endl;
    }
  }

  boost::optional<std::pair<std::string, program>> get_program(int argc, char** argv)
  {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
      po::options_description description{"Options"};
      opts.prepare(description);

      po::positional_options_description positional{};
      positional.add(opts.command.name, 1);
      positional.add(opts.arguments.name, -1);

      po::store(
        po::command_line_parser(argc, argv)
        .options(description).positional(positional).run()
        , args
      );
      po::notify(args);
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
      print_help(std::cout);
      return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/

    program prog{
      lws::db::storage::open(command_line::get_arg(args, opts.db_path).c_str(), 0)
    };

    prog.show_sensitive = command_line::get_arg(args, opts.show_sensitive);
    prog.no_purge = command_line::get_arg(args, opts.no_purge);
    auto cmd = args[opts.command.name];
    if (cmd.empty())
      throw std::runtime_error{"No command given"};

    prog.arguments = command_line::get_arg(args, opts.arguments);
    return {{cmd.as<std::string>(), std::move(prog)}};
  }

  void run(boost::string_ref name, program prog, std::ostream& out)
  {
    struct by_name
    {
      bool operator()(command const& left, command const& right) const noexcept
      {
        assert(left.name && right.name);
        return std::strcmp(left.name, right.name) < 0;
      }
      bool operator()(boost::string_ref left, command const& right) const noexcept
      {
        assert(right.name);
        return left < right.name;
      }
      bool operator()(command const& left, boost::string_ref right) const noexcept
      {
        assert(left.name);
        return left.name < right;
      }
    };

    assert(std::is_sorted(std::begin(commands), std::end(commands), by_name{}));
    const auto found = std::lower_bound(
      std::begin(commands), std::end(commands), name, by_name{}
    );
    if (found == std::end(commands) || found->name != name)
      throw std::runtime_error{"No such command"};

    assert(found->handler != nullptr);
    found->handler(std::move(prog), out);

    if (out.bad())
      MONERO_THROW(std::io_errc::stream, "Writing to stdout failed");

    out << std::endl;
  }
} // anonymous

int main (int argc, char** argv)
{
  try
  {
    mlog_configure("", false, 0, 0); // disable logging

    boost::optional<std::pair<std::string, program>> prog;

    try
    {
      prog = get_program(argc, argv);
    }
    catch (std::exception const& e)
    {
      std::cerr << e.what() << std::endl << std::endl;
      print_help(std::cerr);
      return EXIT_FAILURE;
    }

    if (prog)
      run(prog->first, std::move(prog->second), std::cout);
  }
  catch (std::exception const& e)
  {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "Unknown exception" << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
