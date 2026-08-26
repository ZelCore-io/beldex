// #include <boost/filesystem/operations.hpp>
#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/thread/thread.hpp>
#include <boost/filesystem.hpp>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/command_line.h"      //beldex/common
#include "common/util.h"              //beldex/common
#include "config.h"
#include "cryptonote_config.h"        //beldex/src/
#include "db/storage.h"
#include "error.h"
//#include "rpc/client.h"
#include "options.h"
#include "rest_server.h"
#include <algorithm>
#include "rpc/admin.h"
#include "scanner.h"

namespace
{
  struct options : lws::options
  {
    const command_line::arg_descriptor<std::string> daemon_rpc;
    const command_line::arg_descriptor<std::string> daemon_sub;
    const command_line::arg_descriptor<std::vector<std::string>> rest_servers;
    const command_line::arg_descriptor<std::vector<std::string>> admin_rest_servers;
    const command_line::arg_descriptor<std::string> rest_ssl_key;
    const command_line::arg_descriptor<std::string> rest_ssl_cert;
    const command_line::arg_descriptor<std::size_t> rest_threads;
    const command_line::arg_descriptor<std::size_t> scan_threads;
    const command_line::arg_descriptor<std::uint64_t> max_group_span;
    const command_line::arg_descriptor<std::uint64_t> scan_batch_size;
    const command_line::arg_descriptor<bool> no_blob_transport;
    const command_line::arg_descriptor<std::uint64_t> account_idle_days;
    const command_line::arg_descriptor<std::vector<std::string>> access_controls;
    const command_line::arg_descriptor<bool> external_bind;
    const command_line::arg_descriptor<unsigned> create_queue_max;
    const command_line::arg_descriptor<bool> require_account_approval;
    const command_line::arg_descriptor<std::chrono::minutes::rep> rates_interval;
    const command_line::arg_descriptor<unsigned short> log_level;
    const command_line::arg_descriptor<std::string> config_file;

    static std::string get_default_zmq()
    {
      static constexpr const char base[] = "http://127.0.0.1:";
      switch (lws::config::network)
      {
      case cryptonote::network_type::TESTNET:
        return base + std::to_string(cryptonote::config::testnet::RPC_DEFAULT_PORT);
      case cryptonote::network_type::DEVNET:
        return base + std::to_string(cryptonote::config::devnet::RPC_DEFAULT_PORT);
      case cryptonote::network_type::MAINNET:
      default:
        break;
      }
      return base + std::to_string(cryptonote::config::RPC_DEFAULT_PORT);
    }

    options()
      : lws::options()
      , daemon_rpc{"daemon", "[(https|http)://<address>:]<port> for daemon connections", get_default_zmq()}
      , daemon_sub{"sub", "tcp://address:port or ipc://path of a beldexd OMQ Pub", ""}
      , rest_servers{"rest-server", "[(https|http)://<address>:]<port>[/<prefix>] for incoming connections, multiple declarations allowed"}
      , admin_rest_servers{"admin-rest-server", "[(https|http])://<address>:]<port>[/<prefix>] for incoming admin connections, multiple declarations allowed"}      , rest_ssl_key{"rest-ssl-key", "<path> to PEM formatted SSL key for https REST server", ""}
      , rest_ssl_cert{"rest-ssl-certificate", "<path> to PEM formatted SSL certificate (chains supported) for https REST server", ""}
      , rest_threads{"rest-threads", "Number of threads to process REST connections", 1}
      , scan_threads{"scan-threads", "Maximum number of threads for account scanning", boost::thread::hardware_concurrency()}
      , max_group_span{"max-group-span", "Maximum scan-height spread within one scan thread; accounts above a group's lowest height idle until it catches up", 10000}
      , scan_batch_size{"scan-batch-size", "Blocks requested per daemon call (daemon caps at 1000); halved on timeout, ramped on success", 1000}
      , no_blob_transport{"no-blob-transport", "Use the legacy JSON block transport instead of raw blobs", false}
      , account_idle_days{"account-idle-days", "Stop scanning accounts untouched for this many days; they reactivate on their next login and resume from their stored height. 0 disables (30 is a sensible starting point)", 0}
      , access_controls{"access-control-origin", "Specify a whitelisted HTTP control origin domain"}
      , external_bind{"confirm-external-bind", "Allow listening for external connections", false}
      , create_queue_max{"create-queue-max", "Set pending create account requests maximum", 10000}
      , require_account_approval{"require-account-approval", "Queue new logins for admin approval instead of activating them immediately", false}
      , rates_interval{"exchange-rate-interval", "Retrieve exchange rates in minute intervals from cryptocompare.com if greater than 0", 0}
      , log_level{"log-level", "Log level [0-4]", 1}
      , config_file{"config-file", "Specify any option in a config file; <name>=<value> on separate lines"}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      static constexpr const char rest_default[] = "https://0.0.0.0:8443";

      lws::options::prepare(description);
      command_line::add_arg(description, daemon_rpc);
      command_line::add_arg(description, daemon_sub);
      description.add_options()(rest_servers.name, boost::program_options::value<std::vector<std::string>>()->default_value({rest_default}, rest_default), rest_servers.description);
      command_line::add_arg(description, admin_rest_servers);
      command_line::add_arg(description, rest_ssl_key);
      command_line::add_arg(description, rest_ssl_cert);
      command_line::add_arg(description, rest_threads);
      command_line::add_arg(description, scan_threads);
      command_line::add_arg(description, max_group_span);
      command_line::add_arg(description, scan_batch_size);
      command_line::add_arg(description, no_blob_transport);
      command_line::add_arg(description, account_idle_days);
      command_line::add_arg(description, access_controls);
      command_line::add_arg(description, external_bind);
      command_line::add_arg(description, create_queue_max);
      command_line::add_arg(description, require_account_approval);
      command_line::add_arg(description, rates_interval);
      command_line::add_arg(description, log_level);
      command_line::add_arg(description, config_file);
    }
  };
 struct program
  {
    std::string db_path;
    std::vector<std::string> rest_servers;
    std::vector<std::string> admin_rest_servers;
    lws::rest_server::configuration rest_config;
    std::string daemon_rpc;
    std::string daemon_sub;
    std::chrono::minutes rates_interval;
    lws::scanner_options scan;
    unsigned create_queue_max;
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options]" << std::endl;
    out << description;
  }

 boost::optional<program> get_program(int argc, char **argv)
 {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
        po::options_description description{"Options"};
        opts.prepare(description);

        po::store(
            po::command_line_parser(argc, argv).options(description).run(), args);
        po::notify(args);
      if (!command_line::is_arg_defaulted(args, opts.config_file))
      {
        boost::filesystem::path config_path{command_line::get_arg(args, opts.config_file)};
        if (!boost::filesystem::exists(config_path))
          MONERO_THROW(lws::error::configuration, "Config file does not exist");

        po::store(
          po::parse_config_file<char>(config_path.string<std::string>().c_str(), description), args
        );
        po::notify(args);
      }
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
        print_help(std::cout);
        return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/
    lws::config::auto_accept_accounts = !command_line::get_arg(args, opts.require_account_approval);
    mlog_set_log_level(command_line::get_arg(args, opts.log_level));

    program prog{
        command_line::get_arg(args, opts.db_path),
        command_line::get_arg(args, opts.rest_servers),
        command_line::get_arg(args, opts.admin_rest_servers),
        lws::rest_server::configuration{
            {command_line::get_arg(args, opts.rest_ssl_key), command_line::get_arg(args, opts.rest_ssl_cert)},
            command_line::get_arg(args, opts.access_controls),
            command_line::get_arg(args, opts.rest_threads),
            command_line::get_arg(args, opts.external_bind)},
        command_line::get_arg(args, opts.daemon_rpc),
        command_line::get_arg(args, opts.daemon_sub),
        std::chrono::minutes{command_line::get_arg(args, opts.rates_interval)},
        lws::scanner_options{
            command_line::get_arg(args, opts.scan_threads),
            command_line::get_arg(args, opts.max_group_span),
            command_line::get_arg(args, opts.scan_batch_size),
            !command_line::get_arg(args, opts.no_blob_transport),
            command_line::get_arg(args, opts.account_idle_days) * 24 * 60 * 60},
        command_line::get_arg(args, opts.create_queue_max),
    };

    prog.rest_config.threads = std::max(std::size_t(1), prog.rest_config.threads);
    prog.scan.thread_count = std::max(std::size_t(1), prog.scan.thread_count);

    // Detect IPC mode
  const bool ipc_mode = prog.daemon_rpc.rfind("ipc://", 0) == 0;

  if (command_line::is_arg_defaulted(args, opts.daemon_rpc))
  {
      prog.daemon_rpc = options::get_default_zmq();

      // Append only for HTTP mode
      if (!ipc_mode)
          prog.daemon_rpc += "/json_rpc";
  }
  else
  {
      // Append only for HTTP mode
      if (!ipc_mode)
          prog.daemon_rpc += "/json_rpc";
  }

    // For cpr::Post HTTP calls in rest_server.cpp, always use HTTP endpoint
    if (prog.daemon_rpc.rfind("ipc://", 0) == 0)
      lws::daemon_add = options::get_default_zmq() + "/json_rpc";
    else
      lws::daemon_add = prog.daemon_rpc;
    return prog;
  }
  //! \return The scan thread carrying `id`, for the `account_info` admin endpoint.
  boost::optional<lws::rpc::account_scan_slot> find_scan_slot(lws::db::account_id id)
  {
    const lws::scanner_status status = lws::scanner::status();
    for (const auto& thread : status.threads)
    {
      if (!thread.alive)
        continue;
      if (std::find(thread.accounts.begin(), thread.accounts.end(), id) == thread.accounts.end())
        continue;
      return lws::rpc::account_scan_slot{thread.index, thread.group_low, thread.group_high};
    }
    return boost::none;
  }

  void run(program prog)
  {
    std::signal(SIGINT, [] (int) { lws::scanner::stop(); });
    lws::rpc::account_scan_slot_of = &find_scan_slot;
    fs::create_directories(prog.db_path);
    auto disk = lws::db::storage::open(prog.db_path.c_str(), prog.create_queue_max);
    MINFO("Using beldexd RPC at " << prog.daemon_rpc);

    /* Bring the REST servers up before the initial chain sync. The sync walks
       every block hash from the last stored height to the tip, which on a fresh
       database is the whole chain - previously nothing answered until it
       finished. The REST servers run on their own io_service threads. */
    lws::rest_server server{
      epee::to_span(prog.rest_servers), prog.admin_rest_servers, disk.clone(), std::move(prog.rest_config)
    };
    for (const std::string& address : prog.rest_servers)
      MINFO("Listening for REST clients at " << address);
    for (const std::string& address : prog.admin_rest_servers)
      MINFO("Listening for REST admin clients at " << address);

    lws::scanner::sync(disk.clone(),prog.daemon_rpc);

        // blocks until SIGINT
   lws::scanner::run(std::move(disk), prog.daemon_rpc, prog.scan);

   if (lws::scanner::stopped_on_error())
     throw std::runtime_error{"Scanner stopped because of an unrecoverable error"};
  }
} // anonymous

int main(int argc, char **argv)
{
    tools::on_startup(); // if it throws, don't use MERROR just print default msg

    try
    {
        boost::optional<program> prog;

        try
        {
            prog = get_program(argc, argv);
        }
        catch (std::exception const &e)
        {
            std::cerr << e.what() << std::endl
                      << std::endl;
            print_help(std::cerr);
            return EXIT_FAILURE;
        }

        if (prog)
            run(std::move(*prog));
    }
    catch (std::exception const &e)
    {
        MERROR(e.what());
        return EXIT_FAILURE;
    }
    catch (...)
    {
        MERROR("Unknown exception");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
