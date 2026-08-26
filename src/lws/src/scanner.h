#pragma once

#include <atomic>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <vector>
#include <cstddef>
#include <string>
#include "epee/misc_log_ex.h"
#include "db/storage.h"
#include "db/data.h"
#include "rpc/client.h"

namespace lws
{
    /*! Live state of one scan thread, as reported by `/scanner_status`.

      Populated by the scan threads themselves and copied out under a lock, so
      the admin endpoint never blocks a scan. */
    struct scan_thread_status
    {
        std::size_t index{0};                    //!< Matches the `scan[N]` log prefix.
        std::vector<db::account_id> accounts{};  //!< Accounts this thread carries.
        std::uint64_t group_low{0};              //!< Lowest scan height in the group at start.
        std::uint64_t group_high{0};             //!< Highest scan height in the group at start.
        std::uint64_t current_height{0};         //!< Height of the most recent committed batch.
        std::uint64_t blocks_scanned{0};         //!< Blocks scanned since this thread started.
        double blocks_per_second{0};             //!< Rate of the most recent batch.
        std::int64_t last_commit{0};             //!< Unix seconds of last commit; 0 if never.
        std::uint64_t last_batch_ms{0};          //!< Duration of the most recent batch.
        std::string last_error{};                //!< Most recent batch error, if any.
        unsigned consecutive_failures{0};        //!< Failed batches since the last good one.
        bool alive{false};                       //!< False once the thread has exited.
    };

    //! Live state of the scanner as a whole.
    struct scanner_status
    {
        bool running{false};
        std::uint64_t daemon_height{0};   //!< Chain tip last seen by any scan thread.
        std::uint64_t restarts{0};        //!< Scan-thread teardowns since process start.
        std::uint64_t deactivated{0};     //!< Accounts idle-swept since process start.
        std::int64_t last_sweep{0};       //!< Unix seconds of the last idle sweep; 0 if never.
        std::int64_t last_restart{0};     //!< Unix seconds of the most recent teardown.
        std::string last_restart_reason{};
        std::vector<scan_thread_status> threads{};
    };

    //! Tunables for `scanner::run`, all settable from the command line.
    struct scanner_options
    {
        std::size_t thread_count{1};
        /*! Maximum scan-height difference tolerated inside one thread group.
            Accounts in a group advance from the group's lowest height, so a wide
            span means the ones near the top idle. */
        std::uint64_t max_group_span{10000};
        //! Blocks requested per `get_blocks_fast`; halved on timeout, ramped on success.
        std::uint64_t batch_size{1000};
        //! Ask the daemon for raw blobs instead of the legacy JSON transport.
        bool blob_transport{true};
        /*! Deactivate accounts untouched for this many seconds. Zero disables
            the sweep entirely, which is the default. */
        std::uint64_t account_idle_timeout{0};
    };

    class scanner
    {
        static std::atomic<bool> running;
        static std::atomic<bool> failed;
        scanner() = delete;

    public:

        //! Use `client` to sync blockchain data, and \return client if successful.
        static void sync(db::storage disk,std::string daemon_rpc);

        //! Poll daemon until `stop()` is called.
        static void run(db::storage disk, std::string daemon_rpc, scanner_options options);

        //! \return True if `stop()` has never been called.
        static bool is_running() noexcept { return running; }

        /*! \return True if the scanner stopped because of an error rather than
            an operator request. Callers should exit non-zero in that case. */
        static bool stopped_on_error() noexcept { return failed; }

        /*! Stop all scanner instances globally. This is for shutdown, not for
            error handling - a scan thread that hits a transient daemon problem
            backs off and retries instead of taking the process down with it. */
        static void stop() noexcept { running = false; }

        //! \return A consistent snapshot of live scanner state.
        static scanner_status status();

        //! Stop all scanner instances because of an unrecoverable `reason`.
        static void fail(const char* reason) noexcept
        {
            failed = true;
            running = false;
            MERROR("Scanner stopping, unrecoverable: " << reason);
        }
    };

} //lws