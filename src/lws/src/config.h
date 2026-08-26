#pragma once

#include "cryptonote_config.h"

namespace lws
{
namespace config
{
  extern cryptonote::network_type network;

  /*! When true, `login` creates an active account immediately. When false it
      queues a `create` request for an admin to approve, which is what makes
      `create-queue-max` and the `list_requests`/`accept_requests` pair mean
      anything. */
  extern bool auto_accept_accounts;
}
}