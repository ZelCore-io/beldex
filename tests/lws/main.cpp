#include "gtest/gtest.h"

#include "common/util.h"
#include "config.h"
#include "cryptonote_config.h"
#include "epee/misc_log_ex.h"

int main(int argc, char** argv)
{
  tools::on_startup();
  mlog_configure("", false, 0, 0); // tests are noisy enough without scanner logs
  lws::config::network = cryptonote::network_type::MAINNET;

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
