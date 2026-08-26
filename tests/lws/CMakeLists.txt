# Unit tests for the light wallet server.
#
# A target of its own rather than more files in unit_tests: it links only the
# LWS libraries, so it builds and runs in seconds while iterating on the scanner
# or the storage layer.

add_executable(lws_tests
  main.cpp
  scan_planner.cpp
  storage.cpp)

target_link_libraries(lws_tests
  PRIVATE
    beldex-lws-common
    beldex-lws-db
    cncrypto
    cryptonote_basic
    filesystem
    Boost::thread
    gtest
    Threads::Threads
    extra)

target_include_directories(lws_tests PRIVATE "${CMAKE_SOURCE_DIR}/src/lws/src")

set_property(TARGET lws_tests PROPERTY FOLDER "tests")
add_test(NAME lws_tests COMMAND lws_tests)
