// Main test entry point for the gtls library test suite.
// Google Test provides its own main() via gtest_main, so this file
// contains a minimal smoke test to verify the build infrastructure works.

#include <gtest/gtest.h>
#include <rapidcheck.h>
#include <rapidcheck/gtest.h>

#include <signal.h>

// Global test environment: ignore SIGPIPE to prevent process termination
// when writing to closed sockets during TLS shutdown in loopback tests.
class GlobalTestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        signal(SIGPIPE, SIG_IGN);
    }
};

// Register the global environment before any tests run.
static auto* const g_env =
    ::testing::AddGlobalTestEnvironment(new GlobalTestEnvironment);

// Smoke test: verify Google Test is functional
TEST(BuildInfrastructure, GoogleTestWorks) {
    EXPECT_TRUE(true);
}

// Smoke test: verify RapidCheck integration is functional
RC_GTEST_PROP(BuildInfrastructure, RapidCheckWorks, ()) {
    const auto x = *rc::gen::inRange(0, 100);
    RC_ASSERT(x >= 0);
    RC_ASSERT(x < 100);
}
