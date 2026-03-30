// =============================================================================
// Unit tests for the gtls::Logger module.
// Tests cover: set_callback, log formatting, enable_keylog, level_to_string.
// =============================================================================

#include <gtest/gtest.h>
#include "gtls/logger.h"

#include <atomic>
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace {

// Helper to capture log messages during tests.
struct LogCapture {
    gtls::LogLevel last_level = gtls::LogLevel::Debug;
    std::string last_message;
    int call_count = 0;

    gtls::LogCallback callback() {
        return [this](gtls::LogLevel level, const std::string& msg) {
            last_level = level;
            last_message = msg;
            ++call_count;
        };
    }
};

// Test fixture that resets Logger state after each test.
class LoggerTest : public ::testing::Test {
protected:
    void TearDown() override {
        gtls::Logger::set_callback(nullptr);
        gtls::Logger::disable_keylog();
    }
};

} // namespace

// --- set_callback / log tests ---

TEST_F(LoggerTest, LogWithNoCallbackDoesNotCrash) {
    // Logging without a registered callback should be a silent no-op.
    EXPECT_NO_THROW(gtls::Logger::log(gtls::LogLevel::Info, "hello %s", "world"));
}

TEST_F(LoggerTest, SetCallbackReceivesMessages) {
    LogCapture cap;
    gtls::Logger::set_callback(cap.callback());

    gtls::Logger::log(gtls::LogLevel::Error, "error code %d", 42);

    EXPECT_EQ(cap.call_count, 1);
    EXPECT_EQ(cap.last_level, gtls::LogLevel::Error);
    EXPECT_EQ(cap.last_message, "error code 42");
}

TEST_F(LoggerTest, LogFormatsMultipleArguments) {
    LogCapture cap;
    gtls::Logger::set_callback(cap.callback());

    gtls::Logger::log(gtls::LogLevel::Warning, "%s=%d, pi=%.2f", "x", 10, 3.14);

    EXPECT_EQ(cap.last_level, gtls::LogLevel::Warning);
    EXPECT_EQ(cap.last_message, "x=10, pi=3.14");
}

TEST_F(LoggerTest, LogFormatsEmptyString) {
    LogCapture cap;
    gtls::Logger::set_callback(cap.callback());

    gtls::Logger::log(gtls::LogLevel::Debug, "");

    EXPECT_EQ(cap.call_count, 1);
    EXPECT_EQ(cap.last_message, "");
}

TEST_F(LoggerTest, SetCallbackToNullDisablesLogging) {
    LogCapture cap;
    gtls::Logger::set_callback(cap.callback());
    gtls::Logger::log(gtls::LogLevel::Info, "first");
    EXPECT_EQ(cap.call_count, 1);

    // Disable callback
    gtls::Logger::set_callback(nullptr);
    gtls::Logger::log(gtls::LogLevel::Info, "second");

    // Count should not increase
    EXPECT_EQ(cap.call_count, 1);
}

TEST_F(LoggerTest, CallbackCanBeReplaced) {
    LogCapture cap1;
    LogCapture cap2;

    gtls::Logger::set_callback(cap1.callback());
    gtls::Logger::log(gtls::LogLevel::Info, "msg1");
    EXPECT_EQ(cap1.call_count, 1);
    EXPECT_EQ(cap2.call_count, 0);

    gtls::Logger::set_callback(cap2.callback());
    gtls::Logger::log(gtls::LogLevel::Info, "msg2");
    EXPECT_EQ(cap1.call_count, 1);
    EXPECT_EQ(cap2.call_count, 1);
    EXPECT_EQ(cap2.last_message, "msg2");
}

// --- level_to_string tests ---

TEST_F(LoggerTest, LevelToStringCoversAllLevels) {
    EXPECT_STREQ(gtls::Logger::level_to_string(gtls::LogLevel::Error), "ERROR");
    EXPECT_STREQ(gtls::Logger::level_to_string(gtls::LogLevel::Warning), "WARNING");
    EXPECT_STREQ(gtls::Logger::level_to_string(gtls::LogLevel::Notice), "NOTICE");
    EXPECT_STREQ(gtls::Logger::level_to_string(gtls::LogLevel::Info), "INFO");
    EXPECT_STREQ(gtls::Logger::level_to_string(gtls::LogLevel::Debug), "DEBUG");
}

// --- enable_keylog tests ---

TEST_F(LoggerTest, EnableKeylogCreatesFile) {
    const std::string path = "/tmp/gtls_test_keylog.txt";
    std::remove(path.c_str());

    gtls::Logger::enable_keylog(path);

    // Verify the file was created
    std::ifstream f(path);
    EXPECT_TRUE(f.good());
    f.close();

    gtls::Logger::disable_keylog();
    std::remove(path.c_str());
}

TEST_F(LoggerTest, EnableKeylogInvalidPathLogsError) {
    LogCapture cap;
    gtls::Logger::set_callback(cap.callback());

    // Attempt to open a file in a non-existent directory
    gtls::Logger::enable_keylog("/nonexistent/dir/keylog.txt");

    // Should have logged an error
    EXPECT_GE(cap.call_count, 1);
    EXPECT_EQ(cap.last_level, gtls::LogLevel::Error);
}

TEST_F(LoggerTest, DisableKeylogClosesFile) {
    const std::string path = "/tmp/gtls_test_keylog_disable.txt";
    std::remove(path.c_str());

    gtls::Logger::enable_keylog(path);
    gtls::Logger::disable_keylog();

    // After disable, enable_keylog with a new path should work
    const std::string path2 = "/tmp/gtls_test_keylog_disable2.txt";
    std::remove(path2.c_str());
    gtls::Logger::enable_keylog(path2);

    std::ifstream f(path2);
    EXPECT_TRUE(f.good());
    f.close();

    gtls::Logger::disable_keylog();
    std::remove(path.c_str());
    std::remove(path2.c_str());
}

// --- Thread safety smoke test ---

TEST_F(LoggerTest, ConcurrentLogCallsDoNotCrash) {
    std::atomic<int> count{0};
    gtls::Logger::set_callback(
        [&count](gtls::LogLevel /*level*/, const std::string& /*msg*/) {
            count.fetch_add(1, std::memory_order_relaxed);
        });

    constexpr int kThreads = 4;
    constexpr int kMessagesPerThread = 100;
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t]() {
            for (int i = 0; i < kMessagesPerThread; ++i) {
                gtls::Logger::log(gtls::LogLevel::Debug,
                                  "thread=%d msg=%d", t, i);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    EXPECT_EQ(count.load(), kThreads * kMessagesPerThread);
}
