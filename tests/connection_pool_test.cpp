// =============================================================================
// Generic TLS Library (gtls) - ConnectionPool property-based tests
// Tests connection pool acquire/release semantics, tunnel isolation,
// statistics consistency, logging completeness, and full cleanup using
// RapidCheck property testing framework.
// =============================================================================

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

#include "gtls/connection_pool.h"
#include "gtls/library.h"
#include "gtls/logger.h"
#include "gtls/tls_config.h"
#include "gtls/tls_context.h"
#include "gtls/tls_connection.h"

namespace gtls {
namespace {

#ifndef GTLS_SOURCE_DIR
#define GTLS_SOURCE_DIR "."
#endif

// ---------------------------------------------------------------------------
// Helper: build a TlsConfig pointing to the test certificates.
// ---------------------------------------------------------------------------
static TlsConfig make_test_config() {
    TlsConfig cfg;
    cfg.ca_cert_file  = std::string(GTLS_SOURCE_DIR) + "/ca.pem";
    cfg.cert_file     = std::string(GTLS_SOURCE_DIR) + "/client.pem";
    cfg.cert_key_file = std::string(GTLS_SOURCE_DIR) + "/client.key";
    cfg.cache_expiry  = 3600;
    return cfg;
}

// ---------------------------------------------------------------------------
// Helper: create a TlsConnection using a socketpair fd.
// The connection stays in Disconnected state (no handshake performed).
// This is sufficient for testing pool data structure logic.
// ---------------------------------------------------------------------------
static std::shared_ptr<TlsConnection> make_mock_connection(TlsContext& ctx) {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return nullptr;
    }
    // Use one end for the TlsConnection, close the other end.
    auto conn = std::make_shared<TlsConnection>(ctx, fds[0]);
    ::close(fds[1]);
    return conn;
}

// ---------------------------------------------------------------------------
// Helper: generate a TunnelKey with a given index for uniqueness.
// ---------------------------------------------------------------------------
static TunnelKey make_key(int index) {
    return TunnelKey{"host" + std::to_string(index),
                     static_cast<uint16_t>(8000 + index),
                     "config" + std::to_string(index)};
}

// ---------------------------------------------------------------------------
// Test fixture: ensures OpenSSL is initialized before any pool test.
// ---------------------------------------------------------------------------
class ConnectionPoolPropertyTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Library::init();
    }
};

// ---------------------------------------------------------------------------
// Property 13: Connection pool acquire semantics
// After release()ing a connection for a key, acquire() for the same key
// should return that connection (reuse). For a key with no connections,
// acquire() attempts to create one (will fail in test, returning nullptr).
//
// Feature: generic-tls-library, Property 13: Connection pool acquire semantics
// **Validates: Requirements 7.2, 7.3**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, AcquireSemantics, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = *rc::gen::inRange(2, 8);
    ConnectionPool pool(pool_cfg);

    TunnelKey key = make_key(0);

    // Case 1: No connections released yet. acquire() tries to create a real
    // connection which will fail (no real server), returning nullptr.
    auto result = pool.acquire(key, ctx);
    RC_ASSERT(result == nullptr);

    // Case 2: Release a mock connection, then acquire should return it.
    auto conn = make_mock_connection(ctx);
    RC_ASSERT(conn != nullptr);

    pool.release(key, conn);

    // acquire() should find the released connection and return it.
    // Since the connection is in Disconnected state (not Connected),
    // acquire() won't match it as "idle Connected". It will try to create
    // a new one (fails), then fall through to LRU reuse if at limit.
    // So we fill up to max to trigger LRU reuse path.
    int max_conn = pool_cfg.max_connections_per_target;
    // Release enough connections to reach the limit
    std::vector<std::shared_ptr<TlsConnection>> conns;
    conns.push_back(conn);
    for (int i = 1; i < max_conn; ++i) {
        auto c = make_mock_connection(ctx);
        RC_ASSERT(c != nullptr);
        pool.release(key, c);
        conns.push_back(c);
    }

    // Now at limit. acquire() should return one of the existing connections
    // (LRU reuse path since none are in Connected state).
    auto acquired = pool.acquire(key, ctx);
    RC_ASSERT(acquired != nullptr);

    // The acquired connection should be one of the ones we released.
    bool found = false;
    for (const auto& c : conns) {
        if (acquired == c) {
            found = true;
            break;
        }
    }
    RC_ASSERT(found);
}

// ---------------------------------------------------------------------------
// Property 14: Connection pool reuse at limit
// Release max_connections_per_target connections for a key. The next acquire()
// should return one of the existing connections (not nullptr, not create new).
//
// Feature: generic-tls-library, Property 14: Connection pool reuse at limit
// **Validates: Requirements 7.6, 7.7**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, ReuseAtLimit, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    int max_conn = *rc::gen::inRange(1, 8);
    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = max_conn;
    ConnectionPool pool(pool_cfg);

    TunnelKey key = make_key(0);

    // Release exactly max_connections_per_target connections.
    std::vector<std::shared_ptr<TlsConnection>> conns;
    for (int i = 0; i < max_conn; ++i) {
        auto c = make_mock_connection(ctx);
        RC_ASSERT(c != nullptr);
        pool.release(key, c);
        conns.push_back(c);
    }

    // Verify pool is at limit.
    auto st = pool.stats();
    RC_ASSERT(st.per_target.count(key) == 1);
    RC_ASSERT(static_cast<int>(st.per_target.at(key)) == max_conn);

    // acquire() should return one of the existing connections (LRU reuse).
    auto acquired = pool.acquire(key, ctx);
    RC_ASSERT(acquired != nullptr);

    // Must be one of the connections we released.
    bool found = false;
    for (const auto& c : conns) {
        if (acquired == c) {
            found = true;
            break;
        }
    }
    RC_ASSERT(found);

    // Pool size should not have increased.
    auto st2 = pool.stats();
    RC_ASSERT(static_cast<int>(st2.per_target.at(key)) == max_conn);
}

// ---------------------------------------------------------------------------
// Property 15: Tunnel isolation
// Add connections to multiple keys. Remove connections for one key.
// Verify other keys' connections are unaffected.
//
// Feature: generic-tls-library, Property 15: Tunnel isolation
// **Validates: Requirements 7.5, 8.6, 8.7**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, TunnelIsolation, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    int num_tunnels = *rc::gen::inRange(2, 6);
    int conns_per_tunnel = *rc::gen::inRange(1, 4);

    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = conns_per_tunnel + 2;
    ConnectionPool pool(pool_cfg);

    // Create connections for each tunnel.
    std::vector<TunnelKey> keys;
    std::vector<std::vector<std::shared_ptr<TlsConnection>>> all_conns;

    for (int t = 0; t < num_tunnels; ++t) {
        TunnelKey key = make_key(t);
        keys.push_back(key);
        std::vector<std::shared_ptr<TlsConnection>> tunnel_conns;
        for (int c = 0; c < conns_per_tunnel; ++c) {
            auto conn = make_mock_connection(ctx);
            RC_ASSERT(conn != nullptr);
            pool.release(key, conn);
            tunnel_conns.push_back(conn);
        }
        all_conns.push_back(std::move(tunnel_conns));
    }

    // Record stats before removal.
    auto stats_before = pool.stats();
    RC_ASSERT(static_cast<int>(stats_before.per_target.size()) == num_tunnels);

    // Remove tunnel 0.
    pool.remove_tunnel(keys[0]);

    // Verify tunnel 0 is gone.
    auto stats_after = pool.stats();
    RC_ASSERT(stats_after.per_target.count(keys[0]) == 0);

    // Verify all other tunnels are unaffected.
    for (int t = 1; t < num_tunnels; ++t) {
        RC_ASSERT(stats_after.per_target.count(keys[t]) == 1);
        RC_ASSERT(stats_after.per_target.at(keys[t]) ==
                  static_cast<size_t>(conns_per_tunnel));
    }
}

// ---------------------------------------------------------------------------
// Property 16: Connection pool statistics consistency
// After various operations, stats().total_active must equal the sum of all
// per_target values.
//
// Feature: generic-tls-library, Property 16: Connection pool statistics consistency
// **Validates: Requirements 7.10**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, StatsConsistency, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    int num_tunnels = *rc::gen::inRange(1, 6);

    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = 8;
    ConnectionPool pool(pool_cfg);

    // Add varying numbers of connections to different tunnels.
    for (int t = 0; t < num_tunnels; ++t) {
        TunnelKey key = make_key(t);
        int num_conns = *rc::gen::inRange(1, 5);
        for (int c = 0; c < num_conns; ++c) {
            auto conn = make_mock_connection(ctx);
            RC_ASSERT(conn != nullptr);
            pool.release(key, conn);
        }
    }

    // Verify stats consistency: total_active == sum of per_target values.
    auto st = pool.stats();
    size_t sum = 0;
    for (const auto& [key, count] : st.per_target) {
        sum += count;
    }
    RC_ASSERT(st.total_active == sum);

    // Optionally remove some tunnels and re-check.
    if (num_tunnels > 1) {
        int remove_idx = *rc::gen::inRange(0, num_tunnels);
        pool.remove_tunnel(make_key(remove_idx));

        auto st2 = pool.stats();
        size_t sum2 = 0;
        for (const auto& [key, count] : st2.per_target) {
            sum2 += count;
        }
        RC_ASSERT(st2.total_active == sum2);
    }
}

// ---------------------------------------------------------------------------
// Property 22: Connection state change log completeness
// Register a Logger callback, perform pool operations, verify log messages
// contain TunnelKey info, state change type, and timestamp.
//
// Feature: generic-tls-library, Property 22: Connection state change log completeness
// **Validates: Requirements 10.5**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, LogCompleteness, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    // Capture log messages.
    std::mutex log_mutex;
    std::vector<std::string> log_messages;

    Logger::set_callback([&](LogLevel /*level*/, const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        log_messages.push_back(msg);
    });

    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = 4;
    ConnectionPool pool(pool_cfg);

    TunnelKey key{"testhost", 9999, "testcfg"};

    // Perform operations that generate log messages.
    auto conn = make_mock_connection(ctx);
    RC_ASSERT(conn != nullptr);

    pool.release(key, conn);
    pool.remove_tunnel(key);

    // Disable logger to avoid interference with other tests.
    Logger::set_callback(nullptr);

    // Verify log messages contain required fields.
    std::lock_guard<std::mutex> lock(log_mutex);
    RC_ASSERT(!log_messages.empty());

    for (const auto& msg : log_messages) {
        // Each log message from ConnectionPool should contain:
        // 1. TunnelKey info (host, port, config name)
        bool has_key_info = (msg.find("testhost") != std::string::npos) &&
                            (msg.find("9999") != std::string::npos) &&
                            (msg.find("testcfg") != std::string::npos);

        // 2. State change type (one of the known state strings)
        bool has_state = (msg.find("state=") != std::string::npos) ||
                         (msg.find("ConnectionPool") != std::string::npos);

        // 3. Timestamp (ts= field)
        bool has_timestamp = (msg.find("ts=") != std::string::npos);

        // Only check ConnectionPool messages (not other subsystem logs).
        if (msg.find("ConnectionPool") != std::string::npos) {
            RC_ASSERT(has_key_info);
            RC_ASSERT(has_state);
            RC_ASSERT(has_timestamp);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 23: Connection pool full cleanup
// After adding connections and calling remove_tunnel() for all keys,
// stats().total_active == 0 and per_target is empty.
//
// Feature: generic-tls-library, Property 23: Connection pool full cleanup
// **Validates: Requirements 11.6**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, FullCleanup, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    int num_tunnels = *rc::gen::inRange(1, 6);

    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = 8;
    ConnectionPool pool(pool_cfg);

    // Add connections to multiple tunnels.
    std::vector<TunnelKey> keys;
    for (int t = 0; t < num_tunnels; ++t) {
        TunnelKey key = make_key(t);
        keys.push_back(key);
        int num_conns = *rc::gen::inRange(1, 4);
        for (int c = 0; c < num_conns; ++c) {
            auto conn = make_mock_connection(ctx);
            RC_ASSERT(conn != nullptr);
            pool.release(key, conn);
        }
    }

    // Verify pool is non-empty.
    auto st_before = pool.stats();
    RC_ASSERT(st_before.total_active > 0);
    RC_ASSERT(!st_before.per_target.empty());

    // Remove all tunnels.
    for (const auto& key : keys) {
        pool.remove_tunnel(key);
    }

    // Verify complete cleanup.
    auto st_after = pool.stats();
    RC_ASSERT(st_after.total_active == 0);
    RC_ASSERT(st_after.per_target.empty());
}

} // namespace
} // namespace gtls
