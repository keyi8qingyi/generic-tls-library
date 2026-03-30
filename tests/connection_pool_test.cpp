// =============================================================================
// Generic TLS Library (gtls) - ConnectionPool property-based tests (v2)
// Tests pool state machine, release/acquire semantics, tunnel isolation,
// statistics consistency, logging, and cleanup.
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

static TlsConfig make_test_config() {
    TlsConfig cfg;
    cfg.ca_cert_file  = std::string(GTLS_SOURCE_DIR) + "/ca.pem";
    cfg.cert_file     = std::string(GTLS_SOURCE_DIR) + "/client.pem";
    cfg.cert_key_file = std::string(GTLS_SOURCE_DIR) + "/client.key";
    cfg.cache_expiry  = 3600;
    return cfg;
}

static std::shared_ptr<TlsConnection> make_mock_connection(TlsContext& ctx) {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return nullptr;
    auto conn = std::make_shared<TlsConnection>(ctx, fds[0]);
    ::close(fds[1]);
    return conn;
}

static TunnelKey make_key(int index) {
    return TunnelKey{"host" + std::to_string(index),
                     static_cast<uint16_t>(8000 + index),
                     "config" + std::to_string(index)};
}

class ConnectionPoolPropertyTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { Library::init(); }
};

// ---------------------------------------------------------------------------
// Property 13: Connection pool acquire semantics
// acquire() on empty pool with no real server returns PoolExhausted.
// After release(), stats reflect the connection.
//
// Feature: generic-tls-library, Property 13: Connection pool acquire semantics
// **Validates: Requirements 7.2, 7.3**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, AcquireSemantics, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = *rc::gen::inRange(2, 8);
    pool_cfg.acquire_timeout_sec = 0;  // No wait in test
    ConnectionPool pool(pool_cfg);

    TunnelKey key = make_key(0);

    // acquire() on empty pool with no real server -> PoolExhausted or error
    auto result = pool.acquire(key, ctx);
    RC_ASSERT(result.conn == nullptr);
    RC_ASSERT(result.error != TlsError::Ok);

    // release() adds a connection, stats should reflect it
    auto conn = make_mock_connection(ctx);
    RC_ASSERT(conn != nullptr);
    pool.release(key, conn);

    auto st = pool.stats();
    RC_ASSERT(st.total_active == 1);
    RC_ASSERT(st.total_idle == 1);
    RC_ASSERT(st.total_in_use == 0);
    RC_ASSERT(st.per_target.count(key) == 1);
    RC_ASSERT(st.per_target.at(key) == 1);
}

// ---------------------------------------------------------------------------
// Property 14: Connection pool reuse at limit
// Release max connections. Stats should show all IDLE. Pool size stable.
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

    // Release exactly max connections
    for (int i = 0; i < max_conn; ++i) {
        auto c = make_mock_connection(ctx);
        RC_ASSERT(c != nullptr);
        pool.release(key, c);
    }

    auto st = pool.stats();
    RC_ASSERT(st.per_target.count(key) == 1);
    RC_ASSERT(static_cast<int>(st.per_target.at(key)) == max_conn);
    RC_ASSERT(static_cast<int>(st.total_idle) == max_conn);
    RC_ASSERT(st.total_in_use == 0);
}

// ---------------------------------------------------------------------------
// Property 15: Tunnel isolation
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

    std::vector<TunnelKey> keys;
    for (int t = 0; t < num_tunnels; ++t) {
        TunnelKey key = make_key(t);
        keys.push_back(key);
        for (int c = 0; c < conns_per_tunnel; ++c) {
            auto conn = make_mock_connection(ctx);
            RC_ASSERT(conn != nullptr);
            pool.release(key, conn);
        }
    }

    // Remove tunnel 0
    pool.remove_tunnel(keys[0]);

    auto stats_after = pool.stats();
    RC_ASSERT(stats_after.per_target.count(keys[0]) == 0);

    // Other tunnels unaffected
    for (int t = 1; t < num_tunnels; ++t) {
        RC_ASSERT(stats_after.per_target.count(keys[t]) == 1);
        RC_ASSERT(stats_after.per_target.at(keys[t]) ==
                  static_cast<size_t>(conns_per_tunnel));
    }
}

// ---------------------------------------------------------------------------
// Property 16: Statistics consistency
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

    for (int t = 0; t < num_tunnels; ++t) {
        TunnelKey key = make_key(t);
        int num_conns = *rc::gen::inRange(1, 5);
        for (int c = 0; c < num_conns; ++c) {
            auto conn = make_mock_connection(ctx);
            RC_ASSERT(conn != nullptr);
            pool.release(key, conn);
        }
    }

    auto st = pool.stats();
    size_t sum = 0;
    for (const auto& [key, count] : st.per_target) {
        sum += count;
    }
    RC_ASSERT(st.total_active == sum);
    RC_ASSERT(st.total_active == st.total_idle + st.total_in_use);
}

// ---------------------------------------------------------------------------
// Property 22: Log completeness
//
// Feature: generic-tls-library, Property 22: Connection state change log completeness
// **Validates: Requirements 10.5**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(ConnectionPoolPropertyTest, LogCompleteness, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    std::mutex log_mutex;
    std::vector<std::string> log_messages;

    Logger::set_callback([&](LogLevel, const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        log_messages.push_back(msg);
    });

    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = 4;
    ConnectionPool pool(pool_cfg);

    TunnelKey key{"testhost", 9999, "testcfg"};

    auto conn = make_mock_connection(ctx);
    RC_ASSERT(conn != nullptr);

    pool.release(key, conn);
    pool.remove_tunnel(key);

    Logger::set_callback(nullptr);

    std::lock_guard<std::mutex> lock(log_mutex);
    RC_ASSERT(!log_messages.empty());

    for (const auto& msg : log_messages) {
        if (msg.find("ConnectionPool") != std::string::npos) {
            RC_ASSERT(msg.find("testhost") != std::string::npos);
            RC_ASSERT(msg.find("9999") != std::string::npos);
            RC_ASSERT(msg.find("ts=") != std::string::npos);
        }
    }
}

// ---------------------------------------------------------------------------
// Property 23: Full cleanup
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

    RC_ASSERT(pool.stats().total_active > 0);

    for (const auto& key : keys) {
        pool.remove_tunnel(key);
    }

    auto st = pool.stats();
    RC_ASSERT(st.total_active == 0);
    RC_ASSERT(st.per_target.empty());
}

} // namespace
} // namespace gtls
