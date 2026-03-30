// =============================================================================
// Generic TLS Library (gtls) - Integration tests
// End-to-end tests using real TLS connections over loopback socketpairs.
// Covers: TLS handshake (12.1), TLS I/O (12.2), ConnectionPool + ProtocolAdapter (12.3).
// =============================================================================

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "gtls/connection_pool.h"
#include "gtls/library.h"
#include "gtls/logger.h"
#include "gtls/protocol_adapter.h"
#include "gtls/tls_config.h"
#include "gtls/tls_connection.h"
#include "gtls/tls_context.h"
#include "gtls/tls_io.h"

namespace gtls {
namespace {

#ifndef GTLS_SOURCE_DIR
#define GTLS_SOURCE_DIR "."
#endif

// ---------------------------------------------------------------------------
// Helper: build a TlsConfig pointing to the self-signed test certificates.
// Uses the same cert/key for both client and server roles.
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
// Helper: create a Unix socketpair for loopback TLS testing.
// Returns {client_fd, server_fd}. Both fds are valid on success.
// ---------------------------------------------------------------------------
static std::pair<int, int> create_socketpair() {
    int fds[2] = {-1, -1};
    int ret = ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (ret != 0) {
        return {-1, -1};
    }
    return {fds[0], fds[1]};
}

// ---------------------------------------------------------------------------
// Helper: create a mock TlsConnection on a socketpair fd (no handshake).
// Useful for pool/adapter tests that don't need a real TLS session.
// ---------------------------------------------------------------------------
static std::shared_ptr<TlsConnection> make_mock_connection(TlsContext& ctx) {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return nullptr;
    }
    auto conn = std::make_shared<TlsConnection>(ctx, fds[0]);
    ::close(fds[1]);
    return conn;
}

// ---------------------------------------------------------------------------
// Test fixture: initializes OpenSSL once for all integration tests.
// ---------------------------------------------------------------------------
class IntegrationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Library::init();
    }
};

// =========================================================================
// 12.1 — TLS Handshake Integration Tests
// =========================================================================

// ---------------------------------------------------------------------------
// HandshakeSuccess: Full client + server TLS handshake over socketpair.
// Verifies both sides reach Connected state and SSL pointers are valid.
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, HandshakeSuccess) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);
    TlsContext server_ctx(cfg);

    auto [client_fd, server_fd] = create_socketpair();
    ASSERT_GE(client_fd, 0);
    ASSERT_GE(server_fd, 0);

    TlsConnection server_conn(server_ctx, server_fd);
    TlsConnection client_conn(client_ctx, client_fd);

    bool server_ok = false;

    // Server thread: accept TLS handshake
    std::thread server_thread([&]() {
        server_ok = server_conn.accept(5);
    });

    // Client: connect TLS handshake
    bool client_ok = client_conn.connect(5);

    server_thread.join();

    EXPECT_TRUE(client_ok) << "Client handshake should succeed";
    EXPECT_TRUE(server_ok) << "Server handshake should succeed";

    EXPECT_EQ(client_conn.state(), ConnState::Connected);
    EXPECT_EQ(server_conn.state(), ConnState::Connected);

    EXPECT_NE(client_conn.ssl(), nullptr);
    EXPECT_NE(server_conn.ssl(), nullptr);

    // Clean shutdown
    client_conn.shutdown();
    server_conn.shutdown();

    EXPECT_EQ(client_conn.state(), ConnState::Disconnected);
    EXPECT_EQ(server_conn.state(), ConnState::Disconnected);
}

// ---------------------------------------------------------------------------
// HandshakeTimeout: Connect to a peer that immediately closes its end.
// SSL_connect should fail quickly (not hang), and the connection should
// report failure.
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, HandshakeTimeout) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);

    auto [client_fd, server_fd] = create_socketpair();
    ASSERT_GE(client_fd, 0);
    ASSERT_GE(server_fd, 0);

    // Close the server end immediately so SSL_connect detects a broken pipe
    // instead of spinning in WANT_READ forever on a live socketpair.
    ::close(server_fd);

    TlsConnection client_conn(client_ctx, client_fd);

    auto start = std::chrono::steady_clock::now();
    bool client_ok = client_conn.connect(2);  // 2 second timeout
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_FALSE(client_ok) << "Client handshake should fail (peer closed)";
    EXPECT_NE(client_conn.state(), ConnState::Connected);

    // Should complete quickly (well under the timeout)
    auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    EXPECT_LE(elapsed_sec, 3) << "Should complete within reasonable time";
}

// ---------------------------------------------------------------------------
// HandshakeCleanup: Verify resources are cleaned up after a failed handshake.
// After a failed connect(), the SSL pointer should be null and state should
// reflect failure. No resource leaks (ASan will catch leaks at process exit).
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, HandshakeCleanup) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);

    auto [client_fd, server_fd] = create_socketpair();
    ASSERT_GE(client_fd, 0);
    ASSERT_GE(server_fd, 0);

    // Close server end so client handshake fails quickly
    ::close(server_fd);

    {
        TlsConnection client_conn(client_ctx, client_fd);

        // Fail the handshake by having the peer closed
        bool client_ok = client_conn.connect(2);
        EXPECT_FALSE(client_ok);

        // After failure, SSL should be cleaned up
        EXPECT_EQ(client_conn.ssl(), nullptr)
            << "SSL pointer should be null after failed handshake";
        EXPECT_EQ(client_conn.state(), ConnState::Failing)
            << "State should be Failing after failed handshake";

        // Destructor will run here — should not crash or leak
    }

    // If we reach here without ASan complaints, cleanup is correct.
    SUCCEED() << "No resource leaks detected (ASan would report if any)";
}

// =========================================================================
// 12.2 — TLS I/O Integration Tests
// =========================================================================

// ---------------------------------------------------------------------------
// ReadWriteBasic: Write data from client, read from server, verify content.
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, ReadWriteBasic) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);
    TlsContext server_ctx(cfg);

    auto [client_fd, server_fd] = create_socketpair();
    ASSERT_GE(client_fd, 0);

    TlsConnection server_conn(server_ctx, server_fd);
    TlsConnection client_conn(client_ctx, client_fd);

    bool server_ok = false;
    std::thread server_thread([&]() {
        server_ok = server_conn.accept(5);
    });
    bool client_ok = client_conn.connect(5);
    server_thread.join();

    ASSERT_TRUE(client_ok && server_ok) << "Handshake must succeed for I/O test";

    // Write from client
    const std::string message = "Hello, TLS integration test!";
    int write_ret = TlsIO::write(client_conn.ssl(),
                                  message.data(),
                                  static_cast<int>(message.size()),
                                  /*blocking=*/true);
    ASSERT_EQ(write_ret, static_cast<int>(message.size()))
        << "Blocking write should send all bytes";

    // Read from server
    unsigned char read_buf[256] = {};
    int read_ret = TlsIO::read(server_conn.ssl(), read_buf,
                                sizeof(read_buf), 3);
    ASSERT_GT(read_ret, 0) << "Read should return data";
    ASSERT_EQ(read_ret, static_cast<int>(message.size()));

    std::string received(reinterpret_cast<char*>(read_buf), read_ret);
    EXPECT_EQ(received, message) << "Received data should match sent data";

    client_conn.shutdown();
    server_conn.shutdown();
}

// ---------------------------------------------------------------------------
// ReadWriteMultiple: Multiple read/write exchanges in both directions.
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, ReadWriteMultiple) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);
    TlsContext server_ctx(cfg);

    auto [client_fd, server_fd] = create_socketpair();
    ASSERT_GE(client_fd, 0);

    TlsConnection server_conn(server_ctx, server_fd);
    TlsConnection client_conn(client_ctx, client_fd);

    bool server_ok = false;
    std::thread server_thread([&]() {
        server_ok = server_conn.accept(5);
    });
    bool client_ok = client_conn.connect(5);
    server_thread.join();

    ASSERT_TRUE(client_ok && server_ok);

    // Exchange multiple messages in both directions
    for (int i = 0; i < 5; ++i) {
        // Client -> Server
        std::string msg_cs = "client-to-server-" + std::to_string(i);
        int w = TlsIO::write(client_conn.ssl(), msg_cs.data(),
                              static_cast<int>(msg_cs.size()), true);
        ASSERT_EQ(w, static_cast<int>(msg_cs.size()));

        unsigned char buf[256] = {};
        int r = TlsIO::read(server_conn.ssl(), buf, sizeof(buf), 3);
        ASSERT_EQ(r, static_cast<int>(msg_cs.size()));
        EXPECT_EQ(std::string(reinterpret_cast<char*>(buf), r), msg_cs);

        // Server -> Client
        std::string msg_sc = "server-to-client-" + std::to_string(i);
        w = TlsIO::write(server_conn.ssl(), msg_sc.data(),
                          static_cast<int>(msg_sc.size()), true);
        ASSERT_EQ(w, static_cast<int>(msg_sc.size()));

        std::memset(buf, 0, sizeof(buf));
        r = TlsIO::read(client_conn.ssl(), buf, sizeof(buf), 3);
        ASSERT_EQ(r, static_cast<int>(msg_sc.size()));
        EXPECT_EQ(std::string(reinterpret_cast<char*>(buf), r), msg_sc);
    }

    client_conn.shutdown();
    server_conn.shutdown();
}


// ---------------------------------------------------------------------------
// ShutdownZeroReturn: Client shuts down TLS, server reads and gets -1
// (SSL_ERROR_ZERO_RETURN path).
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, ShutdownZeroReturn) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);
    TlsContext server_ctx(cfg);

    auto [client_fd, server_fd] = create_socketpair();
    ASSERT_GE(client_fd, 0);

    TlsConnection server_conn(server_ctx, server_fd);
    TlsConnection client_conn(client_ctx, client_fd);

    bool server_ok = false;
    std::thread server_thread([&]() {
        server_ok = server_conn.accept(5);
    });
    bool client_ok = client_conn.connect(5);
    server_thread.join();

    ASSERT_TRUE(client_ok && server_ok);

    // Client initiates TLS shutdown
    client_conn.shutdown();

    // Server tries to read — should get -1 (zero return / connection closed)
    unsigned char buf[64] = {};
    int read_ret = TlsIO::read(server_conn.ssl(), buf, sizeof(buf), 3);
    EXPECT_EQ(read_ret, -1)
        << "Read after peer shutdown should return -1";

    server_conn.shutdown();
}

// =========================================================================
// 12.3 — ConnectionPool + ProtocolAdapter End-to-End Tests
// =========================================================================

// ---------------------------------------------------------------------------
// ProtocolAdapterFrameCallback: Register a RADIUS-style frame callback
// that determines message boundaries from a 2-byte length header.
// Verify the callback is invoked during read_message() on a real TLS
// connection.
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, ProtocolAdapterFrameCallback) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);
    TlsContext server_ctx(cfg);

    auto [client_fd, server_fd] = create_socketpair();
    ASSERT_GE(client_fd, 0);

    TlsConnection server_conn(server_ctx, server_fd);
    TlsConnection client_conn(client_ctx, client_fd);

    bool server_ok = false;
    std::thread server_thread([&]() {
        server_ok = server_conn.accept(5);
    });
    bool client_ok = client_conn.connect(5);
    server_thread.join();

    ASSERT_TRUE(client_ok && server_ok);

    // Create a ProtocolAdapter with a RADIUS-style frame callback.
    // RADIUS packets have a 4-byte header: Code(1) + ID(1) + Length(2).
    // The Length field (bytes 2-3, big-endian) gives the total packet length.
    ProtocolAdapter adapter("radius-test");

    std::atomic<int> frame_cb_calls{0};
    adapter.set_frame_callback(
        [&](const unsigned char* data, int len) -> int {
            frame_cb_calls.fetch_add(1);
            if (len < 4) {
                return 0;  // Need more data (header incomplete)
            }
            // Extract length from bytes 2-3 (big-endian)
            int msg_len = (data[2] << 8) | data[3];
            if (msg_len < 4 || msg_len > 4096) {
                return -1;  // Framing error
            }
            if (len >= msg_len) {
                return msg_len;  // Complete message
            }
            return 0;  // Need more data
        });

    // Build a fake RADIUS packet: Code=1, ID=42, Length=24, then 20 bytes payload
    std::vector<unsigned char> radius_pkt(24);
    radius_pkt[0] = 0x01;  // Code: Access-Request
    radius_pkt[1] = 0x2A;  // ID: 42
    radius_pkt[2] = 0x00;  // Length high byte
    radius_pkt[3] = 0x18;  // Length low byte (24)
    for (int i = 4; i < 24; ++i) {
        radius_pkt[i] = static_cast<unsigned char>(i);
    }

    // Write the RADIUS packet from the client side
    int w = TlsIO::write(client_conn.ssl(), radius_pkt.data(),
                          static_cast<int>(radius_pkt.size()), true);
    ASSERT_EQ(w, 24);

    // Read the framed message from the server side using the adapter
    unsigned char* msg_buf = nullptr;
    int msg_len = adapter.read_message(server_conn, &msg_buf, 3);

    ASSERT_EQ(msg_len, 24) << "Should read complete RADIUS packet";
    ASSERT_NE(msg_buf, nullptr);

    // Verify content matches
    EXPECT_EQ(std::memcmp(msg_buf, radius_pkt.data(), 24), 0)
        << "Received RADIUS packet should match sent packet";

    // Verify frame callback was invoked at least once
    EXPECT_GE(frame_cb_calls.load(), 1)
        << "Frame callback should have been called";

    std::free(msg_buf);

    client_conn.shutdown();
    server_conn.shutdown();
}

// ---------------------------------------------------------------------------
// ConnectionPoolCleanup: Add mock connections to the pool, run cleanup_idle,
// verify stats reflect the cleanup.
// ---------------------------------------------------------------------------
TEST_F(IntegrationTest, ConnectionPoolCleanup) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    // Use a very short idle timeout so cleanup triggers immediately
    PoolConfig pool_cfg;
    pool_cfg.max_connections_per_target = 4;
    pool_cfg.idle_timeout_sec = 0;  // Expire immediately

    ConnectionPool pool(pool_cfg);

    TunnelKey key1{"cleanup-host1", 8001, "cfg1"};
    TunnelKey key2{"cleanup-host2", 8002, "cfg2"};

    // Add mock connections to two tunnels
    auto conn1a = make_mock_connection(ctx);
    auto conn1b = make_mock_connection(ctx);
    auto conn2a = make_mock_connection(ctx);
    ASSERT_NE(conn1a, nullptr);
    ASSERT_NE(conn1b, nullptr);
    ASSERT_NE(conn2a, nullptr);

    pool.release(key1, conn1a);
    pool.release(key1, conn1b);
    pool.release(key2, conn2a);

    // Verify initial stats
    auto stats_before = pool.stats();
    EXPECT_EQ(stats_before.total_active, 3u);
    EXPECT_EQ(stats_before.per_target[key1], 2u);
    EXPECT_EQ(stats_before.per_target[key2], 1u);

    // Small sleep to ensure the idle timeout (0 sec) has elapsed
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Run idle cleanup
    pool.cleanup_idle();

    // Verify all connections were cleaned up
    auto stats_after = pool.stats();
    EXPECT_EQ(stats_after.total_active, 0u)
        << "All connections should be cleaned up after idle timeout";
    EXPECT_TRUE(stats_after.per_target.empty())
        << "No tunnels should remain after cleanup";
}

} // namespace
} // namespace gtls
