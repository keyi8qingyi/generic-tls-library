// =============================================================================
// Generic TLS Library (gtls) - TLS I/O property-based tests
// Tests read return value domain and blocking write completeness using
// loopback socketpair + TLS handshake with RapidCheck.
// =============================================================================

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <openssl/ssl.h>

#include "gtls/library.h"
#include "gtls/tls_config.h"
#include "gtls/tls_context.h"
#include "gtls/tls_connection.h"
#include "gtls/tls_io.h"

#include <sys/socket.h>
#include <thread>
#include <vector>
#include <cstring>

namespace gtls {
namespace {

// ---------------------------------------------------------------------------
// Helper: build a TlsConfig pointing to the test certificates.
// Uses the same cert/key for both client and server since verify mode
// defaults to SSL_VERIFY_NONE.
// ---------------------------------------------------------------------------
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
// Helper: establish a loopback TLS connection over a socketpair.
// Spawns a server thread that does accept(), client does connect().
// On success, both connections are in Connected state.
// ---------------------------------------------------------------------------
struct LoopbackTlsPair {
    std::unique_ptr<TlsConnection> client;
    std::unique_ptr<TlsConnection> server;
    bool ok = false;
};

static LoopbackTlsPair make_loopback_tls(TlsContext& client_ctx,
                                          TlsContext& server_ctx) {
    LoopbackTlsPair result;

    auto [client_fd, server_fd] = create_socketpair();
    if (client_fd < 0 || server_fd < 0) {
        return result;
    }

    result.server = std::make_unique<TlsConnection>(server_ctx, server_fd);
    result.client = std::make_unique<TlsConnection>(client_ctx, client_fd);

    bool server_ok = false;
    bool client_ok = false;

    // Server thread: accept TLS handshake
    std::thread server_thread([&]() {
        server_ok = result.server->accept(5);
    });

    // Client: connect TLS handshake
    client_ok = result.client->connect(5);

    server_thread.join();

    result.ok = server_ok && client_ok;
    return result;
}

// ---------------------------------------------------------------------------
// Test fixture: ensures OpenSSL is initialized.
// ---------------------------------------------------------------------------
class TlsIOPropertyTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Library::init();
    }
};

// ---------------------------------------------------------------------------
// Property 9: TLS I/O read return value domain
// For ANY TLS read operation, the return value MUST be one of:
//   - Positive integer (bytes read)
//   - 0 (timeout)
//   - -1 (error)
// No other return values should occur.
//
// Strategy: establish a loopback TLS connection, write random data from
// server side, then read from client side. Also test timeout (no data)
// and error (after shutdown) scenarios. Verify all return values are
// in the valid set {positive, 0, -1}.
//
// Feature: generic-tls-library, Property 9: TLS I/O read return value domain
// **Validates: Requirements 4.1**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsIOPropertyTest, ReadReturnValueDomain, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);
    TlsContext server_ctx(cfg);

    auto pair = make_loopback_tls(client_ctx, server_ctx);
    RC_PRE(pair.ok);

    // Generate random data size (1 to 4096 bytes)
    const auto data_size = *rc::gen::inRange(1, 4097);
    std::vector<unsigned char> write_buf(data_size);
    for (int i = 0; i < data_size; ++i) {
        write_buf[i] = static_cast<unsigned char>(*rc::gen::inRange(0, 256));
    }

    // Write data from server side
    int write_ret = TlsIO::write(pair.server->ssl(), write_buf.data(),
                                  data_size, true);
    RC_ASSERT(write_ret == data_size || write_ret == -1);

    if (write_ret > 0) {
        // Read from client side with a short timeout
        std::vector<unsigned char> read_buf(data_size + 100);
        int read_ret = TlsIO::read(pair.client->ssl(), read_buf.data(),
                                    static_cast<int>(read_buf.size()), 3);

        // Property: return value must be positive, 0, or -1
        RC_ASSERT(read_ret > 0 || read_ret == 0 || read_ret == -1);

        // If positive, must not exceed buffer size
        if (read_ret > 0) {
            RC_ASSERT(read_ret <= static_cast<int>(read_buf.size()));
        }
    }

    // Test timeout scenario: read with short timeout when no data is pending
    {
        std::vector<unsigned char> read_buf(64);
        int read_ret = TlsIO::read(pair.client->ssl(), read_buf.data(),
                                    static_cast<int>(read_buf.size()), 1);
        // Should be 0 (timeout) or possibly positive if buffered data remains
        RC_ASSERT(read_ret > 0 || read_ret == 0 || read_ret == -1);
    }

    // Cleanup
    pair.client->shutdown();
    pair.server->shutdown();
}

// ---------------------------------------------------------------------------
// Property 10: TLS I/O blocking write completeness
// For ANY non-empty data buffer, calling TlsIO::write() in blocking mode
// MUST return either the full number of bytes requested (num) or -1 (error).
// Partial writes should NOT occur in blocking mode.
//
// Strategy: establish a loopback TLS connection, generate random data of
// varying sizes, write in blocking mode, and verify the return value is
// exactly num or -1.
//
// Feature: generic-tls-library, Property 10: TLS I/O blocking write completeness
// **Validates: Requirements 4.5**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsIOPropertyTest, BlockingWriteCompleteness, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext client_ctx(cfg);
    TlsContext server_ctx(cfg);

    auto pair = make_loopback_tls(client_ctx, server_ctx);
    RC_PRE(pair.ok);

    // Generate random data size (1 to 8192 bytes)
    const auto data_size = *rc::gen::inRange(1, 8193);
    std::vector<unsigned char> write_buf(data_size);
    for (int i = 0; i < data_size; ++i) {
        write_buf[i] = static_cast<unsigned char>(*rc::gen::inRange(0, 256));
    }

    // Write in blocking mode (blocking = true)
    int write_ret = TlsIO::write(pair.client->ssl(), write_buf.data(),
                                  data_size, /*blocking=*/true);

    // Property: return value must be exactly data_size or -1
    RC_ASSERT(write_ret == data_size || write_ret == -1);

    // If write succeeded, verify data can be read back correctly
    if (write_ret == data_size) {
        // Drain the data from server side to verify integrity
        std::vector<unsigned char> read_buf(data_size);
        int total_read = 0;
        while (total_read < data_size) {
            int ret = TlsIO::read(pair.server->ssl(),
                                   read_buf.data() + total_read,
                                   data_size - total_read, 3);
            if (ret <= 0) break;
            total_read += ret;
        }
        // Verify all data was received
        RC_ASSERT(total_read == data_size);
        RC_ASSERT(std::memcmp(write_buf.data(), read_buf.data(), data_size) == 0);
    }

    // Cleanup
    pair.client->shutdown();
    pair.server->shutdown();
}

} // namespace
} // namespace gtls
