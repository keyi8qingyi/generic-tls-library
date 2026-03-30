// =============================================================================
// Generic TLS Library (gtls) - TLS I/O property-based tests
// Tests read return value domain and blocking write completeness.
// Uses a single shared loopback TLS connection initialized via call_once
// to avoid per-iteration handshake overhead.
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
#include <mutex>
#include <memory>

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

static std::pair<int, int> create_socketpair() {
    int fds[2] = {-1, -1};
    int ret = ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    if (ret != 0) return {-1, -1};
    return {fds[0], fds[1]};
}

// Shared state initialized once across all iterations via call_once.
static std::once_flag s_init_flag;
static std::unique_ptr<TlsContext> s_client_ctx;
static std::unique_ptr<TlsContext> s_server_ctx;
static std::unique_ptr<TlsConnection> s_client;
static std::unique_ptr<TlsConnection> s_server;
static bool s_ready = false;

static void init_shared_connection() {
    Library::init();

    auto cfg = make_test_config();
    s_client_ctx = std::make_unique<TlsContext>(cfg);
    s_server_ctx = std::make_unique<TlsContext>(cfg);

    auto [cfd, sfd] = create_socketpair();
    if (cfd < 0) return;

    s_server = std::make_unique<TlsConnection>(*s_server_ctx, sfd);
    s_client = std::make_unique<TlsConnection>(*s_client_ctx, cfd);

    bool server_ok = false;
    std::thread t([&]() { server_ok = s_server->accept(5); });
    bool client_ok = s_client->connect(5);
    t.join();

    s_ready = server_ok && client_ok;
}

// ---------------------------------------------------------------------------
// Test fixture: uses call_once to establish the shared TLS connection.
// ---------------------------------------------------------------------------
class TlsIOPropertyTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::call_once(s_init_flag, init_shared_connection);
    }
};

// ---------------------------------------------------------------------------
// Property 9: TLS I/O read return value domain
// Return value MUST be: positive (bytes read), 0 (timeout), or -1 (error).
//
// Feature: generic-tls-library, Property 9: TLS I/O read return value domain
// **Validates: Requirements 4.1**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsIOPropertyTest, ReadReturnValueDomain, ()) {
    RC_PRE(s_ready);

    // Generate random data (1-2048 bytes)
    const auto data_size = *rc::gen::inRange(1, 2049);
    std::vector<unsigned char> write_buf(data_size, 0xAB);

    // Write from server, read from client
    int w = TlsIO::write(s_server->ssl(), write_buf.data(), data_size, true);
    RC_PRE(w == data_size);

    std::vector<unsigned char> read_buf(data_size + 64);
    int r = TlsIO::read(s_client->ssl(), read_buf.data(),
                         static_cast<int>(read_buf.size()), 2);

    // Property: return value must be positive, 0, or -1
    RC_ASSERT(r > 0 || r == 0 || r == -1);
    if (r > 0) {
        RC_ASSERT(r <= static_cast<int>(read_buf.size()));
    }
}

// ---------------------------------------------------------------------------
// Property 10: TLS I/O blocking write completeness
// Blocking write MUST return exactly num bytes or -1. No partial writes.
//
// Feature: generic-tls-library, Property 10: TLS I/O blocking write completeness
// **Validates: Requirements 4.5**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsIOPropertyTest, BlockingWriteCompleteness, ()) {
    RC_PRE(s_ready);

    // Generate random data (1-4096 bytes)
    const auto data_size = *rc::gen::inRange(1, 4097);
    std::vector<unsigned char> write_buf(data_size);
    for (int i = 0; i < data_size; ++i) {
        write_buf[i] = static_cast<unsigned char>(i & 0xFF);
    }

    // Blocking write from client
    int w = TlsIO::write(s_client->ssl(), write_buf.data(), data_size, true);

    // Property: must be exactly data_size or -1
    RC_ASSERT(w == data_size || w == -1);

    // Drain from server to keep the connection clean for next iteration
    if (w == data_size) {
        std::vector<unsigned char> drain(data_size);
        int total = 0;
        while (total < data_size) {
            int r = TlsIO::read(s_server->ssl(), drain.data() + total,
                                 data_size - total, 2);
            if (r <= 0) break;
            total += r;
        }
        RC_ASSERT(total == data_size);
    }
}

} // namespace
} // namespace gtls
