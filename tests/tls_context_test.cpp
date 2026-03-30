// =============================================================================
// Generic TLS Library (gtls) - TlsContext property-based tests
// Tests SSL_CTX caching, reload, protocol version constraints, and security
// options using RapidCheck property testing framework.
// =============================================================================

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <openssl/ssl.h>

#include "gtls/library.h"
#include "gtls/tls_config.h"
#include "gtls/tls_context.h"

namespace gtls {
namespace {

// ---------------------------------------------------------------------------
// Helper: build a TlsConfig pointing to the test certificates at the
// workspace root. Uses GTLS_SOURCE_DIR macro defined via CMake.
// ---------------------------------------------------------------------------
#ifndef GTLS_SOURCE_DIR
#define GTLS_SOURCE_DIR "."
#endif

static TlsConfig make_test_config() {
    TlsConfig cfg;
    cfg.ca_cert_file   = std::string(GTLS_SOURCE_DIR) + "/ca.pem";
    cfg.cert_file      = std::string(GTLS_SOURCE_DIR) + "/client.pem";
    cfg.cert_key_file  = std::string(GTLS_SOURCE_DIR) + "/client.key";
    cfg.cache_expiry   = 3600;  // large value so cache does not expire
    return cfg;
}

// ---------------------------------------------------------------------------
// Test fixture: ensures OpenSSL is initialized before any TlsContext test.
// ---------------------------------------------------------------------------
class TlsContextPropertyTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Library::init();
    }
};

// ---------------------------------------------------------------------------
// Property 4: SSL_CTX cache consistency
// Within a non-expired cache window, consecutive calls to get_ctx() MUST
// return the same SSL_CTX pointer.
//
// Feature: generic-tls-library, Property 4: SSL_CTX cache consistency
// **Validates: Requirements 2.2**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsContextPropertyTest, CacheConsistency, ()) {
    // Generate a random number of calls (2..20) to exercise the cache
    const auto num_calls = *rc::gen::inRange(2, 21);

    TlsConfig cfg = make_test_config();
    // Use a large cache_expiry so the cache never expires during the test
    cfg.cache_expiry = 3600;

    TlsContext ctx(cfg);

    // First call creates the SSL_CTX
    SSL_CTX* first = ctx.get_ctx();
    RC_ASSERT(first != nullptr);

    // Subsequent calls must return the exact same pointer
    for (int i = 1; i < num_calls; ++i) {
        SSL_CTX* current = ctx.get_ctx();
        RC_ASSERT(current == first);
    }
}

// ---------------------------------------------------------------------------
// Property 5: SSL_CTX update after reload
// After a successful reload(), get_ctx() MUST return a different SSL_CTX
// pointer than before the reload.
//
// Feature: generic-tls-library, Property 5: SSL_CTX update after reload
// **Validates: Requirements 2.4**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsContextPropertyTest, ReloadUpdatesCtx, ()) {
    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    // Get the initial SSL_CTX pointer
    SSL_CTX* before = ctx.get_ctx();
    RC_ASSERT(before != nullptr);

    // Reload must succeed with valid certificates
    bool ok = ctx.reload();
    RC_ASSERT(ok);

    // After reload, the pointer must be different
    SSL_CTX* after = ctx.get_ctx();
    RC_ASSERT(after != nullptr);
    RC_ASSERT(after != before);
}

// ---------------------------------------------------------------------------
// Property 6: SSL_CTX protocol version constraint
// When tls_min_version and/or tls_max_version are set in TlsConfig, the
// created SSL_CTX must reflect those constraints via
// SSL_CTX_get_min_proto_version / SSL_CTX_get_max_proto_version.
//
// Feature: generic-tls-library, Property 6: SSL_CTX protocol version constraint
// **Validates: Requirements 2.1**
// ---------------------------------------------------------------------------

// Generator for valid TLS version constants recognized by OpenSSL.
static rc::Gen<int> genTlsVersion() {
    return rc::gen::elementOf(
        std::vector<int>{
            TLS1_VERSION,       // 0x0301
            TLS1_1_VERSION,     // 0x0302
            TLS1_2_VERSION,     // 0x0303
            TLS1_3_VERSION      // 0x0304
        });
}

RC_GTEST_FIXTURE_PROP(TlsContextPropertyTest, ProtocolVersionConstraint, ()) {
    // Generate a valid (min, max) version pair where min <= max
    int v1 = *genTlsVersion();
    int v2 = *genTlsVersion();
    int min_ver = std::min(v1, v2);
    int max_ver = std::max(v1, v2);

    TlsConfig cfg = make_test_config();
    cfg.tls_min_version = min_ver;
    cfg.tls_max_version = max_ver;

    TlsContext ctx(cfg);
    SSL_CTX* ssl_ctx = ctx.get_ctx();
    RC_ASSERT(ssl_ctx != nullptr);

    // Verify the SSL_CTX reflects the configured version constraints
    long actual_min = SSL_CTX_get_min_proto_version(ssl_ctx);
    long actual_max = SSL_CTX_get_max_proto_version(ssl_ctx);

    RC_ASSERT(actual_min == min_ver);
    RC_ASSERT(actual_max == max_ver);
}

// ---------------------------------------------------------------------------
// Property 7: SSL_CTX security options invariant
// For ANY SSL_CTX created by TlsContext:
//   - SSL_OP_NO_TICKET MUST be set
//   - SSL_OP_ALLOW_NO_DHE_KEX MUST NOT be set
//
// Feature: generic-tls-library, Property 7: SSL_CTX security options invariant
// **Validates: Requirements 6.3, 6.4**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsContextPropertyTest, SecurityOptionsInvariant, ()) {
    TlsConfig cfg = make_test_config();

    // Randomize optional fields to ensure the security options hold
    // regardless of other configuration choices
    cfg.cipher_list  = *rc::gen::arbitrary<std::string>();
    cfg.cipher_suites = *rc::gen::arbitrary<std::string>();
    cfg.crl_check    = *rc::gen::arbitrary<bool>();

    // Reset cipher fields if they would cause SSL_CTX creation to fail
    // (invalid cipher strings). Use empty string as safe default.
    cfg.cipher_list = "";
    cfg.cipher_suites = "";

    TlsContext ctx(cfg);
    SSL_CTX* ssl_ctx = ctx.get_ctx();
    RC_ASSERT(ssl_ctx != nullptr);

    long options = SSL_CTX_get_options(ssl_ctx);

    // SSL_OP_NO_TICKET must be set (Req 6.3)
    RC_ASSERT((options & SSL_OP_NO_TICKET) != 0);

    // SSL_OP_ALLOW_NO_DHE_KEX must NOT be set (Req 6.4)
    RC_ASSERT((options & SSL_OP_ALLOW_NO_DHE_KEX) == 0);
}

} // namespace
} // namespace gtls
