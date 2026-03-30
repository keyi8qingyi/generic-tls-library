// =============================================================================
// Generic TLS Library (gtls) - TlsConnection property-based tests
// Tests SNI (Server Name Indication) setting correctness using RapidCheck.
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
// Helper: build a TlsConfig pointing to the test certificates.
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
// Generator: produce a valid DNS hostname label (alphanumeric, 3-8 chars).
// ---------------------------------------------------------------------------
static rc::Gen<std::string> genHostnameLabel() {
    return rc::gen::map(
        rc::gen::container<std::string>(
            rc::gen::oneOf(
                rc::gen::inRange('a', static_cast<char>('z' + 1)),
                rc::gen::inRange('0', static_cast<char>('9' + 1))
            )
        ),
        [](std::string s) {
            // Ensure at least 1 char and at most 12
            if (s.empty()) s += "a";
            if (s.size() > 12) s.resize(12);
            return s;
        }
    );
}

// ---------------------------------------------------------------------------
// Generator: produce a valid hostname like "abc.def.example.com".
// ---------------------------------------------------------------------------
static rc::Gen<std::string> genValidHostname() {
    return rc::gen::map(
        rc::gen::tuple(genHostnameLabel(), genHostnameLabel()),
        [](const std::tuple<std::string, std::string>& t) {
            return std::get<0>(t) + "." + std::get<1>(t) + ".example.com";
        }
    );
}

// ---------------------------------------------------------------------------
// Test fixture: ensures OpenSSL is initialized.
// ---------------------------------------------------------------------------
class TlsConnectionPropertyTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        Library::init();
    }
};

// ---------------------------------------------------------------------------
// Property 8: SNI setting correctness
// For ANY valid non-empty hostname string, after calling
// SSL_set_tlsext_host_name() on an SSL object, SSL_get_servername()
// MUST return the same hostname.
//
// We test this at the SSL object level without a full TLS handshake:
//   1. Create SSL_CTX from TlsContext
//   2. Create SSL object from SSL_CTX
//   3. Set SNI via SSL_set_tlsext_host_name
//   4. Verify SSL_get_servername returns the same hostname
//
// Feature: generic-tls-library, Property 8: SNI setting correctness
// **Validates: Requirements 3.3**
// ---------------------------------------------------------------------------
RC_GTEST_FIXTURE_PROP(TlsConnectionPropertyTest, SniSettingCorrectness, ()) {
    // Generate a random valid hostname
    const auto hostname = *genValidHostname();
    RC_PRE(!hostname.empty());

    TlsConfig cfg = make_test_config();
    TlsContext ctx(cfg);

    SSL_CTX* ssl_ctx = ctx.get_ctx();
    RC_ASSERT(ssl_ctx != nullptr);

    // Create an SSL object from the context
    SSL* ssl = SSL_new(ssl_ctx);
    RC_ASSERT(ssl != nullptr);

    // Set SNI hostname (mirrors TlsConnection::connect logic)
    int ret = SSL_set_tlsext_host_name(ssl, hostname.c_str());
    RC_ASSERT(ret == 1);

    // Verify SSL_get_servername returns the same hostname
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    RC_ASSERT(servername != nullptr);
    RC_ASSERT(std::string(servername) == hostname);

    // Cleanup
    SSL_free(ssl);
}

} // namespace
} // namespace gtls
