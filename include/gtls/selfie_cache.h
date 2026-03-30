// =============================================================================
// Generic TLS Library (gtls) - Selfie attack detection via ClientHello cache
// Detects self-connections by caching ClientHello random values and rejecting
// duplicates, preventing TLS selfie attacks (Req 6.1).
// =============================================================================
#ifndef GTLS_SELFIE_CACHE_H
#define GTLS_SELFIE_CACHE_H

#include <mutex>
#include <set>
#include <vector>

// Forward declaration for OpenSSL types
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace gtls {

// Detects TLS selfie attacks by caching ClientHello random values.
// When a server receives a ClientHello whose random matches one it recently
// sent as a client, this indicates a self-connection (loopback) which must
// be rejected to prevent reflection attacks.
//
// Usage: call SelfieCache::install(ctx) on any server-side SSL_CTX.
// The callback is automatically invoked during the TLS handshake.
class SelfieCache {
public:
    // Install the client_hello callback on the given SSL_CTX.
    // Should be called once per SSL_CTX after creation.
    static void install(SSL_CTX* ctx);

    // Clear all cached random values.
    // Useful for testing or periodic cache maintenance.
    static void clear();

private:
    // OpenSSL client_hello callback (SSL_CTX_set_client_hello_cb).
    // Returns SSL_CLIENT_HELLO_SUCCESS if the random is new,
    // or SSL_CLIENT_HELLO_ERROR if a duplicate is detected.
    static int client_hello_cb(SSL* ssl, int* alert, void* arg);

    static std::mutex mutex_;
    static std::set<std::vector<unsigned char>> cache_;
};

} // namespace gtls

#endif // GTLS_SELFIE_CACHE_H
