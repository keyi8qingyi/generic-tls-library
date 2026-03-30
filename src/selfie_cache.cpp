// =============================================================================
// Generic TLS Library (gtls) - Selfie attack detection implementation
// =============================================================================

#include "gtls/selfie_cache.h"
#include "gtls/logger.h"

#include <openssl/ssl.h>

namespace gtls {

// Static member definitions
std::mutex SelfieCache::mutex_;
std::set<std::vector<unsigned char>> SelfieCache::cache_;

void SelfieCache::install(SSL_CTX* ctx) {
    if (!ctx) {
        Logger::log(LogLevel::Error,
                    "SelfieCache::install: null SSL_CTX pointer");
        return;
    }
    SSL_CTX_set_client_hello_cb(ctx, client_hello_cb, nullptr);
    Logger::log(LogLevel::Debug,
                "SelfieCache::install: client_hello callback registered");
}

void SelfieCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

int SelfieCache::client_hello_cb(SSL* ssl, int* alert, void* /*arg*/) {
    // Extract the ClientHello random (32 bytes) from the SSL object.
    const unsigned char* random = nullptr;
    size_t random_len = SSL_client_hello_get0_random(ssl, &random);

    if (!random || random_len == 0) {
        // Cannot extract random; allow the handshake to continue
        // since we cannot make a determination.
        Logger::log(LogLevel::Warning,
                    "SelfieCache: could not extract ClientHello random");
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    std::vector<unsigned char> rand_vec(random, random + random_len);

    std::lock_guard<std::mutex> lock(mutex_);
    if (cache_.count(rand_vec)) {
        // Duplicate random detected — selfie attack!
        Logger::log(LogLevel::Error,
                    "SelfieCache: duplicate ClientHello random detected, "
                    "rejecting connection");
        *alert = SSL_AD_HANDSHAKE_FAILURE;
        return SSL_CLIENT_HELLO_ERROR;
    }

    cache_.insert(std::move(rand_vec));
    return SSL_CLIENT_HELLO_SUCCESS;
}

} // namespace gtls
