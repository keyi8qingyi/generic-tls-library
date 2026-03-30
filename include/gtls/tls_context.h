// =============================================================================
// Generic TLS Library (gtls) - TLS context management
// Manages SSL_CTX lifecycle with caching, thread-safe access, and hot-reload.
// =============================================================================
#ifndef GTLS_TLS_CONTEXT_H
#define GTLS_TLS_CONTEXT_H

#include <ctime>
#include <memory>
#include <mutex>

#include <openssl/ssl.h>

#include "gtls/tls_config.h"

namespace gtls {

// Custom deleter for SSL_CTX, enabling RAII via std::unique_ptr.
struct SslCtxDeleter {
    void operator()(SSL_CTX* ctx) const {
        if (ctx) {
            SSL_CTX_free(ctx);
        }
    }
};

// RAII smart pointer for SSL_CTX. Automatically calls SSL_CTX_free on destruction.
using SslCtxPtr = std::unique_ptr<SSL_CTX, SslCtxDeleter>;

// Manages an SSL_CTX with caching, expiry-based refresh, and thread-safe access.
// Corresponds to radsecproxy's tlscreatectx / tlsgetctx / tlsreload functions.
class TlsContext {
public:
    // Construct a TlsContext from the given configuration.
    // Does NOT create the SSL_CTX immediately; it is lazily created on first get_ctx() call.
    explicit TlsContext(TlsConfig config);

    // Destructor. The SSL_CTX is automatically freed via SslCtxPtr.
    ~TlsContext();

    // Non-copyable, non-movable (due to mutex).
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    TlsContext(TlsContext&&) = delete;
    TlsContext& operator=(TlsContext&&) = delete;

    // Get or create the cached SSL_CTX (thread-safe).
    // If the cache has expired (cache_expiry > 0 and current time > expiry_),
    // a new SSL_CTX is created and replaces the old one.
    // Returns nullptr if SSL_CTX creation fails and no cached context exists.
    SSL_CTX* get_ctx();

    // Force reload: create a new SSL_CTX and replace the old one.
    // On success, the old SSL_CTX is replaced and true is returned.
    // On failure, the old SSL_CTX is preserved and false is returned.
    // Thread-safe.
    bool reload();

    // Get the underlying configuration (read-only).
    const TlsConfig& config() const;

private:
    // Create a new SSL_CTX based on config_.
    // Configures protocol versions, cipher suites, certificates, CA/CRL,
    // security options, and DH parameters.
    // Returns a valid SslCtxPtr on success, or nullptr on failure.
    SslCtxPtr create_ctx();

    // Password callback for encrypted private keys.
    // OpenSSL calls this during SSL_CTX_use_PrivateKey_file when the key is encrypted.
    static int password_callback(char* buf, int size, int rwflag, void* userdata);

    TlsConfig config_;
    SslCtxPtr ctx_;
    std::time_t expiry_ = 0;
    mutable std::mutex mutex_;
};

} // namespace gtls

#endif // GTLS_TLS_CONTEXT_H
