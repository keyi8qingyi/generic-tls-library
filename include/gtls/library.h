// =============================================================================
// Generic TLS Library (gtls) - Library initialization and cleanup
// =============================================================================
#ifndef GTLS_LIBRARY_H
#define GTLS_LIBRARY_H

#include <mutex>

namespace gtls {

// Manages OpenSSL library initialization and cleanup.
// Corresponds to radsecproxy's sslinit() function.
// Thread-safe: uses a static mutex to guard initialization state.
class Library {
public:
    // Initialize OpenSSL and internal state.
    // Calls OPENSSL_init_ssl() for OpenSSL 1.1.0+ initialization.
    // Safe to call multiple times; only the first call performs initialization.
    static void init();

    // Cleanup all OpenSSL resources.
    // Calls EVP_cleanup(), CRYPTO_cleanup_all_ex_data(), ERR_free_strings(), etc.
    // After cleanup, init() can be called again to re-initialize.
    static void cleanup();

    // Check whether the library has been initialized.
    static bool is_initialized();

private:
    static bool initialized_;
    static std::mutex mutex_;
};

} // namespace gtls

#endif // GTLS_LIBRARY_H
