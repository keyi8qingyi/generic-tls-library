// =============================================================================
// Generic TLS Library (gtls) - Library initialization and cleanup
// =============================================================================

#include "gtls/library.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

namespace gtls {

// Static member definitions
bool Library::initialized_ = false;
std::mutex Library::mutex_;

void Library::init() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return;
    }

    // Initialize OpenSSL using the 1.1.0+ API.
    // OPENSSL_init_ssl() performs all necessary library initialization
    // including loading error strings, SSL algorithms, and crypto internals.
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    initialized_ = true;
}

void Library::cleanup() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }

    // Clean up OpenSSL resources.
    // Note: In OpenSSL 1.1.0+, most cleanup is handled automatically
    // via atexit handlers. These calls are included for completeness
    // and compatibility with environments that require explicit cleanup.
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    initialized_ = false;
}

bool Library::is_initialized() {
    std::lock_guard<std::mutex> lock(mutex_);
    return initialized_;
}

} // namespace gtls
