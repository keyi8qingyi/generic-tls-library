// =============================================================================
// Generic TLS Library (gtls) - TLS context implementation
// =============================================================================

#include "gtls/tls_context.h"
#include "gtls/logger.h"
#include "gtls/selfie_cache.h"

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>

#include <cstring>
#include <ctime>

namespace gtls {

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

TlsContext::TlsContext(TlsConfig config)
    : config_(std::move(config)) {}

TlsContext::~TlsContext() = default;

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

SSL_CTX* TlsContext::get_ctx() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if we need to create or refresh the context.
    bool need_create = (ctx_ == nullptr);

    if (!need_create && config_.cache_expiry > 0) {
        std::time_t now = std::time(nullptr);
        if (now > expiry_) {
            need_create = true;
        }
    }

    if (need_create) {
        auto new_ctx = create_ctx();
        if (new_ctx) {
            ctx_ = std::move(new_ctx);
            if (config_.cache_expiry > 0) {
                expiry_ = std::time(nullptr) + config_.cache_expiry;
            }
        } else if (!ctx_) {
            // No existing context and creation failed.
            Logger::log(LogLevel::Error,
                        "TlsContext::get_ctx: failed to create SSL_CTX and no cached context available");
            return nullptr;
        } else {
            // Creation failed but we still have the old context.
            Logger::log(LogLevel::Warning,
                        "TlsContext::get_ctx: failed to refresh SSL_CTX, using cached context");
        }
    }

    return ctx_.get();
}

bool TlsContext::reload() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto new_ctx = create_ctx();
    if (!new_ctx) {
        Logger::log(LogLevel::Error,
                    "TlsContext::reload: failed to create new SSL_CTX, keeping old context");
        return false;
    }

    ctx_ = std::move(new_ctx);
    if (config_.cache_expiry > 0) {
        expiry_ = std::time(nullptr) + config_.cache_expiry;
    }

    Logger::log(LogLevel::Info, "TlsContext::reload: SSL_CTX successfully reloaded");
    return true;
}

const TlsConfig& TlsContext::config() const {
    return config_;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

int TlsContext::password_callback(char* buf, int size, int /*rwflag*/, void* userdata) {
    // userdata points to the password string stored in config_.
    const auto* password = static_cast<const std::string*>(userdata);
    if (!password || password->empty()) {
        return 0;
    }

    int len = static_cast<int>(password->size());
    if (len > size) {
        len = size;
    }
    std::memcpy(buf, password->c_str(), static_cast<size_t>(len));
    return len;
}

SslCtxPtr TlsContext::create_ctx() {
    // Create a new SSL_CTX using the flexible TLS_method().
    SSL_CTX* raw_ctx = SSL_CTX_new(TLS_method());
    if (!raw_ctx) {
        Logger::log(LogLevel::Error,
                    "TlsContext::create_ctx: SSL_CTX_new(TLS_method()) failed");
        return nullptr;
    }

    // Wrap in RAII smart pointer immediately to ensure cleanup on any error path.
    SslCtxPtr ctx(raw_ctx);

    // --- Protocol version constraints ---
    if (config_.tls_min_version > 0) {
        if (!SSL_CTX_set_min_proto_version(ctx.get(), config_.tls_min_version)) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to set min protocol version to %d",
                        config_.tls_min_version);
            return nullptr;
        }
    }

    if (config_.tls_max_version > 0) {
        if (!SSL_CTX_set_max_proto_version(ctx.get(), config_.tls_max_version)) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to set max protocol version to %d",
                        config_.tls_max_version);
            return nullptr;
        }
    }

    // --- Cipher configuration ---
    if (!config_.cipher_list.empty()) {
        if (!SSL_CTX_set_cipher_list(ctx.get(), config_.cipher_list.c_str())) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to set cipher list: %s",
                        config_.cipher_list.c_str());
            return nullptr;
        }
    }

    if (!config_.cipher_suites.empty()) {
        if (!SSL_CTX_set_ciphersuites(ctx.get(), config_.cipher_suites.c_str())) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to set TLS 1.3 cipher suites: %s",
                        config_.cipher_suites.c_str());
            return nullptr;
        }
    }

    // --- Private key password callback ---
    if (!config_.cert_key_password.empty()) {
        SSL_CTX_set_default_passwd_cb(ctx.get(), password_callback);
        // Pass a pointer to the password string. This is safe because config_
        // outlives the SSL_CTX (config_ is a member of TlsContext).
        SSL_CTX_set_default_passwd_cb_userdata(
            ctx.get(),
            const_cast<std::string*>(&config_.cert_key_password));
    }

    // --- Certificate and private key loading ---
    if (!config_.cert_file.empty()) {
        if (SSL_CTX_use_certificate_chain_file(ctx.get(), config_.cert_file.c_str()) != 1) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to load certificate file: %s",
                        config_.cert_file.c_str());
            return nullptr;
        }
    }

    if (!config_.cert_key_file.empty()) {
        if (SSL_CTX_use_PrivateKey_file(ctx.get(), config_.cert_key_file.c_str(),
                                         SSL_FILETYPE_PEM) != 1) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to load private key file: %s",
                        config_.cert_key_file.c_str());
            return nullptr;
        }

        // Verify that the private key matches the certificate.
        if (!SSL_CTX_check_private_key(ctx.get())) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: private key does not match certificate");
            return nullptr;
        }
    }

    // --- CA certificate loading ---
    const char* ca_file = config_.ca_cert_file.empty() ? nullptr : config_.ca_cert_file.c_str();
    const char* ca_path = config_.ca_cert_path.empty() ? nullptr : config_.ca_cert_path.c_str();

    if (ca_file || ca_path) {
        if (!SSL_CTX_load_verify_locations(ctx.get(), ca_file, ca_path)) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to load CA certificates (file=%s, path=%s)",
                        ca_file ? ca_file : "(none)",
                        ca_path ? ca_path : "(none)");
            return nullptr;
        }
    }

    // --- CRL checking ---
    if (config_.crl_check) {
        X509_STORE* store = SSL_CTX_get_cert_store(ctx.get());
        if (store) {
            X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
        } else {
            Logger::log(LogLevel::Warning,
                        "TlsContext::create_ctx: could not get X509_STORE for CRL check setup");
        }
    }

    // --- Security options ---
    // Disable session tickets for enhanced security (Req 6.3).
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET);

    // Disable no-DHE key exchange to ensure forward secrecy (Req 6.4).
    // SSL_OP_ALLOW_NO_DHE_KEX is set by default in some OpenSSL builds;
    // we explicitly clear it.
    SSL_CTX_clear_options(ctx.get(), SSL_OP_ALLOW_NO_DHE_KEX);

    // --- DH parameters ---
    if (!config_.dh_param_file.empty()) {
        // Load DH parameters from file using BIO.
        BIO* bio = BIO_new_file(config_.dh_param_file.c_str(), "r");
        if (!bio) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to open DH param file: %s",
                        config_.dh_param_file.c_str());
            return nullptr;
        }

        // Use EVP_PKEY-based DH parameter loading (OpenSSL 3.0+ preferred).
        // For compatibility, we try the legacy DH approach first.
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        // OpenSSL 3.0+: use EVP_PKEY for DH parameters.
        EVP_PKEY* pkey = PEM_read_bio_Parameters(bio, nullptr);
        BIO_free(bio);
        if (!pkey) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to read DH parameters from: %s",
                        config_.dh_param_file.c_str());
            return nullptr;
        }
        if (SSL_CTX_set0_tmp_dh_pkey(ctx.get(), pkey) != 1) {
            EVP_PKEY_free(pkey);
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to set DH parameters");
            return nullptr;
        }
        // pkey ownership transferred to ctx on success, do not free.
#else
        // OpenSSL < 3.0: use legacy DH API.
        DH* dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!dh) {
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to read DH parameters from: %s",
                        config_.dh_param_file.c_str());
            return nullptr;
        }
        if (SSL_CTX_set_tmp_dh(ctx.get(), dh) != 1) {
            DH_free(dh);
            Logger::log(LogLevel::Error,
                        "TlsContext::create_ctx: failed to set DH parameters");
            return nullptr;
        }
        DH_free(dh);
#endif
    }

    // --- Install keylog callback if enabled ---
    Logger::install_keylog_callback(ctx.get());

    // --- Install selfie cache for self-connection detection (Req 6.1) ---
    SelfieCache::install(ctx.get());

    Logger::log(LogLevel::Debug, "TlsContext::create_ctx: SSL_CTX created successfully");
    return ctx;
}

} // namespace gtls
