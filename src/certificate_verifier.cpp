// =============================================================================
// Generic TLS Library (gtls) - Certificate verification implementation
// =============================================================================

#include "gtls/certificate_verifier.h"
#include "gtls/logger.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>

#include <arpa/inet.h>

#include <cstring>
#include <regex>
#include <string>

namespace gtls {

// ---------------------------------------------------------------------------
// Helper: check if a string looks like an IP address (IPv4 or IPv6).
// ---------------------------------------------------------------------------
static bool is_ip_address(const std::string& name) {
    struct in_addr ipv4;
    struct in6_addr ipv6;
    return (inet_pton(AF_INET, name.c_str(), &ipv4) == 1 ||
            inet_pton(AF_INET6, name.c_str(), &ipv6) == 1);
}

// ---------------------------------------------------------------------------
// Helper: extract a UTF-8 string from an ASN1_STRING.
// ---------------------------------------------------------------------------
static std::string asn1_string_to_utf8(const ASN1_STRING* asn1) {
    if (!asn1) {
        return {};
    }
    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, asn1);
    if (len < 0 || !utf8) {
        return {};
    }
    std::string result(reinterpret_cast<char*>(utf8), static_cast<size_t>(len));
    OPENSSL_free(utf8);
    return result;
}

// ---------------------------------------------------------------------------
// Helper: convert a GEN_IPADD entry to a human-readable IP string.
// ---------------------------------------------------------------------------
static std::string ipadd_to_string(const ASN1_OCTET_STRING* octet) {
    if (!octet) {
        return {};
    }
    const unsigned char* data = ASN1_STRING_get0_data(octet);
    int length = ASN1_STRING_length(octet);

    char buf[INET6_ADDRSTRLEN] = {};
    if (length == 4) {
        // IPv4
        inet_ntop(AF_INET, data, buf, sizeof(buf));
    } else if (length == 16) {
        // IPv6
        inet_ntop(AF_INET6, data, buf, sizeof(buf));
    } else {
        return {};
    }
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Helper: extract the Subject CN from a certificate.
// ---------------------------------------------------------------------------
static std::string get_subject_cn(X509* cert) {
    if (!cert) {
        return {};
    }
    X509_NAME* subject = X509_get_subject_name(cert);
    if (!subject) {
        return {};
    }
    int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    if (idx < 0) {
        return {};
    }
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, idx);
    if (!entry) {
        return {};
    }
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    return asn1_string_to_utf8(data);
}

// ---------------------------------------------------------------------------
// Helper: try to match a string against a regex pattern.
// Returns true on match, false otherwise (including invalid regex).
// ---------------------------------------------------------------------------
static bool regex_match_safe(const std::string& text, const std::string& pattern) {
    try {
        std::regex re(pattern, std::regex::ECMAScript);
        return std::regex_search(text, re);
    } catch (const std::regex_error& e) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier: invalid regex pattern '%s': %s",
                    pattern.c_str(), e.what());
        return false;
    }
}

// ---------------------------------------------------------------------------
// verify_peer
// ---------------------------------------------------------------------------
X509* CertificateVerifier::verify_peer(SSL* ssl) {
    if (!ssl) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::verify_peer: SSL pointer is null");
        return nullptr;
    }

    long result = SSL_get_verify_result(ssl);
    if (result != X509_V_OK) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::verify_peer: verification failed with code %ld (%s)",
                    result, X509_verify_cert_error_string(result));
        return nullptr;
    }

    // SSL_get1_peer_certificate increments the reference count; caller owns it.
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (!cert) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::verify_peer: no peer certificate available");
        return nullptr;
    }

    return cert;
}

// ---------------------------------------------------------------------------
// check_hostname
// ---------------------------------------------------------------------------
bool CertificateVerifier::check_hostname(X509* cert, const std::string& name,
                                          bool check_cn) {
    if (!cert || name.empty()) {
        return false;
    }

    // Check if the name is an IP address.
    if (is_ip_address(name)) {
        // Use X509_check_ip_asc for IP address matching against SAN IP entries.
        int rc = X509_check_ip_asc(cert, name.c_str(), 0);
        if (rc == 1) {
            return true;
        }
        Logger::log(LogLevel::Debug,
                    "CertificateVerifier::check_hostname: IP '%s' did not match SAN",
                    name.c_str());
        return false;
    }

    // DNS hostname matching via X509_check_host (checks DNS SANs).
    int rc = X509_check_host(cert, name.c_str(), name.size(), 0, nullptr);
    if (rc == 1) {
        return true;
    }

    // Fallback: check Subject CN if enabled.
    if (check_cn) {
        std::string cn = get_subject_cn(cert);
        if (!cn.empty() && cn == name) {
            return true;
        }
    }

    Logger::log(LogLevel::Debug,
                "CertificateVerifier::check_hostname: hostname '%s' did not match certificate",
                name.c_str());
    return false;
}

// ---------------------------------------------------------------------------
// match_rules
// ---------------------------------------------------------------------------
bool CertificateVerifier::match_rules(X509* cert,
                                       const std::vector<CertMatchRule>& rules) {
    if (!cert || rules.empty()) {
        return false;
    }

    // Get the SubjectAltName extension.
    GENERAL_NAMES* sans = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));

    for (const auto& rule : rules) {
        // Handle CN_Regex separately (not in SAN).
        if (rule.type == CertMatchRule::CN_Regex) {
            std::string cn = get_subject_cn(cert);
            if (!cn.empty() && regex_match_safe(cn, rule.pattern)) {
                GENERAL_NAMES_free(sans);
                return true;
            }
            continue;
        }

        if (!sans) {
            continue;
        }

        int num_sans = sk_GENERAL_NAME_num(sans);
        for (int i = 0; i < num_sans; ++i) {
            const GENERAL_NAME* gen = sk_GENERAL_NAME_value(sans, i);
            if (!gen) {
                continue;
            }

            switch (rule.type) {
            case CertMatchRule::DNS_Regex: {
                if (gen->type != GEN_DNS) continue;
                std::string dns_name = asn1_string_to_utf8(gen->d.dNSName);
                if (regex_match_safe(dns_name, rule.pattern)) {
                    GENERAL_NAMES_free(sans);
                    return true;
                }
                break;
            }
            case CertMatchRule::URI_Regex: {
                if (gen->type != GEN_URI) continue;
                std::string uri = asn1_string_to_utf8(gen->d.uniformResourceIdentifier);
                if (regex_match_safe(uri, rule.pattern)) {
                    GENERAL_NAMES_free(sans);
                    return true;
                }
                break;
            }
            case CertMatchRule::IP_Address: {
                if (gen->type != GEN_IPADD) continue;
                std::string ip_str = ipadd_to_string(gen->d.iPAddress);
                if (ip_str == rule.pattern) {
                    GENERAL_NAMES_free(sans);
                    return true;
                }
                break;
            }
            case CertMatchRule::RegisteredID: {
                if (gen->type != GEN_RID) continue;
                // Convert the ASN1_OBJECT to a dotted OID string.
                char oid_buf[256] = {};
                OBJ_obj2txt(oid_buf, sizeof(oid_buf), gen->d.registeredID, 1);
                if (std::string(oid_buf) == rule.pattern) {
                    GENERAL_NAMES_free(sans);
                    return true;
                }
                break;
            }
            case CertMatchRule::OtherName: {
                if (gen->type != GEN_OTHERNAME) continue;
                // Match OID first.
                char oid_buf[256] = {};
                OBJ_obj2txt(oid_buf, sizeof(oid_buf),
                            gen->d.otherName->type_id, 1);
                if (std::string(oid_buf) != rule.oid) {
                    continue;
                }
                // Extract the value and match against the regex pattern.
                ASN1_TYPE* val = gen->d.otherName->value;
                if (val && val->type == V_ASN1_UTF8STRING) {
                    std::string text = asn1_string_to_utf8(val->value.utf8string);
                    if (regex_match_safe(text, rule.pattern)) {
                        GENERAL_NAMES_free(sans);
                        return true;
                    }
                }
                break;
            }
            default:
                break;
            }
        }
    }

    GENERAL_NAMES_free(sans);
    return false;
}

// ---------------------------------------------------------------------------
// reverify
// ---------------------------------------------------------------------------
int CertificateVerifier::reverify(SSL* ssl, SSL_CTX* new_ctx) {
    if (!ssl || !new_ctx) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::reverify: null SSL or SSL_CTX pointer");
        return -1;
    }

    // Get the peer certificate from the existing connection.
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (!cert) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::reverify: no peer certificate on connection");
        return -1;
    }

    // Get the trust store from the new SSL_CTX.
    X509_STORE* store = SSL_CTX_get_cert_store(new_ctx);
    if (!store) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::reverify: no certificate store in new SSL_CTX");
        X509_free(cert);
        return -1;
    }

    // Create a verification context.
    X509_STORE_CTX* store_ctx = X509_STORE_CTX_new();
    if (!store_ctx) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::reverify: failed to create X509_STORE_CTX");
        X509_free(cert);
        return -1;
    }

    // Get the peer's certificate chain if available.
    STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);

    int result = -1;
    if (X509_STORE_CTX_init(store_ctx, store, cert, chain) != 1) {
        Logger::log(LogLevel::Error,
                    "CertificateVerifier::reverify: X509_STORE_CTX_init failed");
    } else {
        int verify_rc = X509_verify_cert(store_ctx);
        if (verify_rc == 1) {
            result = 1;
            Logger::log(LogLevel::Info,
                        "CertificateVerifier::reverify: certificate re-verification succeeded");
        } else {
            result = 0;
            int err = X509_STORE_CTX_get_error(store_ctx);
            int depth = X509_STORE_CTX_get_error_depth(store_ctx);
            Logger::log(LogLevel::Error,
                        "CertificateVerifier::reverify: verification failed at depth %d: %s",
                        depth, X509_verify_cert_error_string(err));
        }
    }

    X509_STORE_CTX_free(store_ctx);
    X509_free(cert);
    return result;
}

// ---------------------------------------------------------------------------
// set_callback
// ---------------------------------------------------------------------------
void CertificateVerifier::set_callback(VerifyCallback cb) {
    custom_cb_ = std::move(cb);
}

// ---------------------------------------------------------------------------
// get_subject
// ---------------------------------------------------------------------------
std::string CertificateVerifier::get_subject(X509* cert) {
    if (!cert) {
        return {};
    }

    X509_NAME* name = X509_get_subject_name(cert);
    if (!name) {
        return {};
    }

    // Use X509_NAME_print_ex to get a readable subject string.
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return {};
    }

    // XN_FLAG_ONELINE produces a single-line, human-readable format.
    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_ONELINE) < 0) {
        BIO_free(bio);
        return {};
    }

    char* buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string result;
    if (buf && len > 0) {
        result.assign(buf, static_cast<size_t>(len));
    }

    BIO_free(bio);
    return result;
}

} // namespace gtls
