// =============================================================================
// Generic TLS Library (gtls) - Certificate verification module
// Provides certificate chain verification, hostname checking, SAN matching,
// custom match rules, and re-verification against new SSL_CTX.
// =============================================================================
#ifndef GTLS_CERTIFICATE_VERIFIER_H
#define GTLS_CERTIFICATE_VERIFIER_H

#include <functional>
#include <string>
#include <vector>

// Forward declarations for OpenSSL types.
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_st X509;

namespace gtls {

// Describes a single certificate attribute matching rule.
// Corresponds to radsecproxy's struct certattrmatch.
struct CertMatchRule {
    enum Type {
        DNS_Regex,      // Match GEN_DNS SAN entries against a regex pattern
        URI_Regex,      // Match GEN_URI SAN entries against a regex pattern
        IP_Address,     // Match GEN_IPADD SAN entries against an IP string
        RegisteredID,   // Match GEN_RID SAN entries against an OID string
        OtherName,      // Match GEN_OTHERNAME entries against OID + regex
        CN_Regex        // Match Subject CN against a regex pattern
    };

    Type type;
    std::string pattern;  // Regex pattern, IP string, or OID depending on type
    std::string oid;      // OID string, used only for OtherName type
};

// Custom verification callback type.
// Receives the peer certificate and hostname; returns true to accept.
using VerifyCallback = std::function<bool(X509* cert, const std::string& hostname)>;

// Certificate verification utility class.
// Provides static methods for peer verification, hostname checking,
// custom rule matching, and re-verification against a new trust store.
class CertificateVerifier {
public:
    // Verify the peer certificate after TLS handshake.
    // Checks SSL_get_verify_result; returns the peer certificate (caller owns)
    // on success, or nullptr on verification failure.
    static X509* verify_peer(SSL* ssl);

    // Check if the certificate matches the given hostname or IP address.
    // Uses X509_check_host() for DNS names and X509_check_ip_asc() for IPs.
    // If check_cn is true, also checks the Subject CN as a fallback.
    static bool check_hostname(X509* cert, const std::string& name,
                               bool check_cn = true);

    // Match a certificate against a set of custom rules.
    // Iterates SAN extensions and Subject CN, applying regex/IP/OID matching.
    // Returns true if ANY rule matches.
    static bool match_rules(X509* cert, const std::vector<CertMatchRule>& rules);

    // Re-verify the peer certificate against a new SSL_CTX's trust store.
    // Used for certificate hot-reload scenarios.
    // Returns 1 on success, 0 on verification failure, -1 on error.
    static int reverify(SSL* ssl, SSL_CTX* new_ctx);

    // Register a custom verification callback.
    void set_callback(VerifyCallback cb);

    // Get the subject string from a certificate.
    // Returns a human-readable subject line, or empty string on error.
    static std::string get_subject(X509* cert);

private:
    VerifyCallback custom_cb_;
};

} // namespace gtls

#endif // GTLS_CERTIFICATE_VERIFIER_H
