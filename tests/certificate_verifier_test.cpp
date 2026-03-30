// =============================================================================
// Generic TLS Library (gtls) - CertificateVerifier property-based tests
// Tests certificate match rules correctness using RapidCheck property testing
// framework with programmatically generated X509 certificates.
// =============================================================================

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include <arpa/inet.h>

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "gtls/certificate_verifier.h"
#include "gtls/library.h"

namespace gtls {
namespace {

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL resources used in test certificate generation.
// ---------------------------------------------------------------------------
struct X509Deleter {
    void operator()(X509* p) const { X509_free(p); }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

struct EVPKeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
using EVPKeyPtr = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;

// ---------------------------------------------------------------------------
// Helper: generate a self-signed RSA key pair for test certificate signing.
// ---------------------------------------------------------------------------
static EVPKeyPtr generate_test_key() {
    EVPKeyPtr pkey(EVP_PKEY_new());
    if (!pkey) return nullptr;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;

    bool ok = (EVP_PKEY_keygen_init(ctx) > 0 &&
               EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) > 0);
    EVP_PKEY* raw = nullptr;
    if (ok) {
        ok = (EVP_PKEY_keygen(ctx, &raw) > 0);
    }
    EVP_PKEY_CTX_free(ctx);

    if (!ok || !raw) return nullptr;
    pkey.reset(raw);
    return pkey;
}

// ---------------------------------------------------------------------------
// Helper: create a self-signed X509 certificate with a given CN value.
// Optionally adds DNS SAN entries and/or IP SAN entries.
// ---------------------------------------------------------------------------
struct CertSpec {
    std::string cn;                     // Subject CN value
    std::vector<std::string> dns_sans;  // DNS SAN entries
    std::vector<std::string> ip_sans;   // IP SAN entries (as human-readable strings)
};

static X509Ptr create_test_cert(const CertSpec& spec, EVP_PKEY* pkey) {
    X509Ptr cert(X509_new());
    if (!cert) return nullptr;

    // Set version to X509v3
    X509_set_version(cert.get(), 2);

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);

    // Set validity (not before = now, not after = now + 1 year)
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 365 * 24 * 3600);

    // Set subject CN
    X509_NAME* name = X509_get_subject_name(cert.get());
    if (!spec.cn.empty()) {
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(spec.cn.c_str()),
            -1, -1, 0);
    }

    // Set issuer = subject (self-signed)
    X509_set_issuer_name(cert.get(), name);

    // Set public key
    X509_set_pubkey(cert.get(), pkey);

    // Add SAN extensions if any DNS or IP entries are specified
    if (!spec.dns_sans.empty() || !spec.ip_sans.empty()) {
        GENERAL_NAMES* sans = sk_GENERAL_NAME_new_null();

        for (const auto& dns : spec.dns_sans) {
            GENERAL_NAME* gen = GENERAL_NAME_new();
            gen->type = GEN_DNS;
            gen->d.dNSName = ASN1_IA5STRING_new();
            ASN1_STRING_set(gen->d.dNSName, dns.c_str(),
                            static_cast<int>(dns.size()));
            sk_GENERAL_NAME_push(sans, gen);
        }

        for (const auto& ip_str : spec.ip_sans) {
            GENERAL_NAME* gen = GENERAL_NAME_new();
            gen->type = GEN_IPADD;
            gen->d.iPAddress = ASN1_OCTET_STRING_new();

            // Try IPv4 first, then IPv6
            unsigned char ipv4_buf[4];
            unsigned char ipv6_buf[16];
            if (inet_pton(AF_INET, ip_str.c_str(), ipv4_buf) == 1) {
                ASN1_OCTET_STRING_set(gen->d.iPAddress, ipv4_buf, 4);
            } else if (inet_pton(AF_INET6, ip_str.c_str(), ipv6_buf) == 1) {
                ASN1_OCTET_STRING_set(gen->d.iPAddress, ipv6_buf, 16);
            } else {
                GENERAL_NAME_free(gen);
                continue;
            }
            sk_GENERAL_NAME_push(sans, gen);
        }

        X509_add1_ext_i2d(cert.get(), NID_subject_alt_name, sans, 0,
                           X509V3_ADD_DEFAULT);
        GENERAL_NAMES_free(sans);
    }

    // Self-sign the certificate
    if (X509_sign(cert.get(), pkey, EVP_sha256()) <= 0) {
        return nullptr;
    }

    return cert;
}

// ---------------------------------------------------------------------------
// RapidCheck generators for test data.
// ---------------------------------------------------------------------------

// Generate a valid DNS-like hostname label (alphanumeric, 3-8 chars).
static rc::Gen<std::string> genHostnameLabel() {
    return rc::gen::map(
        rc::gen::container<std::string>(
            rc::gen::oneOf(
                rc::gen::inRange('a', static_cast<char>('z' + 1)),
                rc::gen::inRange('0', static_cast<char>('9' + 1))
            )
        ),
        [](std::string s) {
            // Ensure at least 3 chars and at most 8
            if (s.size() < 3) s += "abc";
            if (s.size() > 8) s.resize(8);
            return s;
        }
    );
}

// Generate a valid DNS hostname like "abc.def.example.com".
static rc::Gen<std::string> genHostname() {
    return rc::gen::map(
        rc::gen::tuple(genHostnameLabel(), genHostnameLabel()),
        [](const std::tuple<std::string, std::string>& t) {
            return std::get<0>(t) + "." + std::get<1>(t) + ".example.com";
        }
    );
}

// Generate a valid IPv4 address string.
static rc::Gen<std::string> genIPv4() {
    return rc::gen::map(
        rc::gen::tuple(
            rc::gen::inRange(1, 255),
            rc::gen::inRange(0, 256),
            rc::gen::inRange(0, 256),
            rc::gen::inRange(1, 255)
        ),
        [](const std::tuple<int, int, int, int>& t) {
            return std::to_string(std::get<0>(t)) + "." +
                   std::to_string(std::get<1>(t)) + "." +
                   std::to_string(std::get<2>(t)) + "." +
                   std::to_string(std::get<3>(t));
        }
    );
}

// ---------------------------------------------------------------------------
// Test fixture: ensures OpenSSL is initialized and provides a shared key.
// Uses SetUp() with call_once since RC_GTEST_FIXTURE_PROP may not invoke
// SetUpTestSuite reliably.
// ---------------------------------------------------------------------------
class CertVerifierPropertyTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::call_once(init_flag_, []() {
            Library::init();
            shared_key_ = generate_test_key();
        });
    }

    static std::once_flag init_flag_;
    static EVPKeyPtr shared_key_;
};

std::once_flag CertVerifierPropertyTest::init_flag_;
EVPKeyPtr CertVerifierPropertyTest::shared_key_ = nullptr;


// ---------------------------------------------------------------------------
// Property 11: Certificate match rules correctness
//
// For ANY X509 certificate containing SubjectAltName (DNS, IP) or Subject CN,
// and for ANY corresponding CertMatchRule, match_rules() SHALL return true
// if and only if the certificate field matches the rule pattern.
//
// Feature: generic-tls-library, Property 11: Certificate match rules correctness
// **Validates: Requirements 5.2, 5.3, 5.4, 5.5, 5.6**
// ---------------------------------------------------------------------------

// Sub-property 11a: CN_Regex matching — a regex that matches the CN returns true
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       CnRegexMatchingReturnsTrue, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    // Generate a random hostname to use as CN
    auto cn_value = *genHostname();
    RC_PRE(!cn_value.empty());

    CertSpec spec;
    spec.cn = cn_value;
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    // Build a CN_Regex rule that matches the exact CN value.
    // Escape dots for regex and anchor the pattern.
    std::string pattern = cn_value;
    // Replace '.' with '\\.' for regex literal matching
    std::string escaped;
    for (char c : pattern) {
        if (c == '.') {
            escaped += "\\.";
        } else {
            escaped += c;
        }
    }
    escaped = "^" + escaped + "$";

    CertMatchRule rule;
    rule.type = CertMatchRule::CN_Regex;
    rule.pattern = escaped;

    std::vector<CertMatchRule> rules = {rule};
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == true);
}

// Sub-property 11b: CN_Regex non-matching — a regex that cannot match returns false
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       CnRegexNonMatchingReturnsFalse, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    auto cn_value = *genHostname();
    RC_PRE(!cn_value.empty());

    CertSpec spec;
    spec.cn = cn_value;
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    // Use a pattern that definitely does not match: anchored string with
    // a prefix that cannot appear in the generated hostname.
    CertMatchRule rule;
    rule.type = CertMatchRule::CN_Regex;
    rule.pattern = "^NOMATCH_ZZZZZ_NEVER$";

    std::vector<CertMatchRule> rules = {rule};
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == false);
}

// Sub-property 11c: DNS_Regex matching — a regex that matches a DNS SAN returns true
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       DnsRegexMatchingReturnsTrue, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    auto dns_name = *genHostname();
    RC_PRE(!dns_name.empty());

    CertSpec spec;
    spec.cn = "irrelevant.example.com";
    spec.dns_sans = {dns_name};
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    // Build a DNS_Regex rule that matches the exact DNS SAN value
    std::string escaped;
    for (char c : dns_name) {
        if (c == '.') {
            escaped += "\\.";
        } else {
            escaped += c;
        }
    }
    escaped = "^" + escaped + "$";

    CertMatchRule rule;
    rule.type = CertMatchRule::DNS_Regex;
    rule.pattern = escaped;

    std::vector<CertMatchRule> rules = {rule};
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == true);
}

// Sub-property 11d: DNS_Regex non-matching — a regex that cannot match returns false
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       DnsRegexNonMatchingReturnsFalse, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    auto dns_name = *genHostname();
    RC_PRE(!dns_name.empty());

    CertSpec spec;
    spec.cn = "irrelevant.example.com";
    spec.dns_sans = {dns_name};
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    // Use a pattern that definitely does not match
    CertMatchRule rule;
    rule.type = CertMatchRule::DNS_Regex;
    rule.pattern = "^NOMATCH_ZZZZZ_NEVER$";

    std::vector<CertMatchRule> rules = {rule};
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == false);
}

// Sub-property 11e: IP_Address matching — exact IP match returns true
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       IpAddressMatchingReturnsTrue, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    auto ip_addr = *genIPv4();

    CertSpec spec;
    spec.cn = "irrelevant.example.com";
    spec.ip_sans = {ip_addr};
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    // IP_Address rule uses exact string comparison
    CertMatchRule rule;
    rule.type = CertMatchRule::IP_Address;
    rule.pattern = ip_addr;

    std::vector<CertMatchRule> rules = {rule};
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == true);
}

// Sub-property 11f: IP_Address non-matching — different IP returns false
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       IpAddressNonMatchingReturnsFalse, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    auto ip_addr = *genIPv4();

    CertSpec spec;
    spec.cn = "irrelevant.example.com";
    spec.ip_sans = {ip_addr};
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    // Use a definitely different IP address
    CertMatchRule rule;
    rule.type = CertMatchRule::IP_Address;
    rule.pattern = "254.254.254.254";

    // Ensure the generated IP is not the same as our non-matching IP
    RC_PRE(ip_addr != "254.254.254.254");

    std::vector<CertMatchRule> rules = {rule};
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == false);
}

// Sub-property 11g: Empty rules always returns false
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       EmptyRulesReturnsFalse, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    auto cn_value = *genHostname();
    RC_PRE(!cn_value.empty());

    CertSpec spec;
    spec.cn = cn_value;
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    std::vector<CertMatchRule> rules;  // empty
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == false);
}

// Sub-property 11h: ANY-rule semantics — match_rules returns true if ANY rule matches
RC_GTEST_FIXTURE_PROP(CertVerifierPropertyTest,
                       AnyRuleMatchSuffices, ()) {
    RC_ASSERT(shared_key_ != nullptr);

    auto cn_value = *genHostname();
    RC_PRE(!cn_value.empty());

    CertSpec spec;
    spec.cn = cn_value;
    X509Ptr cert = create_test_cert(spec, shared_key_.get());
    RC_ASSERT(cert != nullptr);

    // Build a matching CN_Regex rule
    std::string escaped;
    for (char c : cn_value) {
        if (c == '.') {
            escaped += "\\.";
        } else {
            escaped += c;
        }
    }
    escaped = "^" + escaped + "$";

    // First rule: non-matching, second rule: matching
    CertMatchRule non_matching;
    non_matching.type = CertMatchRule::CN_Regex;
    non_matching.pattern = "^NOMATCH_ZZZZZ_NEVER$";

    CertMatchRule matching;
    matching.type = CertMatchRule::CN_Regex;
    matching.pattern = escaped;

    std::vector<CertMatchRule> rules = {non_matching, matching};
    bool result = CertificateVerifier::match_rules(cert.get(), rules);
    RC_ASSERT(result == true);
}

} // namespace
} // namespace gtls
