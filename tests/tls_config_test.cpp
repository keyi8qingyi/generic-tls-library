// =============================================================================
// Generic TLS Library (gtls) - TlsConfig unit tests and property tests
// Tests configuration validation and equality comparison.
// =============================================================================

#include <gtest/gtest.h>
#include <rapidcheck/gtest.h>
#include "gtls/tls_config.h"
#include "gtls/config_parser.h"
#include "gtls/config_serializer.h"

namespace gtls {
namespace {

// Helper: create a valid TlsConfig with all required fields set.
TlsConfig make_valid_config() {
    TlsConfig cfg;
    cfg.ca_cert_file = "/etc/ssl/ca.pem";
    cfg.cert_file = "/etc/ssl/cert.pem";
    cfg.cert_key_file = "/etc/ssl/key.pem";
    return cfg;
}

// ---------------------------------------------------------------------------
// Validation tests (Requirements 1.1, 1.2, 1.3, 1.4)
// ---------------------------------------------------------------------------

TEST(TlsConfigValidation, ValidConfigReturnsEmptyString) {
    // Req 1.1: A fully populated config should pass validation.
    TlsConfig cfg = make_valid_config();
    EXPECT_EQ(cfg.validate(), "");
}

TEST(TlsConfigValidation, ValidConfigWithCaPathReturnsEmptyString) {
    // ca_cert_path is an alternative to ca_cert_file.
    TlsConfig cfg;
    cfg.ca_cert_path = "/etc/ssl/certs";
    cfg.cert_file = "/etc/ssl/cert.pem";
    cfg.cert_key_file = "/etc/ssl/key.pem";
    EXPECT_EQ(cfg.validate(), "");
}

TEST(TlsConfigValidation, BothCertAndKeyEmptyReturnsError) {
    // Req 1.4: cert_file and cert_key_file are both required.
    TlsConfig cfg;
    cfg.ca_cert_file = "/etc/ssl/ca.pem";
    std::string err = cfg.validate();
    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("cert_file"), std::string::npos);
}

TEST(TlsConfigValidation, CertWithoutKeyReturnsError) {
    // Req 1.2: cert_file set but cert_key_file empty.
    TlsConfig cfg;
    cfg.ca_cert_file = "/etc/ssl/ca.pem";
    cfg.cert_file = "/etc/ssl/cert.pem";
    std::string err = cfg.validate();
    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("cert_key_file"), std::string::npos);
}

TEST(TlsConfigValidation, KeyWithoutCertReturnsError) {
    // Reverse case: key set but cert empty.
    TlsConfig cfg;
    cfg.ca_cert_file = "/etc/ssl/ca.pem";
    cfg.cert_key_file = "/etc/ssl/key.pem";
    std::string err = cfg.validate();
    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("cert_file"), std::string::npos);
}

TEST(TlsConfigValidation, CertWithoutCaReturnsError) {
    // Req 1.3: cert_file set but no CA source.
    TlsConfig cfg;
    cfg.cert_file = "/etc/ssl/cert.pem";
    cfg.cert_key_file = "/etc/ssl/key.pem";
    std::string err = cfg.validate();
    EXPECT_FALSE(err.empty());
    EXPECT_NE(err.find("ca_cert"), std::string::npos);
}

TEST(TlsConfigValidation, DefaultConfigReturnsError) {
    // Default-constructed config has no cert/key, should fail (Req 1.4).
    TlsConfig cfg;
    EXPECT_FALSE(cfg.validate().empty());
}

// ---------------------------------------------------------------------------
// Equality operator tests
// ---------------------------------------------------------------------------

TEST(TlsConfigEquality, IdenticalConfigsAreEqual) {
    TlsConfig a = make_valid_config();
    TlsConfig b = make_valid_config();
    EXPECT_TRUE(a == b);
    EXPECT_FALSE(a != b);
}

TEST(TlsConfigEquality, DifferentCaCertFileNotEqual) {
    TlsConfig a = make_valid_config();
    TlsConfig b = make_valid_config();
    b.ca_cert_file = "/other/ca.pem";
    EXPECT_FALSE(a == b);
    EXPECT_TRUE(a != b);
}

TEST(TlsConfigEquality, DifferentOptionalFieldsNotEqual) {
    TlsConfig a = make_valid_config();
    TlsConfig b = make_valid_config();

    // Each optional field difference should break equality.
    b.crl_check = true;
    EXPECT_NE(a, b);

    b = make_valid_config();
    b.cipher_list = "AES256-SHA";
    EXPECT_NE(a, b);

    b = make_valid_config();
    b.tls_min_version = 0x0303;
    EXPECT_NE(a, b);

    b = make_valid_config();
    b.cache_expiry = 300;
    EXPECT_NE(a, b);

    b = make_valid_config();
    b.policy_oids.push_back("1.2.3.4");
    EXPECT_NE(a, b);
}

TEST(TlsConfigEquality, DefaultConfigsAreEqual) {
    TlsConfig a;
    TlsConfig b;
    EXPECT_EQ(a, b);
}

TEST(TlsConfigEquality, AllFieldsCompared) {
    // Verify that operator== compares every single field by
    // changing each one individually and checking inequality.
    TlsConfig base = make_valid_config();
    base.ca_cert_path = "/certs";
    base.cert_key_password = "secret";
    base.crl_check = true;
    base.policy_oids = {"1.2.3"};
    base.cipher_list = "HIGH";
    base.cipher_suites = "TLS_AES_256_GCM_SHA384";
    base.tls_min_version = 0x0303;
    base.tls_max_version = 0x0304;
    base.dh_param_file = "/dh.pem";
    base.cache_expiry = 600;

    // Self-equality
    EXPECT_EQ(base, base);

    // Modify each field and verify inequality
    auto test_field = [&](auto modifier) {
        TlsConfig copy = base;
        modifier(copy);
        EXPECT_NE(base, copy);
    };

    test_field([](TlsConfig& c) { c.ca_cert_file = "x"; });
    test_field([](TlsConfig& c) { c.ca_cert_path = "x"; });
    test_field([](TlsConfig& c) { c.cert_file = "x"; });
    test_field([](TlsConfig& c) { c.cert_key_file = "x"; });
    test_field([](TlsConfig& c) { c.cert_key_password = "x"; });
    test_field([](TlsConfig& c) { c.crl_check = false; });
    test_field([](TlsConfig& c) { c.policy_oids = {"9.9.9"}; });
    test_field([](TlsConfig& c) { c.cipher_list = "x"; });
    test_field([](TlsConfig& c) { c.cipher_suites = "x"; });
    test_field([](TlsConfig& c) { c.tls_min_version = 99; });
    test_field([](TlsConfig& c) { c.tls_max_version = 99; });
    test_field([](TlsConfig& c) { c.dh_param_file = "x"; });
    test_field([](TlsConfig& c) { c.cache_expiry = 999; });
}

// ---------------------------------------------------------------------------
// Property-based tests (RapidCheck)
// ---------------------------------------------------------------------------

// Helper: generate a non-empty string for file paths and config values.
static rc::Gen<std::string> genNonEmptyPath() {
    return rc::gen::map(rc::gen::nonEmpty<std::string>(), [](std::string s) {
        // Ensure the string contains at least one printable character
        // and prefix with "/" to look like a path.
        return "/" + s;
    });
}

// Feature: generic-tls-library, Property 2: Incomplete config validation rejection
// **Validates: Requirements 1.2, 1.3, 1.4**
//
// For ANY TlsConfig where:
//   (a) cert_file is set but cert_key_file is empty, OR
//   (b) cert_file is set but both ca_cert_file and ca_cert_path are empty, OR
//   (c) both cert_file and cert_key_file are empty
// validate() MUST return a non-empty error string.
RC_GTEST_PROP(TlsConfigProperty, IncompleteConfigValidationRejection, ()) {
    // Choose one of three incomplete configuration scenarios
    int scenario = *rc::gen::inRange(0, 3);

    TlsConfig cfg;

    // Fill optional fields with arbitrary values to ensure the property
    // holds regardless of other field contents.
    cfg.cert_key_password = *rc::gen::arbitrary<std::string>();
    cfg.crl_check = *rc::gen::arbitrary<bool>();
    cfg.cipher_list = *rc::gen::arbitrary<std::string>();
    cfg.cipher_suites = *rc::gen::arbitrary<std::string>();
    cfg.tls_min_version = *rc::gen::arbitrary<int>();
    cfg.tls_max_version = *rc::gen::arbitrary<int>();
    cfg.dh_param_file = *rc::gen::arbitrary<std::string>();
    cfg.cache_expiry = *rc::gen::arbitrary<int>();

    switch (scenario) {
        case 0: {
            // Scenario (a) - Req 1.2: cert_file set but cert_key_file empty
            cfg.cert_file = *genNonEmptyPath();
            cfg.cert_key_file = "";
            // CA fields can be anything
            cfg.ca_cert_file = *rc::gen::arbitrary<std::string>();
            cfg.ca_cert_path = *rc::gen::arbitrary<std::string>();
            break;
        }
        case 1: {
            // Scenario (b) - Req 1.3: cert_file set but no CA source
            cfg.cert_file = *genNonEmptyPath();
            cfg.cert_key_file = *genNonEmptyPath();
            cfg.ca_cert_file = "";
            cfg.ca_cert_path = "";
            break;
        }
        case 2: {
            // Scenario (c) - Req 1.4: both cert_file and cert_key_file empty
            cfg.cert_file = "";
            cfg.cert_key_file = "";
            // CA fields can be anything
            cfg.ca_cert_file = *rc::gen::arbitrary<std::string>();
            cfg.ca_cert_path = *rc::gen::arbitrary<std::string>();
            break;
        }
    }

    std::string error = cfg.validate();
    RC_ASSERT(!error.empty());
}

// Feature: generic-tls-library, Property 3: Valid config field integrity
// **Validates: Requirements 1.1**
//
// For ANY TlsConfig where ALL required fields are set:
//   - cert_file is non-empty
//   - cert_key_file is non-empty
//   - at least one of ca_cert_file or ca_cert_path is non-empty
// validate() MUST return an empty string (no error),
// AND all field values MUST remain unchanged after calling validate().
RC_GTEST_PROP(TlsConfigProperty, ValidConfigFieldIntegrity, ()) {
    TlsConfig cfg;

    // Generate non-empty required fields
    cfg.cert_file = *genNonEmptyPath();
    cfg.cert_key_file = *genNonEmptyPath();

    // At least one CA source must be non-empty; randomly choose which one(s)
    int ca_scenario = *rc::gen::inRange(0, 3);
    switch (ca_scenario) {
        case 0:
            // Only ca_cert_file set
            cfg.ca_cert_file = *genNonEmptyPath();
            cfg.ca_cert_path = *rc::gen::arbitrary<std::string>();
            break;
        case 1:
            // Only ca_cert_path set
            cfg.ca_cert_file = *rc::gen::arbitrary<std::string>();
            cfg.ca_cert_path = *genNonEmptyPath();
            break;
        case 2:
            // Both set
            cfg.ca_cert_file = *genNonEmptyPath();
            cfg.ca_cert_path = *genNonEmptyPath();
            break;
    }

    // Generate arbitrary values for optional fields
    cfg.cert_key_password = *rc::gen::arbitrary<std::string>();
    cfg.crl_check = *rc::gen::arbitrary<bool>();
    cfg.policy_oids = *rc::gen::arbitrary<std::vector<std::string>>();
    cfg.cipher_list = *rc::gen::arbitrary<std::string>();
    cfg.cipher_suites = *rc::gen::arbitrary<std::string>();
    cfg.tls_min_version = *rc::gen::arbitrary<int>();
    cfg.tls_max_version = *rc::gen::arbitrary<int>();
    cfg.dh_param_file = *rc::gen::arbitrary<std::string>();
    cfg.cache_expiry = *rc::gen::arbitrary<int>();

    // Take a copy before validation to verify field integrity
    TlsConfig copy = cfg;

    // Valid config must pass validation
    std::string error = cfg.validate();
    RC_ASSERT(error.empty());

    // All fields must remain unchanged after validate()
    RC_ASSERT(cfg == copy);
}

// ---------------------------------------------------------------------------
// Safe string generator for round-trip serialization testing.
// Generates printable strings that do not contain characters which would
// break the key-value format: '=', '\n', '#', ','
// Also ensures no leading/trailing whitespace (parser trims).
// ---------------------------------------------------------------------------

// Characters safe for config values (printable ASCII excluding special chars)
static const std::string kSafeChars =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "/_.-+:;!@$%^&*()[]{}|<>?~`";

// Generate a single safe character
static rc::Gen<char> genSafeChar() {
    return rc::gen::elementOf(
        std::vector<char>(kSafeChars.begin(), kSafeChars.end()));
}

// Generate a non-empty safe string (no special chars, no leading/trailing whitespace)
static rc::Gen<std::string> genSafeString() {
    return rc::gen::mapcat(
        rc::gen::inRange<std::size_t>(1, 20),
        [](std::size_t len) {
            return rc::gen::container<std::string>(len, genSafeChar());
        });
}

// Generate an optional safe string (empty or non-empty)
static rc::Gen<std::string> genOptionalSafeString() {
    return rc::gen::oneOf(
        rc::gen::just(std::string("")),
        genSafeString());
}

// Generate a safe policy OID entry (no commas allowed)
static rc::Gen<std::string> genSafeOid() {
    // OIDs look like "1.2.3.4" — generate dot-separated numbers
    return rc::gen::mapcat(
        rc::gen::inRange<std::size_t>(1, 5),
        [](std::size_t count) {
            return rc::gen::map(
                rc::gen::container<std::vector<int>>(count, rc::gen::inRange(0, 100)),
                [](const std::vector<int>& parts) {
                    std::string oid;
                    for (size_t i = 0; i < parts.size(); ++i) {
                        if (i > 0) oid += ".";
                        oid += std::to_string(parts[i]);
                    }
                    return oid;
                });
        });
}

// Generate a safe TlsConfig suitable for round-trip serialization testing.
// All string fields use safe characters; integer fields use valid ranges.
static rc::Gen<TlsConfig> genSafeTlsConfig() {
    return rc::gen::build<TlsConfig>(
        rc::gen::set(&TlsConfig::ca_cert_file, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::ca_cert_path, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::cert_file, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::cert_key_file, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::cert_key_password, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::crl_check, rc::gen::arbitrary<bool>()),
        rc::gen::set(&TlsConfig::policy_oids,
            rc::gen::mapcat(
                rc::gen::inRange<std::size_t>(0, 4),
                [](std::size_t count) {
                    return rc::gen::container<std::vector<std::string>>(count, genSafeOid());
                })),
        rc::gen::set(&TlsConfig::cipher_list, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::cipher_suites, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::tls_min_version,
            rc::gen::oneOf(rc::gen::just(-1), rc::gen::inRange(0, 1000))),
        rc::gen::set(&TlsConfig::tls_max_version,
            rc::gen::oneOf(rc::gen::just(-1), rc::gen::inRange(0, 1000))),
        rc::gen::set(&TlsConfig::dh_param_file, genOptionalSafeString()),
        rc::gen::set(&TlsConfig::cache_expiry,
            rc::gen::oneOf(rc::gen::just(-1), rc::gen::inRange(0, 86400)))
    );
}

// Feature: generic-tls-library, Property 1: Config serialization round-trip consistency
// **Validates: Requirements 1.5, 1.6, 1.7**
//
// For ANY valid TlsConfig, serializing it to key-value text and then parsing
// it back MUST produce an identical TlsConfig object.
// This verifies that ConfigSerializer and ConfigParser are inverse operations.
RC_GTEST_PROP(TlsConfigProperty, ConfigSerializationRoundTripConsistency, ()) {
    TlsConfig original = *genSafeTlsConfig();

    // Serialize the config to key-value text
    std::string serialized = ConfigSerializer::serialize(original);

    // Parse it back
    ParseResult result = ConfigParser::parse(serialized);

    // Parse must succeed
    RC_ASSERT(result.ok());

    // Round-trip must produce identical config
    RC_ASSERT(result.config == original);
}

} // namespace
} // namespace gtls
