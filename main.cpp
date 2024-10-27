#include <iostream>
#include <string>
#include <jwt-cpp/jwt.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sqlite3.h>
#include <cstring> // For std::strlen

// Function prototypes
std::string serialize_key(RSA* private_key);
RSA* deserialize_key(const std::string& key_data);
void insert_key_into_db(sqlite3* db, const std::string& key, const std::string& kid, int expired);
std::string query_key_from_db(sqlite3* db, const std::string& kid, bool expired);

std::string bignum_to_raw_string(const BIGNUM *bn)
{
    int bn_size = BN_num_bytes(bn);
    std::string raw(bn_size, 0);
    BN_bn2bin(bn, reinterpret_cast<unsigned char *>(&raw[0]));
    return raw;
}

std::string extract_pub_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string extract_priv_key(EVP_PKEY *pkey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

std::string base64_url_encode(const std::string &data)
{
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (size_t n = 0; n < data.size(); n++)
    {
        char_array_3[i++] = data[n];
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];
    }

    // Replace '+' with '-', '/' with '_' and remove '='
    std::replace(ret.begin(), ret.end(), '+', '-');
    std::replace(ret.begin(), ret.end(), '/', '_');
    ret.erase(std::remove(ret.begin(), ret.end(), '='), ret.end());

    return ret;
}

void insert_key_into_db(sqlite3* db, const std::string& key, const std::string& kid, int expired) {
    const char* insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    // Prepare the SQL statement
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare insert statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, expired);

    // Execute the statement
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert key: " << sqlite3_errmsg(db) << std::endl;
    } else {
        std::cout << "Inserted key with kid: " << kid << " and expired: " << expired << std::endl;  // Debug print
    }

    sqlite3_finalize(stmt);
}

std::string query_key_from_db(sqlite3* db, const std::string& kid, bool expired) {
    std::string result;
    const char* query_sql = "SELECT key FROM keys WHERE exp = ?;";
    sqlite3_stmt* stmt;

    // Prepare the SQL statement
    if (sqlite3_prepare_v2(db, query_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare query statement: " << sqlite3_errmsg(db) << std::endl;
        return result;
    }

    sqlite3_bind_int(stmt, 1, expired);

    // Execute the statement
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* key = sqlite3_column_text(stmt, 0);
        result = reinterpret_cast<const char*>(key);
        std::cout << "Retrieved key for kid: " << kid << ", expired: " << expired << " => " << result << std::endl; // Debug print
    } else {
        std::cerr << "No key found for kid: " << kid << ", expired: " << expired << std::endl;
    }

    sqlite3_finalize(stmt);
    return result;
}

int main()
{
    // Open/create SQLite Database
    sqlite3 *db;
    int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);

    if (rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return 0;
    } else {
        std::cout << "Opened database successfully" << std::endl;
    }

    // Create the keys table if it doesn't exist
    const char *sql_create_table = R"(
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            kid TEXT NOT NULL,  // Added kid column for unique identification
            exp INTEGER NOT NULL
        );
    )";
    char *errMsg = 0;
    rc = sqlite3_exec(db, sql_create_table, 0, 0, &errMsg);

    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    } else {
        std::cout << "Table created successfully" << std::endl;
    }

    // Generate RSA key pair
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    std::string pub_key = extract_pub_key(pkey);
    std::string priv_key = extract_priv_key(pkey);

    // Insert valid and expired keys into the database
    insert_key_into_db(db, priv_key, "goodKID", 0);       // Insert valid key
    insert_key_into_db(db, priv_key, "expiredKID", 1);    // Insert expired key with a different KID

    httplib::Server svr;

    svr.Post("/auth", [&](const httplib::Request &req, httplib::Response &res)
    {
        auto now = std::chrono::system_clock::now();
        bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";

        std::string kid = expired ? "expiredKID" : "goodKID";
        std::string retrieved_key = query_key_from_db(db, kid, expired);
        if (retrieved_key.empty()) {
            res.set_content("No valid key found", "text/plain");
            return;
        }

        auto token = jwt::create()
            .set_issuer("issuer")
            .set_subject("subject")
            .set_audience("audience")
            .set_expires_at(expired ? now - std::chrono::seconds{1} : now + std::chrono::hours{24})
            .set_key_id(kid)
            .sign(jwt::algorithm::rs256(pub_key, priv_key));

        res.set_content(token, "text/plain");
    });

    svr.Get("/.well-known/jwks.json", [&](const httplib::Request &, httplib::Response &res)
    {
        BIGNUM* n = NULL;
        BIGNUM* e = NULL;

        if (!EVP_PKEY_get_bn_param(pkey, "n", &n) || !EVP_PKEY_get_bn_param(pkey, "e", &e)) {
            res.set_content("Error retrieving JWKS", "text/plain");
            return;
        }

        std::string n_encoded = base64_url_encode(bignum_to_raw_string(n));
        std::string e_encoded = base64_url_encode(bignum_to_raw_string(e));

        BN_free(n);
        BN_free(e);

        std::string jwks = R"({
            "keys": [
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": ")" + n_encoded + R"(",
                    "e": ")" + e_encoded + R"("
                }
            ]
        })";
        res.set_content(jwks, "application/json");
    });

    // Catch-all handlers for other methods
    auto methodNotAllowedHandler = [](const httplib::Request &req, httplib::Response &res)
    {
        if (req.path == "/auth" || req.path == "/.well-known/jwks.json")
        {
            res.status = 405;
            res.set_content("Method Not Allowed", "text/plain");
        }
        else
        {
            res.status = 404;
            res.set_content("Not Found", "text/plain");
        }
    };

    svr.Get(".*", methodNotAllowedHandler);
    svr.Post(".*", methodNotAllowedHandler);
    svr.Put(".*", methodNotAllowedHandler);
    svr.Delete(".*", methodNotAllowedHandler);
    svr.Patch(".*", methodNotAllowedHandler);

    svr.listen("127.0.0.1", 8080);

    // Cleanup
    EVP_PKEY_free(pkey);
    sqlite3_close(db);

    return 0;
}
