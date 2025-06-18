#define _POSIX_C_SOURCE 199309L
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <sys/mman.h>  

#define NONCE_SIZE crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define MAC_SIZE crypto_aead_chacha20poly1305_IETF_ABYTES
#define SALT_SIZE crypto_pwhash_SALTBYTES
#define HEADER_SIZE (1 + SALT_SIZE + NONCE_SIZE + 8)
#define MAX_MSG_SIZE 65536
#define MAX_HEX_SIZE (MAX_MSG_SIZE + HEADER_SIZE + MAC_SIZE) * 2
#define MIN_PASSWORD_LENGTH 12
#define MAX_PASSWORD_LENGTH 1024
#define VERSION_BYTE 0x04  
#define TIMESTAMP_TOLERANCE_FUTURE 300    
#define TIMESTAMP_TOLERANCE_PAST (24 * 3600)  
#define MIN_ENTROPY_BITS 80.0  
#define CACHE_LINE_SIZE 64     

#define OPSLIMIT_PRODUCTION 4  
#define MEMLIMIT_PRODUCTION (64 * 1024 * 1024)  

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define CACHE_ALIGN __attribute__((aligned(CACHE_LINE_SIZE)))
#define FORCE_INLINE __attribute__((always_inline)) inline

typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INIT = -1,
    CRYPTO_ERROR_WEAK_PASSWORD = -2,
    CRYPTO_ERROR_KEY_DERIVATION = -3,
    CRYPTO_ERROR_MESSAGE_TOO_LARGE = -4,
    CRYPTO_ERROR_MEMORY_ALLOCATION = -5,
    CRYPTO_ERROR_ENCRYPTION_FAILED = -6,
    CRYPTO_ERROR_INVALID_INPUT = -7,
    CRYPTO_ERROR_INVALID_VERSION = -8,
    CRYPTO_ERROR_TIMESTAMP_INVALID = -9,
    CRYPTO_ERROR_DECRYPTION_FAILED = -10,
    CRYPTO_ERROR_INVALID_HEX = -11,
    CRYPTO_ERROR_BUFFER_TOO_SMALL = -12,
    CRYPTO_ERROR_RATE_LIMITED = -13
} crypto_error_t;

typedef struct {
    unsigned char *data CACHE_ALIGN;
    size_t size;
    size_t capacity;
    int locked;  
} secure_buffer_t;

typedef struct {
    time_t last_operation;
    int operation_count;
    int max_ops_per_minute;
} rate_limiter_t;

static rate_limiter_t g_rate_limiter = {0, 0, 30};  

static void secure_log(const char *level, const char *msg);
static FORCE_INLINE void secure_wipe(void *data, size_t len);
static crypto_error_t secure_buffer_init(secure_buffer_t *buf, size_t capacity);
static void secure_buffer_free(secure_buffer_t *buf);
static crypto_error_t validate_password_strength_optimized(const char *password);
static FORCE_INLINE crypto_error_t safe_hex_encode_fast(const unsigned char *in, size_t in_len, char *out, size_t out_capacity);
static FORCE_INLINE crypto_error_t safe_hex_decode_fast(const char *hex, unsigned char *out, size_t out_capacity, size_t *decoded_len);
static crypto_error_t derive_key_optimized(const char *password, const unsigned char *salt, unsigned char *key_out);
static FORCE_INLINE crypto_error_t validate_timestamp(uint64_t timestamp);
static FORCE_INLINE int is_valid_hex_char(char c);
static FORCE_INLINE int is_valid_hex_string_fast(const char *hex, size_t len);
static const char* get_error_message(crypto_error_t error);
static crypto_error_t check_rate_limit(void);

static const char hex_chars[16] = "0123456789abcdef";
static const signed char hex_values[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

static crypto_error_t check_rate_limit(void) {
    time_t now = time(NULL);

    if (now - g_rate_limiter.last_operation >= 60) {
        g_rate_limiter.operation_count = 0;
        g_rate_limiter.last_operation = now;
    }

    if (UNLIKELY(g_rate_limiter.operation_count >= g_rate_limiter.max_ops_per_minute)) {
        secure_log("WARNING", "Rate limit exceeded");
        return CRYPTO_ERROR_RATE_LIMITED;
    }

    g_rate_limiter.operation_count++;
    return CRYPTO_SUCCESS;
}

static void secure_log(const char *level, const char *msg) {
    static __thread char timestamp_buf[32];  
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    if (LIKELY(tm_info && strftime(timestamp_buf, sizeof(timestamp_buf), "%Y-%m-%d %H:%M:%S", tm_info) > 0)) {
        fprintf(stderr, "[%s] %s: %s\n", timestamp_buf, level, msg);
    } else {
        fprintf(stderr, "%s: %s\n", level, msg);
    }
}

static FORCE_INLINE void secure_wipe(void *data, size_t len) {
    if (LIKELY(data && len > 0)) {
        sodium_memzero(data, len);
    }
}

static crypto_error_t secure_buffer_init(secure_buffer_t *buf, size_t capacity) {
    if (UNLIKELY(!buf || capacity == 0)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    buf->data = sodium_malloc(capacity);
    if (UNLIKELY(!buf->data)) {
        secure_log("ERROR", "Failed to allocate secure memory");
        return CRYPTO_ERROR_MEMORY_ALLOCATION;
    }

    buf->size = 0;
    buf->capacity = capacity;
    buf->locked = 0;

    #ifdef HAVE_MLOCK
    if (mlock(buf->data, capacity) == 0) {
        buf->locked = 1;
    }
    #endif

    return CRYPTO_SUCCESS;
}

static void secure_buffer_free(secure_buffer_t *buf) {
    if (LIKELY(buf && buf->data)) {
        #ifdef HAVE_MLOCK
        if (buf->locked) {
            munlock(buf->data, buf->capacity);
        }
        #endif
        sodium_free(buf->data);
        buf->data = NULL;
        buf->size = 0;
        buf->capacity = 0;
        buf->locked = 0;
    }
}

static crypto_error_t validate_password_strength_optimized(const char *password) {
    if (UNLIKELY(!password)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    const size_t len = strlen(password);
    if (UNLIKELY(len < MIN_PASSWORD_LENGTH)) {
        secure_log("WARNING", "Password too short");
        return CRYPTO_ERROR_WEAK_PASSWORD;
    }

    if (UNLIKELY(len > MAX_PASSWORD_LENGTH)) {
        secure_log("ERROR", "Password too long");
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    uint8_t char_classes = 0;
    const uint8_t HAS_UPPER = 1, HAS_LOWER = 2, HAS_DIGIT = 4, HAS_SPECIAL = 8;

    for (size_t i = 0; i < len; i++) {
        const unsigned char c = (unsigned char)password[i];

        if (UNLIKELY(c < 32 || c == 127)) {
            secure_log("ERROR", "Password contains invalid characters");
            return CRYPTO_ERROR_INVALID_INPUT;
        }

        if (c >= 'A' && c <= 'Z') char_classes |= HAS_UPPER;
        else if (c >= 'a' && c <= 'z') char_classes |= HAS_LOWER;
        else if (c >= '0' && c <= '9') char_classes |= HAS_DIGIT;
        else char_classes |= HAS_SPECIAL;

        if (char_classes == (HAS_UPPER | HAS_LOWER | HAS_DIGIT | HAS_SPECIAL)) {
            break;
        }
    }

    const int class_count = __builtin_popcount(char_classes);

    if (UNLIKELY(len < 16 && class_count < 3)) {
        secure_log("WARNING", "Password lacks complexity");
        return CRYPTO_ERROR_WEAK_PASSWORD;
    }

    double charset_size = 0;
    if (char_classes & HAS_LOWER) charset_size += 26;
    if (char_classes & HAS_UPPER) charset_size += 26;
    if (char_classes & HAS_DIGIT) charset_size += 10;
    if (char_classes & HAS_SPECIAL) charset_size += 32;

    const double entropy = log2(charset_size) * len;

    if (UNLIKELY(entropy < MIN_ENTROPY_BITS)) {
        secure_log("WARNING", "Password entropy insufficient");
        return CRYPTO_ERROR_WEAK_PASSWORD;
    }

    return CRYPTO_SUCCESS;
}

static FORCE_INLINE crypto_error_t safe_hex_encode_fast(const unsigned char *in, size_t in_len, char *out, size_t out_capacity) {
    if (UNLIKELY(!in || !out || in_len == 0)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    if (UNLIKELY(out_capacity < (in_len * 2 + 1))) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    size_t i = 0;
    for (; i + 3 < in_len; i += 4) {

        out[i * 2] = hex_chars[in[i] >> 4];
        out[i * 2 + 1] = hex_chars[in[i] & 0xF];
        out[(i + 1) * 2] = hex_chars[in[i + 1] >> 4];
        out[(i + 1) * 2 + 1] = hex_chars[in[i + 1] & 0xF];
        out[(i + 2) * 2] = hex_chars[in[i + 2] >> 4];
        out[(i + 2) * 2 + 1] = hex_chars[in[i + 2] & 0xF];
        out[(i + 3) * 2] = hex_chars[in[i + 3] >> 4];
        out[(i + 3) * 2 + 1] = hex_chars[in[i + 3] & 0xF];
    }

    for (; i < in_len; i++) {
        out[i * 2] = hex_chars[in[i] >> 4];
        out[i * 2 + 1] = hex_chars[in[i] & 0xF];
    }

    out[in_len * 2] = '\0';
    return CRYPTO_SUCCESS;
}

static FORCE_INLINE int is_valid_hex_char(char c) {
    return hex_values[(unsigned char)c] >= 0;
}

static FORCE_INLINE int is_valid_hex_string_fast(const char *hex, size_t len) {
    if (UNLIKELY(!hex || len == 0 || len % 2 != 0)) return 0;

    for (size_t i = 0; i < len; i++) {
        if (UNLIKELY(!is_valid_hex_char(hex[i]))) {
            return 0;
        }
    }
    return 1;
}

static FORCE_INLINE crypto_error_t safe_hex_decode_fast(const char *hex, unsigned char *out, size_t out_capacity, size_t *decoded_len) {
    if (UNLIKELY(!hex || !out || !decoded_len)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    const size_t hex_len = strlen(hex);

    if (UNLIKELY(!is_valid_hex_string_fast(hex, hex_len))) {
        return CRYPTO_ERROR_INVALID_HEX;
    }

    const size_t expected_len = hex_len / 2;

    if (UNLIKELY(expected_len > out_capacity)) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }

    for (size_t i = 0; i < expected_len; i++) {
        const signed char high = hex_values[(unsigned char)hex[2 * i]];
        const signed char low = hex_values[(unsigned char)hex[2 * i + 1]];
        out[i] = (unsigned char)((high << 4) | low);
    }

    *decoded_len = expected_len;
    return CRYPTO_SUCCESS;
}

static crypto_error_t derive_key_optimized(const char *password, const unsigned char *salt, unsigned char *key_out) {
    if (UNLIKELY(!password || !salt || !key_out)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    const size_t pw_len = strlen(password);
    if (UNLIKELY(pw_len == 0 || pw_len > MAX_PASSWORD_LENGTH)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    const int result = crypto_pwhash(
        key_out, KEY_SIZE,
        password, pw_len,
        salt,
        OPSLIMIT_PRODUCTION, MEMLIMIT_PRODUCTION,
        crypto_pwhash_ALG_ARGON2ID13
    );

    return (result == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_KEY_DERIVATION;
}

static FORCE_INLINE crypto_error_t validate_timestamp(uint64_t timestamp) {
    const uint64_t now = (uint64_t)time(NULL);

    if (UNLIKELY(timestamp > now + TIMESTAMP_TOLERANCE_FUTURE)) {
        secure_log("WARNING", "Timestamp too far in future");
        return CRYPTO_ERROR_TIMESTAMP_INVALID;
    }

    if (UNLIKELY(timestamp < now - TIMESTAMP_TOLERANCE_PAST)) {
        secure_log("WARNING", "Timestamp too old");
        return CRYPTO_ERROR_TIMESTAMP_INVALID;
    }

    return CRYPTO_SUCCESS;
}

static const char* get_error_message(crypto_error_t error) {
    switch (error) {
        case CRYPTO_SUCCESS: return "Success";
        case CRYPTO_ERROR_INIT: return "Cryptographic library initialization failed";
        case CRYPTO_ERROR_WEAK_PASSWORD: return "Password does not meet security requirements";
        case CRYPTO_ERROR_KEY_DERIVATION: return "Key derivation failed";
        case CRYPTO_ERROR_MESSAGE_TOO_LARGE: return "Message exceeds maximum size";
        case CRYPTO_ERROR_MEMORY_ALLOCATION: return "Memory allocation failed";
        case CRYPTO_ERROR_ENCRYPTION_FAILED: return "Encryption operation failed";
        case CRYPTO_ERROR_INVALID_INPUT: return "Invalid input parameters";
        case CRYPTO_ERROR_INVALID_VERSION: return "Unsupported format version";
        case CRYPTO_ERROR_TIMESTAMP_INVALID: return "Invalid or expired timestamp";
        case CRYPTO_ERROR_DECRYPTION_FAILED: return "Decryption failed - wrong password or corrupted data";
        case CRYPTO_ERROR_INVALID_HEX: return "Invalid hexadecimal format";
        case CRYPTO_ERROR_BUFFER_TOO_SMALL: return "Buffer too small for operation";
        case CRYPTO_ERROR_RATE_LIMITED: return "Rate limit exceeded - too many operations";
        default: return "Unknown error";
    }
}

crypto_error_t encrypt_message(const char *password, const char *message, char **hex_output) {
    if (UNLIKELY(!password || !message || !hex_output)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    *hex_output = NULL;

    crypto_error_t rate_result = check_rate_limit();
    if (UNLIKELY(rate_result != CRYPTO_SUCCESS)) {
        return rate_result;
    }

    if (UNLIKELY(sodium_init() < 0)) {
        secure_log("ERROR", "Failed to initialize cryptographic library");
        return CRYPTO_ERROR_INIT;
    }

    crypto_error_t pw_result = validate_password_strength_optimized(password);
    if (UNLIKELY(pw_result != CRYPTO_SUCCESS)) {
        return pw_result;
    }

    const size_t msg_len = strlen(message);
    if (UNLIKELY(msg_len > MAX_MSG_SIZE)) {
        secure_log("ERROR", "Message too large");
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    }

    unsigned char salt[SALT_SIZE] CACHE_ALIGN;
    unsigned char nonce[NONCE_SIZE] CACHE_ALIGN;
    const uint64_t timestamp = (uint64_t)time(NULL);

    randombytes_buf(salt, SALT_SIZE);
    randombytes_buf(nonce, NONCE_SIZE);

    unsigned char key[KEY_SIZE] CACHE_ALIGN;
    crypto_error_t key_result = derive_key_optimized(password, salt, key);
    if (UNLIKELY(key_result != CRYPTO_SUCCESS)) {
        secure_wipe(key, KEY_SIZE);
        return key_result;
    }

    secure_buffer_t output_buf;
    const size_t total_len = HEADER_SIZE + msg_len + MAC_SIZE;
    crypto_error_t buf_result = secure_buffer_init(&output_buf, total_len);
    if (UNLIKELY(buf_result != CRYPTO_SUCCESS)) {
        secure_wipe(key, KEY_SIZE);
        return buf_result;
    }

    size_t pos = 0;
    output_buf.data[pos++] = VERSION_BYTE;
    memcpy(output_buf.data + pos, salt, SALT_SIZE);
    pos += SALT_SIZE;
    memcpy(output_buf.data + pos, nonce, NONCE_SIZE);
    pos += NONCE_SIZE;
    memcpy(output_buf.data + pos, &timestamp, 8);
    pos += 8;

    unsigned long long ciphertext_len = 0;
    const int encrypt_result = crypto_aead_chacha20poly1305_ietf_encrypt(
        output_buf.data + HEADER_SIZE, &ciphertext_len,
        (const unsigned char*)message, msg_len,
        output_buf.data, HEADER_SIZE,  
        NULL,  
        nonce, key
    );

    secure_wipe(key, KEY_SIZE);

    if (UNLIKELY(encrypt_result != 0)) {
        secure_buffer_free(&output_buf);
        secure_log("ERROR", "Encryption failed");
        return CRYPTO_ERROR_ENCRYPTION_FAILED;
    }

    output_buf.size = HEADER_SIZE + ciphertext_len;

    const size_t hex_len = output_buf.size * 2 + 1;
    *hex_output = malloc(hex_len);
    if (UNLIKELY(!*hex_output)) {
        secure_buffer_free(&output_buf);
        return CRYPTO_ERROR_MEMORY_ALLOCATION;
    }

    crypto_error_t hex_result = safe_hex_encode_fast(output_buf.data, output_buf.size, *hex_output, hex_len);
    secure_buffer_free(&output_buf);

    if (UNLIKELY(hex_result != CRYPTO_SUCCESS)) {
        free(*hex_output);
        *hex_output = NULL;
        return hex_result;
    }

    return CRYPTO_SUCCESS;
}

crypto_error_t decrypt_message(const char *password, const char *hex_input, char **plaintext_output) {
    if (UNLIKELY(!password || !hex_input || !plaintext_output)) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    *plaintext_output = NULL;

    crypto_error_t rate_result = check_rate_limit();
    if (UNLIKELY(rate_result != CRYPTO_SUCCESS)) {
        return rate_result;
    }

    if (UNLIKELY(sodium_init() < 0)) {
        secure_log("ERROR", "Failed to initialize cryptographic library");
        return CRYPTO_ERROR_INIT;
    }

    secure_buffer_t input_buf;
    crypto_error_t buf_result = secure_buffer_init(&input_buf, MAX_MSG_SIZE + HEADER_SIZE + MAC_SIZE);
    if (UNLIKELY(buf_result != CRYPTO_SUCCESS)) {
        return buf_result;
    }

    size_t decoded_len;
    crypto_error_t decode_result = safe_hex_decode_fast(hex_input, input_buf.data, input_buf.capacity, &decoded_len);
    if (UNLIKELY(decode_result != CRYPTO_SUCCESS)) {
        secure_buffer_free(&input_buf);
        return decode_result;
    }

    input_buf.size = decoded_len;

    if (UNLIKELY(input_buf.size < HEADER_SIZE + MAC_SIZE)) {
        secure_buffer_free(&input_buf);
        secure_log("ERROR", "Input too short");
        return CRYPTO_ERROR_INVALID_INPUT;
    }

    size_t pos = 0;
    const unsigned char version = input_buf.data[pos++];
    if (UNLIKELY(version != VERSION_BYTE)) {
        secure_buffer_free(&input_buf);
        secure_log("ERROR", "Unsupported version");
        return CRYPTO_ERROR_INVALID_VERSION;
    }

    unsigned char salt[SALT_SIZE] CACHE_ALIGN;
    memcpy(salt, input_buf.data + pos, SALT_SIZE);
    pos += SALT_SIZE;

    unsigned char nonce[NONCE_SIZE] CACHE_ALIGN;
    memcpy(nonce, input_buf.data + pos, NONCE_SIZE);
    pos += NONCE_SIZE;

    uint64_t timestamp;
    memcpy(&timestamp, input_buf.data + pos, 8);
    pos += 8;

    crypto_error_t ts_result = validate_timestamp(timestamp);
    if (UNLIKELY(ts_result != CRYPTO_SUCCESS)) {
        secure_buffer_free(&input_buf);
        return ts_result;
    }

    unsigned char key[KEY_SIZE] CACHE_ALIGN;
    crypto_error_t key_result = derive_key_optimized(password, salt, key);
    if (UNLIKELY(key_result != CRYPTO_SUCCESS)) {
        secure_buffer_free(&input_buf);
        secure_wipe(key, KEY_SIZE);
        return key_result;
    }

    secure_buffer_t plaintext_buf;
    crypto_error_t pt_buf_result = secure_buffer_init(&plaintext_buf, MAX_MSG_SIZE);
    if (UNLIKELY(pt_buf_result != CRYPTO_SUCCESS)) {
        secure_buffer_free(&input_buf);
        secure_wipe(key, KEY_SIZE);
        return pt_buf_result;
    }

    const size_t ciphertext_len = input_buf.size - HEADER_SIZE;
    unsigned long long plaintext_len;

    const int decrypt_result = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext_buf.data, &plaintext_len,
        NULL,
        input_buf.data + HEADER_SIZE, ciphertext_len,
        input_buf.data, HEADER_SIZE,  
        nonce, key
    );

    secure_wipe(key, KEY_SIZE);
    secure_buffer_free(&input_buf);

    if (UNLIKELY(decrypt_result != 0)) {
        secure_buffer_free(&plaintext_buf);
        secure_log("ERROR", "Decryption failed");
        return CRYPTO_ERROR_DECRYPTION_FAILED;
    }

    *plaintext_output = malloc(plaintext_len + 1);
    if (UNLIKELY(!*plaintext_output)) {
        secure_buffer_free(&plaintext_buf);
        return CRYPTO_ERROR_MEMORY_ALLOCATION;
    }

    memcpy(*plaintext_output, plaintext_buf.data, plaintext_len);
    (*plaintext_output)[plaintext_len] = '\0';

    secure_buffer_free(&plaintext_buf);
    return CRYPTO_SUCCESS;
}

void generate_test_vector(void) {
    const char *test_password = "SecureTestPassword123!@#";
    const char *test_message = "This is a test message for cryptographic verification.";
    char *encrypted_hex = NULL;

    printf("=== Cryptographic Test Vector ===\n");
    printf("Password: %s\n", test_password);
    printf("Message: %s\n", test_message);

    crypto_error_t result = encrypt_message(test_password, test_message, &encrypted_hex);
    if (result == CRYPTO_SUCCESS && encrypted_hex) {
        printf("Encrypted (hex): %s\n", encrypted_hex);

        char *decrypted = NULL;
        crypto_error_t decrypt_result = decrypt_message(test_password, encrypted_hex, &decrypted);
        if (decrypt_result == CRYPTO_SUCCESS && decrypted) {
            printf("Decrypted: %s\n", decrypted);
            printf("Test: %s\n", strcmp(test_message, decrypted) == 0 ? "PASSED" : "FAILED");
            free(decrypted);
        } else {
            printf("Decryption failed: %s\n", get_error_message(decrypt_result));
        }

        free(encrypted_hex);
    } else {
        printf("Encryption failed: %s\n", get_error_message(result));
    }
    printf("================================\n");
}

void print_usage(const char *program_name) {
    printf("\nSecure Encryption Tool\n");
    printf("Usage:\n");
    printf("  %s -e -k <password> -m <message>    # Encrypt message\n", program_name);
    printf("  %s -d -k <password> -h <hex_data>   # Decrypt hex data\n", program_name);
    printf("  %s -t                               # Generate test vector\n", program_name);
    printf("  %s --help                           # Show this help\n", program_name);
    printf("\nSecurity Requirements:\n");
    printf("  - Password must be at least %d characters\n", MIN_PASSWORD_LENGTH);
    printf("  - Password should use multiple character classes\n");
    printf("  - Messages are limited to %d bytes\n", MAX_MSG_SIZE);
    printf("  - Encrypted data expires after %d days\n", TIMESTAMP_TOLERANCE_PAST / (24 * 3600));
    printf("\n");
}

typedef struct {
    char *password;
    char *message;
    char *hex_data;
    int encrypt_mode;
    int decrypt_mode;
    int test_mode;
    int help_mode;
} program_args_t;

static crypto_error_t parse_arguments(int argc, char *argv[], program_args_t *args) {
    memset(args, 0, sizeof(*args));

    if (argc < 2) {
        args->help_mode = 1;
        return CRYPTO_SUCCESS;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            args->encrypt_mode = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            args->decrypt_mode = 1;
        } else if (strcmp(argv[i], "-t") == 0) {
            args->test_mode = 1;
        } else if (strcmp(argv[i], "--xhelp") == 0 || strcmp(argv[i], "-xh") == 0) {
            args->help_mode = 1;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            args->password = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            args->message = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {  
            args->hex_data = argv[++i];
        } else {
            secure_log("ERROR", "Unknown argument");
            return CRYPTO_ERROR_INVALID_INPUT;
        }
    }

    return CRYPTO_SUCCESS;
}

int main(int argc, char *argv[]) {
    program_args_t args;
    crypto_error_t parse_result = parse_arguments(argc, argv, &args);

    if (parse_result != CRYPTO_SUCCESS || args.help_mode) {
        print_usage(argv[0]);
        return (parse_result == CRYPTO_SUCCESS) ? 0 : 1;
    }

    if (args.test_mode) {
        generate_test_vector();
        return 0;
    }

    if (args.encrypt_mode) {
        if (!args.password || !args.message) {
            fprintf(stderr, "Error: Encryption requires password (-k) and message (-m)\n");
            print_usage(argv[0]);
            return 1;
        }

        char *encrypted_hex = NULL;
        crypto_error_t result = encrypt_message(args.password, args.message, &encrypted_hex);

        if (result == CRYPTO_SUCCESS && encrypted_hex) {
            printf("%s\n", encrypted_hex);
            free(encrypted_hex);
            return 0;
        } else {
            fprintf(stderr, "Encryption failed: %s\n", get_error_message(result));
            return 1;
        }
    }

    if (args.decrypt_mode) {
        if (!args.password || !args.hex_data) {
            fprintf(stderr, "Error: Decryption requires password (-k) and hex data (-h)\n");
            print_usage(argv[0]);
            return 1;
        }

        char *decrypted_message = NULL;
        crypto_error_t result = decrypt_message(args.password, args.hex_data, &decrypted_message);

        if (result == CRYPTO_SUCCESS && decrypted_message) {
            printf("%s\n", decrypted_message);
            free(decrypted_message);
            return 0;
        } else {
            fprintf(stderr, "Decryption failed: %s\n", get_error_message(result));
            return 1;
        }
    }

    fprintf(stderr, "Error: Must specify operation mode (-e, -d, or -t)\n");
    print_usage(argv[0]);
    return 1;
}