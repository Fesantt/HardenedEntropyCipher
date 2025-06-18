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

// Security constants
#define NONCE_SIZE crypto_aead_chacha20poly1305_IETF_NPUBBYTES
#define KEY_SIZE crypto_aead_chacha20poly1305_IETF_KEYBYTES
#define MAC_SIZE crypto_aead_chacha20poly1305_IETF_ABYTES
#define SALT_SIZE crypto_pwhash_SALTBYTES
#define HEADER_SIZE (1 + SALT_SIZE + NONCE_SIZE + 8)
#define MAX_MSG_SIZE 65536
#define MAX_HEX_SIZE (MAX_MSG_SIZE + HEADER_SIZE + MAC_SIZE) * 2
#define MIN_PASSWORD_LENGTH 12
#define MAX_PASSWORD_LENGTH 1024
#define VERSION_BYTE 0x03
#define TIMESTAMP_TOLERANCE_FUTURE 300    // 5 minutes
#define TIMESTAMP_TOLERANCE_PAST (7 * 24 * 3600)  // 7 days (reduced from 30)
#define OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE

// Error codes with documentation
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
    CRYPTO_ERROR_BUFFER_TOO_SMALL = -12
} crypto_error_t;

// Secure buffer structure for memory management
typedef struct {
    unsigned char *data;
    size_t size;
    size_t capacity;
} secure_buffer_t;

// Function declarations
static void secure_log(const char *level, const char *msg);
static void secure_wipe(void *data, size_t len);
static crypto_error_t secure_buffer_init(secure_buffer_t *buf, size_t capacity);
static void secure_buffer_free(secure_buffer_t *buf);
static crypto_error_t validate_password_strength(const char *password);
static crypto_error_t safe_hex_encode(const unsigned char *in, size_t in_len, char *out, size_t out_capacity);
static crypto_error_t safe_hex_decode(const char *hex, unsigned char *out, size_t out_capacity, size_t *decoded_len);
static crypto_error_t derive_key_secure(const char *password, const unsigned char *salt, unsigned char *key_out);
static crypto_error_t validate_timestamp(uint64_t timestamp);
static int is_valid_hex_string(const char *hex);
static const char* get_error_message(crypto_error_t error);

// Secure logging with timestamp
static void secure_log(const char *level, const char *msg) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    
    if (tm_info && strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info) > 0) {
        fprintf(stderr, "[%s] %s: %s\n", timestamp, level, msg);
    } else {
        fprintf(stderr, "%s: %s\n", level, msg);
    }
    fflush(stderr);
}

// Secure memory wiping
static void secure_wipe(void *data, size_t len) {
    if (data && len > 0) {
        sodium_memzero(data, len);
    }
}

// Secure buffer management
static crypto_error_t secure_buffer_init(secure_buffer_t *buf, size_t capacity) {
    if (!buf || capacity == 0) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    buf->data = sodium_malloc(capacity);
    if (!buf->data) {
        secure_log("ERROR", "Failed to allocate secure memory");
        return CRYPTO_ERROR_MEMORY_ALLOCATION;
    }
    
    buf->size = 0;
    buf->capacity = capacity;
    return CRYPTO_SUCCESS;
}

static void secure_buffer_free(secure_buffer_t *buf) {
    if (buf && buf->data) {
        sodium_free(buf->data);
        buf->data = NULL;
        buf->size = 0;
        buf->capacity = 0;
    }
}

// Enhanced password strength validation
static crypto_error_t validate_password_strength(const char *password) {
    if (!password) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    size_t len = strlen(password);
    if (len < MIN_PASSWORD_LENGTH) {
        secure_log("WARNING", "Password too short");
        return CRYPTO_ERROR_WEAK_PASSWORD;
    }
    
    if (len > MAX_PASSWORD_LENGTH) {
        secure_log("ERROR", "Password too long");
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    // Character class analysis
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    int char_classes = 0;
    
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)password[i];
        
        // Check for control characters
        if (c < 32 || c == 127) {
            secure_log("ERROR", "Password contains invalid characters");
            return CRYPTO_ERROR_INVALID_INPUT;
        }
        
        if (c >= 'A' && c <= 'Z') has_upper = 1;
        else if (c >= 'a' && c <= 'z') has_lower = 1;
        else if (c >= '0' && c <= '9') has_digit = 1;
        else has_special = 1;
    }
    
    char_classes = has_upper + has_lower + has_digit + has_special;
    
    // Require at least 3 character classes for shorter passwords
    if (len < 16 && char_classes < 3) {
        secure_log("WARNING", "Password lacks complexity");
        return CRYPTO_ERROR_WEAK_PASSWORD;
    }
    
    // Calculate approximate entropy (conservative estimate)
    double charset_size = 0;
    if (has_lower) charset_size += 26;
    if (has_upper) charset_size += 26;
    if (has_digit) charset_size += 10;
    if (has_special) charset_size += 32; // Conservative estimate
    
    double entropy = log2(charset_size) * len;
    
    if (entropy < 60.0) {  // More reasonable entropy threshold
        secure_log("WARNING", "Password entropy may be insufficient");
        return CRYPTO_ERROR_WEAK_PASSWORD;
    }
    
    return CRYPTO_SUCCESS;
}

// Safe hex encoding with bounds checking
static crypto_error_t safe_hex_encode(const unsigned char *in, size_t in_len, char *out, size_t out_capacity) {
    if (!in || !out || in_len == 0) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    if (out_capacity < (in_len * 2 + 1)) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    
    for (size_t i = 0; i < in_len; i++) {
        int written = snprintf(out + i * 2, 3, "%02x", in[i]);
        if (written != 2) {
            return CRYPTO_ERROR_INVALID_INPUT;
        }
    }
    
    out[in_len * 2] = '\0';
    return CRYPTO_SUCCESS;
}

// Validate hex string format
static int is_valid_hex_string(const char *hex) {
    if (!hex) return 0;
    
    size_t len = strlen(hex);
    if (len == 0 || len % 2 != 0) return 0;
    
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)hex[i])) {
            return 0;
        }
    }
    return 1;
}

// Safe hex decoding with validation
static crypto_error_t safe_hex_decode(const char *hex, unsigned char *out, size_t out_capacity, size_t *decoded_len) {
    if (!hex || !out || !decoded_len) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    if (!is_valid_hex_string(hex)) {
        return CRYPTO_ERROR_INVALID_HEX;
    }
    
    size_t hex_len = strlen(hex);
    size_t expected_len = hex_len / 2;
    
    if (expected_len > out_capacity) {
        return CRYPTO_ERROR_BUFFER_TOO_SMALL;
    }
    
    for (size_t i = 0; i < expected_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex + 2 * i, "%2x", &byte_val) != 1) {
            return CRYPTO_ERROR_INVALID_HEX;
        }   
        out[i] = (unsigned char)byte_val;
    }
    
    *decoded_len = expected_len;
    return CRYPTO_SUCCESS;
}

// Secure key derivation
static crypto_error_t derive_key_secure(const char *password, const unsigned char *salt, unsigned char *key_out) {
    if (!password || !salt || !key_out) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    size_t pw_len = strlen(password);
    if (pw_len == 0 || pw_len > MAX_PASSWORD_LENGTH) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    int result = crypto_pwhash(
        key_out, KEY_SIZE,
        password, pw_len,
        salt,
        OPSLIMIT, MEMLIMIT,
        crypto_pwhash_ALG_ARGON2ID13
    );
    
    return (result == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_KEY_DERIVATION;
}

// Validate timestamp with reasonable bounds
static crypto_error_t validate_timestamp(uint64_t timestamp) {
    uint64_t now = (uint64_t)time(NULL);
    
    // Check for future timestamps (allow small clock skew)
    if (timestamp > now + TIMESTAMP_TOLERANCE_FUTURE) {
        secure_log("WARNING", "Timestamp too far in future");
        return CRYPTO_ERROR_TIMESTAMP_INVALID;
    }
    
    // Check for old timestamps
    if (timestamp < now - TIMESTAMP_TOLERANCE_PAST) {
        secure_log("WARNING", "Timestamp too old");
        return CRYPTO_ERROR_TIMESTAMP_INVALID;
    }
    
    return CRYPTO_SUCCESS;
}

// Get human-readable error message
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
        default: return "Unknown error";
    }
}

// Main encryption function
crypto_error_t encrypt_message(const char *password, const char *message, char **hex_output) {
    if (!password || !message || !hex_output) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    *hex_output = NULL;
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        secure_log("ERROR", "Failed to initialize cryptographic library");
        return CRYPTO_ERROR_INIT;
    }
    
    // Validate password strength
    crypto_error_t pw_result = validate_password_strength(password);
    if (pw_result != CRYPTO_SUCCESS) {
        return pw_result;
    }
    
    // Check message size
    size_t msg_len = strlen(message);
    if (msg_len > MAX_MSG_SIZE) {
        secure_log("ERROR", "Message too large");
        return CRYPTO_ERROR_MESSAGE_TOO_LARGE;
    }
    
    // Generate cryptographic material
    unsigned char salt[SALT_SIZE];
    unsigned char nonce[NONCE_SIZE];
    uint64_t timestamp = (uint64_t)time(NULL);
    
    randombytes_buf(salt, SALT_SIZE);
    randombytes_buf(nonce, NONCE_SIZE);
    
    // Derive encryption key
    unsigned char key[KEY_SIZE];
    crypto_error_t key_result = derive_key_secure(password, salt, key);
    if (key_result != CRYPTO_SUCCESS) {
        secure_wipe(key, KEY_SIZE);
        return key_result;
    }
    
    // Allocate output buffer
    secure_buffer_t output_buf;
    size_t total_len = HEADER_SIZE + msg_len + MAC_SIZE;
    crypto_error_t buf_result = secure_buffer_init(&output_buf, total_len);
    if (buf_result != CRYPTO_SUCCESS) {
        secure_wipe(key, KEY_SIZE);
        return buf_result;
    }
    
    // Build header
    size_t pos = 0;
    output_buf.data[pos++] = VERSION_BYTE;
    memcpy(output_buf.data + pos, salt, SALT_SIZE);
    pos += SALT_SIZE;
    memcpy(output_buf.data + pos, nonce, NONCE_SIZE);
    pos += NONCE_SIZE;
    memcpy(output_buf.data + pos, &timestamp, 8);
    pos += 8;
    
    // Encrypt message
    unsigned long long ciphertext_len = 0;
    int encrypt_result = crypto_aead_chacha20poly1305_ietf_encrypt(
        output_buf.data + HEADER_SIZE, &ciphertext_len,
        (const unsigned char*)message, msg_len,
        output_buf.data, HEADER_SIZE,  // Additional data (header)
        NULL,  // No secret nonce
        nonce, key
    );
    
    secure_wipe(key, KEY_SIZE);
    
    if (encrypt_result != 0) {
        secure_buffer_free(&output_buf);
        secure_log("ERROR", "Encryption failed");
        return CRYPTO_ERROR_ENCRYPTION_FAILED;
    }
    
    output_buf.size = HEADER_SIZE + ciphertext_len;
    
    // Convert to hex
    size_t hex_len = output_buf.size * 2 + 1;
    *hex_output = malloc(hex_len);
    if (!*hex_output) {
        secure_buffer_free(&output_buf);
        return CRYPTO_ERROR_MEMORY_ALLOCATION;
    }
    
    crypto_error_t hex_result = safe_hex_encode(output_buf.data, output_buf.size, *hex_output, hex_len);
    secure_buffer_free(&output_buf);
    
    if (hex_result != CRYPTO_SUCCESS) {
        free(*hex_output);
        *hex_output = NULL;
        return hex_result;
    }
    
    secure_log("INFO", "Message encrypted successfully");
    return CRYPTO_SUCCESS;
}

// Main decryption function
crypto_error_t decrypt_message(const char *password, const char *hex_input, char **plaintext_output) {
    if (!password || !hex_input || !plaintext_output) {
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    *plaintext_output = NULL;
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        secure_log("ERROR", "Failed to initialize cryptographic library");
        return CRYPTO_ERROR_INIT;
    }
    
    // Decode hex input
    secure_buffer_t input_buf;
    crypto_error_t buf_result = secure_buffer_init(&input_buf, MAX_MSG_SIZE + HEADER_SIZE + MAC_SIZE);
    if (buf_result != CRYPTO_SUCCESS) {
        return buf_result;
    }
    
    size_t decoded_len;
    crypto_error_t decode_result = safe_hex_decode(hex_input, input_buf.data, input_buf.capacity, &decoded_len);
    if (decode_result != CRYPTO_SUCCESS) {
        secure_buffer_free(&input_buf);
        return decode_result;
    }
    
    input_buf.size = decoded_len;
    
    // Validate minimum size
    if (input_buf.size < HEADER_SIZE + MAC_SIZE) {
        secure_buffer_free(&input_buf);
        secure_log("ERROR", "Input too short");
        return CRYPTO_ERROR_INVALID_INPUT;
    }
    
    // Parse header
    size_t pos = 0;
    unsigned char version = input_buf.data[pos++];
    if (version != VERSION_BYTE) {
        secure_buffer_free(&input_buf);
        secure_log("ERROR", "Unsupported version");
        return CRYPTO_ERROR_INVALID_VERSION;
    }
    
    unsigned char salt[SALT_SIZE];
    memcpy(salt, input_buf.data + pos, SALT_SIZE);
    pos += SALT_SIZE;
    
    unsigned char nonce[NONCE_SIZE];
    memcpy(nonce, input_buf.data + pos, NONCE_SIZE);
    pos += NONCE_SIZE;
    
    uint64_t timestamp;
    memcpy(&timestamp, input_buf.data + pos, 8);
    pos += 8;
    
    // Validate timestamp
    crypto_error_t ts_result = validate_timestamp(timestamp);
    if (ts_result != CRYPTO_SUCCESS) {
        secure_buffer_free(&input_buf);
        return ts_result;
    }
    
    // Derive decryption key
    unsigned char key[KEY_SIZE];
    crypto_error_t key_result = derive_key_secure(password, salt, key);
    if (key_result != CRYPTO_SUCCESS) {
        secure_buffer_free(&input_buf);
        secure_wipe(key, KEY_SIZE);
        return key_result;
    }
    
    // Decrypt message
    secure_buffer_t plaintext_buf;
    crypto_error_t pt_buf_result = secure_buffer_init(&plaintext_buf, MAX_MSG_SIZE);
    if (pt_buf_result != CRYPTO_SUCCESS) {
        secure_buffer_free(&input_buf);
        secure_wipe(key, KEY_SIZE);
        return pt_buf_result;
    }
    
    size_t ciphertext_len = input_buf.size - HEADER_SIZE;
    unsigned long long plaintext_len;
    
    int decrypt_result = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext_buf.data, &plaintext_len,
        NULL,
        input_buf.data + HEADER_SIZE, ciphertext_len,
        input_buf.data, HEADER_SIZE,  // Additional data (header)
        nonce, key
    );
    
    secure_wipe(key, KEY_SIZE);
    secure_buffer_free(&input_buf);
    
    if (decrypt_result != 0) {
        secure_buffer_free(&plaintext_buf);
        secure_log("ERROR", "Decryption failed");
        return CRYPTO_ERROR_DECRYPTION_FAILED;
    }
    
    // Allocate output string
    *plaintext_output = malloc(plaintext_len + 1);
    if (!*plaintext_output) {
        secure_buffer_free(&plaintext_buf);
        return CRYPTO_ERROR_MEMORY_ALLOCATION;
    }
    
    memcpy(*plaintext_output, plaintext_buf.data, plaintext_len);
    (*plaintext_output)[plaintext_len] = '\0';
    
    secure_buffer_free(&plaintext_buf);
    secure_log("INFO", "Message decrypted successfully");
    return CRYPTO_SUCCESS;
}

// Test vector generation for verification
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
        
        // Test decryption
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

// Usage information
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

// Enhanced argument parsing
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
        } else if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {  // Usando -x pra hex input
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