using System.Text;
using HardenedEntropyCipherCS;

// ---------------------------------------------------------------------------
// HardenedEntropyCipher V3 — C# Edition
// Non-deterministic reversible cipher with embedded entropy
//
// Usage:
//   v3cs -e  -k <password> -m <message>               # Encrypt text  → hex
//   v3cs -d  -k <password> -h <hex>                   # Decrypt text  ← hex
//   v3cs -ef -k <password> -i <input> -o <output>     # Encrypt file  → .hec
//   v3cs -df -k <password> -i <input> -o <output>     # Decrypt file  ← .hec
//   v3cs -t                                            # Self-test / test vector
//   v3cs --help                                        # This help
// ---------------------------------------------------------------------------

if (args.Length == 0 || args.Contains("--help") || args.Contains("-xh"))
{
    PrintHelp();
    return 0;
}

try
{
    return args[0] switch
    {
        "-e"  => RunEncryptText(args),
        "-d"  => RunDecryptText(args),
        "-ef" => RunEncryptFile(args),
        "-df" => RunDecryptFile(args),
        "-t"  => RunTestVector(),
        _     => UnknownMode(args[0])
    };
}
catch (CryptoException ex)
{
    Console.Error.WriteLine($"[ERROR] {ex.Error}: {ex.Message}");
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[ERROR] Unexpected error: {ex.Message}");
    return 1;
}

// ---------------------------------------------------------------------------
// Mode handlers
// ---------------------------------------------------------------------------

static int RunEncryptText(string[] args)
{
    string? password = GetArg(args, "-k");
    string? message  = GetArg(args, "-m");

    if (password is null || message is null)
    {
        Console.Error.WriteLine("Encrypt text requires: -k <password> -m <message>");
        return 1;
    }

    string hex = CipherEngine.EncryptText(password, message);
    Console.WriteLine(hex);
    return 0;
}

static int RunDecryptText(string[] args)
{
    string? password = GetArg(args, "-k");
    string? hex      = GetArg(args, "-h");

    if (password is null || hex is null)
    {
        Console.Error.WriteLine("Decrypt text requires: -k <password> -h <hex>");
        return 1;
    }

    string plaintext = CipherEngine.DecryptText(password, hex);
    Console.WriteLine(plaintext);
    return 0;
}

static int RunEncryptFile(string[] args)
{
    string? password = GetArg(args, "-k");
    string? input    = GetArg(args, "-i");
    string? output   = GetArg(args, "-o");

    if (password is null || input is null || output is null)
    {
        Console.Error.WriteLine("Encrypt file requires: -k <password> -i <input_path> -o <output_path>");
        return 1;
    }

    CipherEngine.EncryptFile(password, input, output);
    return 0;
}

static int RunDecryptFile(string[] args)
{
    string? password = GetArg(args, "-k");
    string? input    = GetArg(args, "-i");
    string? output   = GetArg(args, "-o");

    if (password is null || input is null || output is null)
    {
        Console.Error.WriteLine("Decrypt file requires: -k <password> -i <input_path> -o <output_path>");
        return 1;
    }

    CipherEngine.DecryptFile(password, input, output);
    return 0;
}

static int RunTestVector()
{
    const string TestPassword = "SecureTestPassword123!@#";
    const string TestMessage  = "This is a test message for cryptographic verification.";
    const string TestFile     = "test_input.tmp";
    const string TestFileCiph = "test_encrypted.hec";
    const string TestFileDecr = "test_decrypted.tmp";

    Console.WriteLine("=== Cryptographic Test Vector ===");
    Console.WriteLine($"Password : {TestPassword}");
    Console.WriteLine($"Message  : {TestMessage}");
    Console.WriteLine();

    // --- Text round-trip (twice, to prove non-determinism) ---
    Console.WriteLine("[TEXT ENCRYPTION]");
    string hex1 = CipherEngine.EncryptText(TestPassword, TestMessage);
    string hex2 = CipherEngine.EncryptText(TestPassword, TestMessage);

    Console.WriteLine($"Cipher 1 : {hex1}");
    Console.WriteLine($"Cipher 2 : {hex2}");
    Console.WriteLine($"Different: {(hex1 != hex2 ? "YES (non-deterministic)" : "NO — BUG!")}");

    string dec1 = CipherEngine.DecryptText(TestPassword, hex1);
    string dec2 = CipherEngine.DecryptText(TestPassword, hex2);
    bool   textOk = dec1 == TestMessage && dec2 == TestMessage;
    Console.WriteLine($"Decrypted: {dec1}");
    Console.WriteLine($"Text test: {(textOk ? "PASSED" : "FAILED")}");
    Console.WriteLine();

    // --- File round-trip ---
    Console.WriteLine("[FILE ENCRYPTION]");
    File.WriteAllText(TestFile, TestMessage + "\n(file mode test)\n", Encoding.UTF8);
    CipherEngine.EncryptFile(TestPassword, TestFile, TestFileCiph);
    CipherEngine.DecryptFile(TestPassword, TestFileCiph, TestFileDecr);

    string original  = File.ReadAllText(TestFile,     Encoding.UTF8);
    string recovered = File.ReadAllText(TestFileDecr, Encoding.UTF8);
    bool   fileOk    = original == recovered;
    Console.WriteLine($"File test: {(fileOk ? "PASSED" : "FAILED")}");
    if (!fileOk)
    {
        Console.WriteLine($"  Expected : {original}");
        Console.WriteLine($"  Got      : {recovered}");
    }

    // Cleanup
    File.Delete(TestFile);
    File.Delete(TestFileCiph);
    File.Delete(TestFileDecr);

    Console.WriteLine("=================================");
    return (textOk && fileOk) ? 0 : 1;
}

static int UnknownMode(string mode)
{
    Console.Error.WriteLine($"Unknown mode: {mode}");
    PrintHelp();
    return 1;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static string? GetArg(string[] args, string flag)
{
    for (int i = 0; i < args.Length - 1; i++)
        if (args[i] == flag)
            return args[i + 1];
    return null;
}

static void PrintHelp()
{
    Console.WriteLine("""

    HardenedEntropyCipher V3 — C# Edition
    Non-deterministic reversible cipher with embedded entropy.

    Usage:
      v3cs -e  -k <password> -m <message>             Encrypt text  (output: hex)
      v3cs -d  -k <password> -h <hex>                 Decrypt text  (input: hex)
      v3cs -ef -k <password> -i <input> -o <output>   Encrypt file  (output: .hec binary)
      v3cs -df -k <password> -i <input> -o <output>   Decrypt file  (input: .hec binary)
      v3cs -t                                          Run self-test / generate test vectors
      v3cs --help                                      Show this help

    Security profile:
      Cipher          ChaCha20-Poly1305 (IETF)
      KDF             Argon2id  (2 iterations, 64 MB, p=1)
      Salt            32 bytes random per operation  ← non-determinism
      Nonce           12 bytes random per operation  ← non-determinism
      Timestamp       8 bytes (anti-replay, 7-day window)
      Password min    12 chars, 60 bits entropy
      Text limit      65 536 bytes
      File chunks     65 536 bytes each, independent AEAD + anti-reorder AAD

    Examples:
      v3cs -e  -k "MyStr0ng!Pass#2025" -m "secret data"
      v3cs -d  -k "MyStr0ng!Pass#2025" -h 04a3f2...
      v3cs -ef -k "MyStr0ng!Pass#2025" -i secret.pdf  -o secret.pdf.hec
      v3cs -df -k "MyStr0ng!Pass#2025" -i secret.pdf.hec -o secret.pdf

    """);
}
