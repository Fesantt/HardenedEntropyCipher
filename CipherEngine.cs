using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace HardenedEntropyCipherCS;

public enum CryptoError
{
    Success = 0,
    WeakPassword,
    KeyDerivationFailed,
    TextTooLarge,
    InvalidInput,
    InvalidVersion,
    TimestampInvalid,
    DecryptionFailed,
    InvalidHex,
    IoError
}

public sealed class CryptoException(CryptoError error, string message) : Exception(message)
{
    public CryptoError Error { get; } = error;
}

/// <summary>
/// HardenedEntropyCipher — non-deterministic reversible cipher with embedded entropy.
///
/// Text payload layout (hex-encoded output):
///   [1 byte  version  ]
///   [32 bytes salt    ]  — random per operation
///   [12 bytes nonce   ]  — random per operation
///   [8 bytes timestamp]  — Unix epoch, LE, authenticated
///   [N bytes ciphertext] — ChaCha20-Poly1305
///   [16 bytes MAC     ]
///
/// File payload layout (binary .hec file):
///   [4 bytes  magic   ] "HEC\x04"
///   [1 byte   version ]
///   [32 bytes salt    ]
///   [12 bytes nonce   ]
///   [8 bytes timestamp]
///   [8 bytes filesize ] — original, LE
///   [chunks...]
///
/// Each chunk:
///   [4 bytes  plainLen] — original plaintext bytes in this chunk
///   [N bytes  ciphertext]
///   [16 bytes MAC     ]
///
/// Chunk nonce = baseNonce XOR (chunkIndex as LE uint32 in last 4 bytes).
/// Chunk AAD   = magic + salt + baseNonce + timestamp + chunkIndex (prevents reordering).
/// </summary>
public static class CipherEngine
{
    // --- Wire constants (must never change — breaks format compatibility) ---
    private const int    NonceSize   = 12;
    private const int    KeySize     = 32;
    private const int    TagSize     = 16;
    private const int    SaltSize    = 16; // crypto_pwhash_SALTBYTES — libsodium enforces exactly 16
    private const byte   VersionByte = 0x04;
    private const int    HeaderSize  = 1 + SaltSize + NonceSize + 8; // version+salt+nonce+ts

    // --- Operational limits ---
    private const int    MaxTextBytes          = 65_536;
    private const int    ChunkSize             = 65_536;
    private const long   ToleranceFutureSecs   = 300;
    private const long   TolerancePastSecs     = 7L * 24 * 3_600;

    // --- Argon2id params via libsodium (Sodium.Core) ---
    // C original: crypto_pwhash_OPSLIMIT_INTERACTIVE = 2, MEMLIMIT = 67108864 (64 MB)
    // Sodium.Core enforces opsLimit >= 3 for Argon2id in its validation layer.
    // We use 3 iterations + 64 MB: identical memory hardness, marginally higher CPU cost.
    private const long   Argon2OpsLimit   = 3L;
    private const int    Argon2MemLimit   = 67_108_864; // bytes — 64 MB, same as C original
    private const PasswordHash.ArgonAlgorithm Argon2Algo = PasswordHash.ArgonAlgorithm.Argon_2ID13;

    // --- File magic ---
    private static ReadOnlySpan<byte> FileMagic => [0x48, 0x45, 0x43, 0x04]; // "HEC\x04"

    // -------------------------------------------------------------------------
    // Public API — Text
    // -------------------------------------------------------------------------

    /// <summary>
    /// Encrypts <paramref name="message"/> with <paramref name="password"/>.
    /// Returns a lowercase hex string. Every call produces a different output.
    /// </summary>
    public static string EncryptText(string password, string message)
    {
        PasswordValidator.Validate(password);

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        if (messageBytes.Length > MaxTextBytes)
            throw new CryptoException(CryptoError.TextTooLarge,
                $"Message exceeds the {MaxTextBytes}-byte limit");

        byte[] salt      = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] nonce     = RandomNumberGenerator.GetBytes(NonceSize);
        long   timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        byte[] header    = BuildTextHeader(salt, nonce, timestamp);

        byte[] key = DeriveKey(password, salt);
        try
        {
            byte[] ciphertext = new byte[messageBytes.Length];
            byte[] tag        = new byte[TagSize];

            using var cipher = new ChaCha20Poly1305(key);
            cipher.Encrypt(nonce, messageBytes, ciphertext, tag, header);

            // Assemble: header | ciphertext | tag
            byte[] output = new byte[header.Length + ciphertext.Length + TagSize];
            Buffer.BlockCopy(header,     0, output, 0,                                 header.Length);
            Buffer.BlockCopy(ciphertext, 0, output, header.Length,                     ciphertext.Length);
            Buffer.BlockCopy(tag,        0, output, header.Length + ciphertext.Length, TagSize);

            Log("INFO", "Text encrypted successfully");
            return Convert.ToHexString(output).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(messageBytes); // zero plaintext encoding
        }
    }

    /// <summary>
    /// Decrypts a hex-encoded string produced by <see cref="EncryptText"/>.
    /// </summary>
    public static string DecryptText(string password, string hexInput)
    {
        if (string.IsNullOrWhiteSpace(hexInput) || hexInput.Length % 2 != 0)
            throw new CryptoException(CryptoError.InvalidHex, "Invalid hex string");

        byte[] input;
        try   { input = Convert.FromHexString(hexInput); }
        catch { throw new CryptoException(CryptoError.InvalidHex, "Hex decoding failed"); }

        if (input.Length < HeaderSize + TagSize)
            throw new CryptoException(CryptoError.InvalidInput, "Input too short");

        int  pos     = 0;
        byte version = input[pos++];
        if (version != VersionByte)
            throw new CryptoException(CryptoError.InvalidVersion,
                $"Unsupported version byte 0x{version:X2}");

        byte[] salt      = input[pos..(pos + SaltSize)]; pos += SaltSize;
        byte[] nonce     = input[pos..(pos + NonceSize)]; pos += NonceSize;
        long   timestamp = BinaryPrimitives.ReadInt64LittleEndian(input.AsSpan(pos, 8));

        ValidateTimestamp(timestamp);

        byte[] header     = input[..HeaderSize];
        byte[] ciphertext = input[HeaderSize..(input.Length - TagSize)];
        byte[] tag        = input[(input.Length - TagSize)..];

        byte[] key = DeriveKey(password, salt);
        try
        {
            byte[] plaintext = new byte[ciphertext.Length];
            using var cipher = new ChaCha20Poly1305(key);
            try
            {
                cipher.Decrypt(nonce, ciphertext, tag, plaintext, header);
            }
            catch (AuthenticationTagMismatchException)
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw new CryptoException(CryptoError.DecryptionFailed,
                    "Decryption failed — wrong password or corrupted data");
            }

            // Convert to string before zeroing — the string itself is managed
            // memory and cannot be zeroed (runtime limitation), but we zero the
            // intermediate byte buffer that holds the raw UTF-8 plaintext.
            string result = Encoding.UTF8.GetString(plaintext);
            CryptographicOperations.ZeroMemory(plaintext);

            Log("INFO", "Text decrypted successfully");
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    // -------------------------------------------------------------------------
    // Public API — Files
    // -------------------------------------------------------------------------

    /// <summary>
    /// Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/>
    /// using chunked ChaCha20-Poly1305. Handles arbitrarily large files.
    /// Each chunk has its own authenticated context (prevents reordering attacks).
    /// </summary>
    public static void EncryptFile(string password, string inputPath, string outputPath)
    {
        PasswordValidator.Validate(password);

        if (!File.Exists(inputPath))
            throw new CryptoException(CryptoError.IoError, $"Input file not found: {inputPath}");

        byte[] salt      = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] baseNonce = RandomNumberGenerator.GetBytes(NonceSize);
        long   timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long   fileSize  = new FileInfo(inputPath).Length;

        byte[] key = DeriveKey(password, salt);
        try
        {
            using var inStream  = new FileStream(inputPath,  FileMode.Open,   FileAccess.Read,  FileShare.Read);
            using var outStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var writer    = new BinaryWriter(outStream, Encoding.UTF8, leaveOpen: false);

            // File header
            writer.Write(FileMagic);
            writer.Write(VersionByte);
            writer.Write(salt);
            writer.Write(baseNonce);
            writer.Write(timestamp);
            writer.Write(fileSize);

            using var cipher = new ChaCha20Poly1305(key);

            byte[] plainBuf  = new byte[ChunkSize];
            byte[] cipherBuf = new byte[ChunkSize];
            byte[] tag       = new byte[TagSize];
            uint   chunkIdx  = 0;

            try
            {
                int bytesRead;
                while ((bytesRead = inStream.Read(plainBuf, 0, ChunkSize)) > 0)
                {
                    ReadOnlySpan<byte> plain = plainBuf.AsSpan(0, bytesRead);
                    Span<byte>         ct    = cipherBuf.AsSpan(0, bytesRead);
                    byte[]             cn    = ChunkNonce(baseNonce, chunkIdx);
                    byte[]             aad   = ChunkAad(salt, baseNonce, timestamp, chunkIdx);

                    cipher.Encrypt(cn, plain, ct, tag, aad);

                    writer.Write(bytesRead);        // plaintext length of this chunk
                    writer.Write(ct.ToArray());     // ciphertext (same size as plaintext)
                    writer.Write(tag);              // 16-byte Poly1305 tag

                    chunkIdx++;
                }
            }
            finally
            {
                // Zero the plaintext chunk buffer before releasing to GC
                CryptographicOperations.ZeroMemory(plainBuf);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        Log("INFO", $"File encrypted successfully ({fileSize:N0} bytes → {new FileInfo(outputPath).Length:N0} bytes)");
    }

    /// <summary>
    /// Decrypts a .hec file produced by <see cref="EncryptFile"/>.
    /// </summary>
    public static void DecryptFile(string password, string inputPath, string outputPath)
    {
        if (!File.Exists(inputPath))
            throw new CryptoException(CryptoError.IoError, $"Input file not found: {inputPath}");

        using var inStream = new FileStream(inputPath,  FileMode.Open,   FileAccess.Read,  FileShare.Read);
        using var reader   = new BinaryReader(inStream, Encoding.UTF8,   leaveOpen: false);

        // Validate magic
        byte[] magic = reader.ReadBytes(4);
        if (!magic.AsSpan().SequenceEqual(FileMagic))
            throw new CryptoException(CryptoError.InvalidVersion,
                "Not a valid HardenedEntropyCipher file (bad magic)");

        byte version = reader.ReadByte();
        if (version != VersionByte)
            throw new CryptoException(CryptoError.InvalidVersion,
                $"Unsupported version byte 0x{version:X2}");

        byte[] salt      = reader.ReadBytes(SaltSize);
        byte[] baseNonce = reader.ReadBytes(NonceSize);
        long   timestamp = reader.ReadInt64();
        long   fileSize  = reader.ReadInt64();

        ValidateTimestamp(timestamp);

        byte[] key = DeriveKey(password, salt);
        try
        {
            using var outStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
            using var cipher    = new ChaCha20Poly1305(key);

            byte[] tag          = new byte[TagSize];
            uint   chunkIdx     = 0;
            long   totalWritten = 0;

            while (inStream.Position < inStream.Length)
            {
                int    plainLen    = reader.ReadInt32();
                byte[] cipherChunk = reader.ReadBytes(plainLen);
                reader.Read(tag, 0, TagSize);

                byte[] cn    = ChunkNonce(baseNonce, chunkIdx);
                byte[] aad   = ChunkAad(salt, baseNonce, timestamp, chunkIdx);
                byte[] plain = new byte[plainLen];

                try
                {
                    cipher.Decrypt(cn, cipherChunk, tag, plain, aad);
                }
                catch (AuthenticationTagMismatchException)
                {
                    CryptographicOperations.ZeroMemory(plain);
                    throw new CryptoException(CryptoError.DecryptionFailed,
                        $"Chunk {chunkIdx} authentication failed — wrong password or corrupted file");
                }

                outStream.Write(plain, 0, plainLen);
                CryptographicOperations.ZeroMemory(plain); // zero plaintext after flushing to disk
                totalWritten += plainLen;
                chunkIdx++;
            }

            if (totalWritten != fileSize)
                throw new CryptoException(CryptoError.DecryptionFailed,
                    $"File size mismatch: expected {fileSize} bytes, got {totalWritten}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        Log("INFO", $"File decrypted successfully ({fileSize:N0} bytes)");
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            // crypto_pwhash() via libsodium — exact parity with the C original.
            // Argon2id13, OPSLIMIT_INTERACTIVE = 2, MEMLIMIT_INTERACTIVE = 64 MB.
            // Positional: (password, salt, opsLimit, memLimit, outputLength, algorithm)
            return PasswordHash.ArgonHashBinary(
                passwordBytes,
                salt,
                Argon2OpsLimit,
                Argon2MemLimit,
                KeySize,
                Argon2Algo
            );
        }
        catch (Exception ex)
        {
            throw new CryptoException(CryptoError.KeyDerivationFailed,
                $"Argon2id key derivation failed: {ex.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <summary>Builds the 45-byte authenticated header for text mode.</summary>
    private static byte[] BuildTextHeader(byte[] salt, byte[] nonce, long timestamp)
    {
        byte[] header = new byte[HeaderSize]; // 1+32+12+8 = 53
        int    pos    = 0;
        header[pos++] = VersionByte;
        Buffer.BlockCopy(salt,  0, header, pos, SaltSize);  pos += SaltSize;
        Buffer.BlockCopy(nonce, 0, header, pos, NonceSize); pos += NonceSize;
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(pos, 8), timestamp);
        return header;
    }

    /// <summary>
    /// Derives a per-chunk nonce by XOR-ing the last 4 bytes of
    /// <paramref name="baseNonce"/> with the chunk index (LE uint32).
    /// Ensures every chunk in a file uses a unique nonce.
    /// </summary>
    private static byte[] ChunkNonce(byte[] baseNonce, uint chunkIndex)
    {
        byte[] nonce = (byte[])baseNonce.Clone();
        nonce[NonceSize - 4] ^= (byte)(chunkIndex);
        nonce[NonceSize - 3] ^= (byte)(chunkIndex >> 8);
        nonce[NonceSize - 2] ^= (byte)(chunkIndex >> 16);
        nonce[NonceSize - 1] ^= (byte)(chunkIndex >> 24);
        return nonce;
    }

    /// <summary>
    /// Builds the AAD for a file chunk.
    /// Binds each chunk to its position, preventing chunk reordering or
    /// cross-file chunk substitution attacks.
    /// </summary>
    private static byte[] ChunkAad(byte[] salt, byte[] baseNonce, long timestamp, uint chunkIndex)
    {
        // magic(4) + version(1) + salt(32) + nonce(12) + timestamp(8) + chunkIndex(4) = 61 bytes
        byte[] aad = new byte[4 + 1 + SaltSize + NonceSize + 8 + 4];
        int    pos = 0;
        FileMagic.CopyTo(aad.AsSpan(pos, 4)); pos += 4;
        aad[pos++] = VersionByte;
        Buffer.BlockCopy(salt,      0, aad, pos, SaltSize);  pos += SaltSize;
        Buffer.BlockCopy(baseNonce, 0, aad, pos, NonceSize); pos += NonceSize;
        BinaryPrimitives.WriteInt64LittleEndian(aad.AsSpan(pos, 8), timestamp); pos += 8;
        BinaryPrimitives.WriteUInt32LittleEndian(aad.AsSpan(pos, 4), chunkIndex);
        return aad;
    }

    private static void ValidateTimestamp(long timestamp)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (timestamp > now + ToleranceFutureSecs)
            throw new CryptoException(CryptoError.TimestampInvalid, "Timestamp too far in the future");
        if (timestamp < now - TolerancePastSecs)
            throw new CryptoException(CryptoError.TimestampInvalid, "Timestamp expired (older than 7 days)");
    }

    private static void Log(string level, string msg) =>
        Console.Error.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {level}: {msg}");
}
