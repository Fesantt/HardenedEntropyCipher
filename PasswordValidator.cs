namespace HardenedEntropyCipherCS;

internal static class PasswordValidator
{
    private const int MinLength = 12;
    private const int MaxLength = 1024;
    private const double MinEntropy = 60.0;

    /// <summary>
    /// Validates password strength matching the original C implementation rules.
    /// Throws <see cref="CryptoException"/> if the password is too weak or invalid.
    /// </summary>
    public static void Validate(string password)
    {
        if (password is null)
            throw new CryptoException(CryptoError.WeakPassword, "Password cannot be null");

        if (password.Length < MinLength)
            throw new CryptoException(CryptoError.WeakPassword,
                $"Password must be at least {MinLength} characters");

        if (password.Length > MaxLength)
            throw new CryptoException(CryptoError.WeakPassword,
                $"Password exceeds maximum length of {MaxLength}");

        bool hasUpper = false, hasLower = false, hasDigit = false, hasSpecial = false;

        foreach (char c in password)
        {
            if (c < 32 || c == 127)
                throw new CryptoException(CryptoError.WeakPassword,
                    "Password contains invalid control characters");

            if (char.IsAsciiLetterUpper(c))      hasUpper   = true;
            else if (char.IsAsciiLetterLower(c)) hasLower   = true;
            else if (char.IsAsciiDigit(c))       hasDigit   = true;
            else                                  hasSpecial = true;
        }

        int classes = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0)
                    + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

        if (password.Length < 16 && classes < 3)
            throw new CryptoException(CryptoError.WeakPassword,
                "Password lacks complexity: needs at least 3 character classes or 16+ characters");

        double charsetSize = (hasLower   ? 26 : 0)
                           + (hasUpper   ? 26 : 0)
                           + (hasDigit   ? 10 : 0)
                           + (hasSpecial ? 32 : 0);

        double entropy = Math.Log2(charsetSize) * password.Length;

        if (entropy < MinEntropy)
            throw new CryptoException(CryptoError.WeakPassword,
                $"Password entropy too low ({entropy:F1} bits, minimum is {MinEntropy:F0} bits)");
    }
}
