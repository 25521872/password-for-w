using System;
using System.Security.Cryptography;

namespace password_for_w
{
    public static class MatKhau
    {
        public static (string HashBase64, string SaltBase64) TaoHashMatKhau(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            byte[] hash = pbkdf2.GetBytes(32);

            return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
        }

        public static bool XacThucMatKhau(string password, string hashBase64, string saltBase64)
        {
            byte[] salt = Convert.FromBase64String(saltBase64);
            byte[] storedHash = Convert.FromBase64String(hashBase64);

            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            byte[] computedHash = pbkdf2.GetBytes(32);

            return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
        }
    }
}
