using System;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Radius.Core
{
    public static class RadiusPassword
    {
        /// <summary>
        /// Encrypt/decrypt using XOR
        /// </summary>
        private static void EncryptDecrypt(ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, Span<byte> destination)
        {
            for (var i = 0; i < input.Length; i++)
            {
                destination[i] = (byte)(input[i] ^ key[i]);
            }
        }


        /// <summary>
        /// Create a radius shared secret key
        /// </summary>
        private static byte[] CreateKey(byte[] sharedSecret, ReadOnlySpan<byte> authenticator)
        {
            var hashInput = new byte[sharedSecret.Length + authenticator.Length];
            Buffer.BlockCopy(sharedSecret, 0, hashInput, 0, sharedSecret.Length);
            authenticator.CopyTo(hashInput.AsSpan(sharedSecret.Length));

            using var md5 = MD5.Create();
            return md5.ComputeHash(hashInput);
        }


        /// <summary>
        /// Decrypt user password
        /// </summary>
        public static string Decrypt(byte[] sharedSecret, byte[] authenticator, byte[] passwordBytes) =>
            Decrypt(sharedSecret, authenticator, (ReadOnlySpan<byte>)passwordBytes);


        /// <summary>
        /// Decrypt user password
        /// </summary>
        public static string Decrypt(byte[] sharedSecret, byte[] authenticator, ReadOnlySpan<byte> passwordBytes)
        {
            var decryptedBytes = new byte[passwordBytes.Length];
            var key = CreateKey(sharedSecret, authenticator);

            for (var offset = 0; offset < passwordBytes.Length; offset += 16)
            {
                var chunk = passwordBytes.Slice(offset, 16);
                EncryptDecrypt(chunk, key, decryptedBytes.AsSpan(offset, 16));
                key = CreateKey(sharedSecret, chunk);
            }

            return Encoding.UTF8.GetString(decryptedBytes).TrimEnd('\0');
        }


        /// <summary>
        /// Encrypt a password
        /// </summary>
        public static byte[] Encrypt(byte[] sharedSecret, byte[] authenticator, byte[] passwordBytes)
        {
            var paddedPasswordBytes = new byte[GetEncryptedLength(passwordBytes.Length)];
            Buffer.BlockCopy(passwordBytes, 0, paddedPasswordBytes, 0, passwordBytes.Length);

            var key = CreateKey(sharedSecret, authenticator);
            var encryptedBytes = new byte[paddedPasswordBytes.Length];

            for (var offset = 0; offset < paddedPasswordBytes.Length; offset += 16)
            {
                var encryptedChunk = encryptedBytes.AsSpan(offset, 16);
                EncryptDecrypt(paddedPasswordBytes.AsSpan(offset, 16), key, encryptedChunk);
                key = CreateKey(sharedSecret, encryptedChunk);
            }

            return encryptedBytes;
        }


        internal static int GetEncryptedLength(int passwordLength) =>
            passwordLength + (16 - passwordLength % 16);
    }
}
