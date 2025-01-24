using Microsoft.AspNetCore.DataProtection;
using System.Text;

namespace ConcasDev.Security.Memory
{
    /// <summary>
    /// Provides methods to securely handle sensitive data in memory.
    /// <para>
    /// This class offers functionality to protect sensitive data by converting it into a cryptographically secured 
    /// <see cref="Secret"/> object and to retrieve the original data securely. It ensures proper memory cleanup 
    /// to minimize the risk of exposing unprotected sensitive data.
    /// </para>
    /// </summary>
    /// <remarks>
    /// The <see cref="MemoryProtection"/> class is designed to handle sensitive data such as passwords or cryptographic keys. 
    /// It provides mechanisms to protect the data in memory and ensures secure cleanup of temporary buffers.
    /// Use the provided methods responsibly, ensuring any returned data is cleared from memory as soon as it is no longer needed.
    /// </remarks>
    public static class MemoryProtection
    {
        /// <summary>
        /// Secures sensitive data by converting it into a protected secret.
        /// </summary>
        /// <typeparam name="T">The type of the data (byte[] or char[]).</typeparam>
        /// <param name="data">The sensitive data to secure.</param>
        /// <returns>A <see cref="Secret"/> containing the secured data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the data is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the data is empty.</exception>
        /// <exception cref="NotSupportedException">Thrown when the type of data is not supported.</exception>
        public static Secret SecureData<T>(T data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null");
            }

            try
            {
                switch (data)
                {
                    case byte[] dataBytes:
                        {
                            if (dataBytes.Length == 0)
                            {
                                throw new ArgumentException("Data cannot be empty", nameof(data));
                            }

                            return new Secret(dataBytes);
                        }
                    case char[] dataChars:
                        {
                            if (dataChars.Length == 0)
                            {
                                throw new ArgumentException("Data cannot be empty", nameof(data));
                            }

                            var encoded = Encoding.UTF8.GetBytes(dataChars);

                            try
                            {
                                return new Secret(encoded);
                            }
                            finally
                            {
                                Array.Clear(encoded, 0, encoded.Length);
                            }
                        }
                    default:
                        throw new NotSupportedException($"The type '{typeof(T)}' is not supported");
                }
            }
            finally
            {
                switch (data)
                {
                    case byte[] dataBytes:
                        dataBytes.Clear();
                        break;
                    case char[] dataChars:
                        dataChars.Clear();
                        break;
                }
            }
        }

        /// <summary>
        /// Retrieves sensitive data from a protected secret.
        /// <para>It's important to call <see cref="Array.Clear"/> on the returned reference as soon as you have finished using it, to leave no traces of unprotected sensitive data in memory.</para>
        /// </summary>
        /// <typeparam name="T">The type of the data to retrieve (byte[] or char[]).</typeparam>
        /// <param name="secret">The secret containing the protected data.</param>
        /// <returns>The unprotected data.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the secret is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the secret is empty.</exception>
        /// <exception cref="NotSupportedException">Thrown when the requested type is not supported.</exception>
        public static T GetData<T>(Secret secret)
        {
            if (secret == null)
            {
                throw new ArgumentNullException(nameof(secret), "Secret cannot be null");
            }

            if (secret.Length == 0)
            {
                throw new ArgumentException("Secret cannot be empty", nameof(secret));
            }

            var buffer = new byte[secret.Length];
            secret.WriteSecretIntoBuffer(buffer);

            return typeof(T) switch
            {
                Type t when t == typeof(byte[]) => (T)(object)buffer,
                Type t when t == typeof(char[]) => (T)(object)Encoding.UTF8.GetChars(buffer),
                _ => throw new NotSupportedException($"The type '{typeof(T)}' is not supported"),
            };
        }

        /// <summary>
        /// Clears all elements in the byte array by setting them to the default value.
        /// </summary>
        /// <param name="data">The byte array to clear.</param>
        public static void Clear(this byte[] data)
        {
            if (data != null && data.Length > 0)
            {
                Array.Clear(data, 0, data.Length);
            }
        }

        /// <summary>
        /// Clears all elements in the char array by setting them to the default value.
        /// </summary>
        /// <param name="data">The char array to clear.</param>
        public static void Clear(this char[] data)
        {
            if (data != null && data.Length > 0)
            {
                Array.Clear(data, 0, data.Length);
            }
        }
    }
}