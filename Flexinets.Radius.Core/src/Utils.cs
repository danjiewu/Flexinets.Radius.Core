using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace Flexinets.Radius.Core
{
    public static class Utils
    {
        private static readonly byte[] AuthenticatorZeros = new byte[16];


        /// <summary>
        /// Convert a string of hex encoded bytes to a byte array
        /// </summary>
        public static byte[] StringToByteArray(string hex)
        {
            var numberChars = hex.Length;
            var bytes = new byte[numberChars / 2];
            for (var i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return bytes;
        }


        /// <summary>
        /// Convert a byte array to a string of hex encoded bytes
        /// </summary>
        public static string ToHexString(this ReadOnlySpan<byte> bytes) =>
            BitConverter.ToString(bytes.ToArray()).ToLowerInvariant().Replace("-", "");

        public static string ToHexString(this ReadOnlyMemory<byte> bytes) =>
            BitConverter.ToString(bytes.ToArray()).ToLowerInvariant().Replace("-", "");

        /// <summary>
        /// Get the mccmnc as a string from a 3GPP-User-Location-Info vendor attribute.
        /// </summary>
        public static (LocationType locationType, string? mccmnc) GetMccMncFrom3GPPLocationInfo(byte[] bytes)
        {
            string? mccmnc = null;
            var type = (LocationType)bytes[0];

            if (type == LocationType.CGI
                || type == LocationType.ECGI
                || type == LocationType.RAI
                || type == LocationType.SAI
                || type == LocationType.TAI
                || type == LocationType.TAIAndECGI)
            {
                var mccDigit1 = (bytes[1] & 15).ToString();
                var mccDigit2 = ((bytes[1] & 240) >> 4).ToString();
                var mccDigit3 = (bytes[2] & 15).ToString();

                var mncDigit1 = (bytes[3] & 15).ToString();
                var mncDigit2 = ((bytes[3] >> 4)).ToString();
                var mncDigit3 = (bytes[2] >> 4).ToString();

                mccmnc = mccDigit1 + mccDigit2 + mccDigit3 + mncDigit1 + mncDigit2;
                if (mncDigit3 != "15")
                {
                    mccmnc = mccmnc + mncDigit3;
                }
            }

            return (type, mccmnc);
        }


        /// <summary>
        /// Get message authenticator for a response
        /// Message-Authenticator = HMAC-MD5 (Type, Identifier, Length, Request Authenticator, Attributes)
        /// The HMAC-MD5 function takes in two arguments:
        /// The payload of the packet, which includes the 16 byte Message-Authenticator field filled with zeros
        /// The shared secret
        /// https://www.ietf.org/rfc/rfc2869.txt
        /// </summary>
        /// <param name="packetBytes">Packet bytes with the message authenticator set to zeros</param>
        /// <param name="sharedSecret">Shared secret</param>
        /// <param name="requestAuthenticator">Request authenticator from corresponding request packet</param>
        /// <param name="messageAuthenticatorPosition">Position of the message authenticator attribute in the packet bytes</param>
        public static byte[] CalculateResponseMessageAuthenticator(
            ReadOnlySpan<byte> packetBytes,
            byte[] sharedSecret,
            byte[] requestAuthenticator,
            int messageAuthenticatorPosition) =>
            CalculateMessageAuthenticator(
                packetBytes,
                sharedSecret,
                requestAuthenticator,
                messageAuthenticatorPosition);


        /// <summary>
        /// Create a message authenticator for a request
        /// Message-Authenticator = HMAC-MD5 (Type, Identifier, Length, Request Authenticator, Attributes)
        /// The HMAC-MD5 function takes in two arguments:
        /// The payload of the packet, which includes the 16 byte Message-Authenticator field filled with zeros
        /// The shared secret
        /// https://www.ietf.org/rfc/rfc2869.txt
        /// </summary>
        /// <param name="packetBytes">Packet bytes with the message authenticator set to zeros</param>
        /// <param name="sharedSecret">Shared secret</param>
        /// <param name="messageAuthenticatorPosition">Position of the message authenticator attribute in the packet bytes</param>
        public static byte[] CalculateRequestMessageAuthenticator(
            ReadOnlySpan<byte> packetBytes,
            byte[] sharedSecret,
            int messageAuthenticatorPosition) =>
            CalculateMessageAuthenticator(packetBytes, sharedSecret, null, messageAuthenticatorPosition);


        private static byte[] CalculateMessageAuthenticator(
            ReadOnlySpan<byte> packetBytes,
            byte[] sharedSecret,
            byte[]? requestAuthenticator,
            int messageAuthenticatorPosition)
        {
            var temp = ArrayPool<byte>.Shared.Rent(packetBytes.Length);
            try
            {
                var tempSpan = temp.AsSpan(0, packetBytes.Length);
                packetBytes.CopyTo(tempSpan);
                AuthenticatorZeros.CopyTo(tempSpan[(messageAuthenticatorPosition + 2)..]);
                requestAuthenticator?.CopyTo(temp, 4);

                using var md5 = new HMACMD5(sharedSecret);
                return md5.ComputeHash(temp, 0, packetBytes.Length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(temp, clearArray: true);
            }
        }


        /// <summary>
        /// Creates a response authenticator
        /// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        /// Actually this means it is the response packet with the request authenticator and secret...
        /// </summary>
        /// <returns>Response authenticator for the packet</returns>
        public static byte[] CalculateResponseAuthenticator(
            byte[] sharedSecret,
            byte[] requestAuthenticator,
            ReadOnlySpan<byte> packetBytes)
        {
            var length = packetBytes.Length + sharedSecret.Length;
            var bytes = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                var bytesSpan = bytes.AsSpan(0, length);
                packetBytes.CopyTo(bytesSpan);
                sharedSecret.CopyTo(bytesSpan[packetBytes.Length..]);
                requestAuthenticator.CopyTo(bytes, 4);

                using var md5 = MD5.Create();
                return md5.ComputeHash(bytes, 0, length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bytes, clearArray: true);
            }
        }


        /// <summary>
        /// Validate message authenticator in packet
        /// </summary>
        public static bool ValidateMessageAuthenticator(
            ReadOnlySpan<byte> packetBytes,
            int messageAuthenticatorPosition,
            byte[] sharedSecret,
            byte[]? requestAuthenticator)
        {
            var calculatedMessageAuthenticator = CalculateMessageAuthenticator(
                packetBytes,
                sharedSecret,
                requestAuthenticator,
                messageAuthenticatorPosition);

            return CryptographicOperations.FixedTimeEquals(
                calculatedMessageAuthenticator,
                packetBytes.Slice(messageAuthenticatorPosition + 2, 16));
        }


        /// <summary>
        /// Calculate the request authenticator used in accounting, disconnect and coa requests
        /// </summary>
        internal static byte[] CalculateRequestAuthenticator(byte[] sharedSecret, ReadOnlySpan<byte> packetBytes) =>
            CalculateResponseAuthenticator(sharedSecret, AuthenticatorZeros, packetBytes);


        /// <summary>
        /// Get a pretty string representation of the packet
        /// </summary>
        public static string GetPacketString(IRadiusPacket packet)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Packet dump for {packet.Identifier}:");
            foreach (var attribute in packet.Attributes)
            {
                if (attribute.Key == "User-Password")
                {
                    sb.AppendLine($"{attribute.Key} length : {attribute.Value[0].ToString()?.Length}");
                }
                else
                {
                    attribute.Value.ForEach(o => sb.AppendLine($"{attribute.Key} : {o} [{o.GetType()}]"));
                }
            }

            return sb.ToString();
        }
    }
}
