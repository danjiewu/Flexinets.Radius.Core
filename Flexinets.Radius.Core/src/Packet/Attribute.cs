using System;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Flexinets.Radius.Core
{
    public static class Attribute
    {
        /// <summary>
        /// Parses the attribute value and returns an object of some sort
        /// </summary>
        public static object ToObject(
            byte[] contentBytes,
            string type,
            uint code,
            byte[] authenticator,
            byte[] sharedSecret) =>
            ToObject((ReadOnlySpan<byte>)contentBytes, type, code, authenticator, sharedSecret);


        /// <summary>
        /// Parses the attribute value and returns an object of some sort
        /// </summary>
        public static object ToObject(
            ReadOnlySpan<byte> contentBytes,
            string type,
            uint code,
            byte[] authenticator,
            byte[] sharedSecret) =>
            type switch
            {
                "string" => Encoding.UTF8.GetString(contentBytes),
                "tagged-string" => Encoding.UTF8.GetString(contentBytes),
                "octet" when code == 2 => RadiusPassword.Decrypt(sharedSecret, authenticator, contentBytes),
                "octet" => contentBytes.ToArray(),
                "integer" => BinaryPrimitives.ReadUInt32BigEndian(contentBytes),
                "tagged-integer" => BinaryPrimitives.ReadUInt32BigEndian(contentBytes),
                "ipaddr" => new IPAddress(contentBytes),
                _ => throw new ArgumentException("Unknown type")
            };


        /// <summary>
        /// Gets the number of bytes needed for the attribute object
        /// </summary>
        public static int GetByteCount(object value) =>
            value switch
            {
                string stringValue => Encoding.UTF8.GetByteCount(stringValue),
                uint _ => sizeof(uint),
                byte[] byteArray => byteArray.Length,
                IPAddress ipAddress => ipAddress.AddressFamily switch
                {
                    AddressFamily.InterNetwork => 4,
                    AddressFamily.InterNetworkV6 => 16,
                    _ => ipAddress.GetAddressBytes().Length
                },
                _ => throw new NotImplementedException()
            };


        /// <summary>
        /// Writes the byte representation of an attribute object to the destination span
        /// </summary>
        public static void WriteBytes(object value, Span<byte> destination)
        {
            switch (value)
            {
                case string stringValue:
                    var bytesWritten = Encoding.UTF8.GetBytes(stringValue.AsSpan(), destination);
                    if (bytesWritten != destination.Length)
                    {
                        throw new InvalidOperationException("Failed to encode string attribute");
                    }

                    break;
                case uint uintValue:
                    BinaryPrimitives.WriteUInt32BigEndian(destination, uintValue);
                    break;
                case byte[] byteArray:
                    byteArray.CopyTo(destination);
                    break;
                case IPAddress ipAddress:
                    ipAddress.GetAddressBytes().CopyTo(destination);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
