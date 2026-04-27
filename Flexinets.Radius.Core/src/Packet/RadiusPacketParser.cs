using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Flexinets.Radius.Core.PacketTypes;
using Microsoft.Extensions.Logging;

namespace Flexinets.Radius.Core
{
    public partial class RadiusPacketParser : IRadiusPacketParser
    {
        private readonly ILogger _logger;
        private readonly IRadiusDictionary _dictionary;
        private readonly bool _skipBlastRadiusChecks;


        /// <summary>
        /// RadiusPacketParser
        /// </summary>
        public RadiusPacketParser(
            ILogger<RadiusPacketParser> logger,
            IRadiusDictionary dictionary,
            bool skipBlastRadiusChecks = false)
        {
            _logger = logger;
            _dictionary = dictionary;
            _skipBlastRadiusChecks = skipBlastRadiusChecks;
        }


        /// <summary>
        /// Parses packet bytes and returns an IRadiusPacket
        /// </summary>
        public IRadiusPacket Parse(byte[] packetBytes, byte[] sharedSecret, byte[]? requestAuthenticator = null)
        {
            var packetLength = GetPacketLength(packetBytes);
            if (packetBytes.Length < packetLength)
            {
                throw new ArgumentOutOfRangeException(nameof(packetBytes),
                    $"Packet length mismatch, expected: {packetLength}, actual: {packetBytes.Length}");
            }

            var effectivePacketBytes = packetBytes.Length == packetLength
                ? packetBytes
                : TrimPacketBytes(packetBytes, packetLength);

            var (packet, messageAuthenticatorPosition) = ParsePacketBytes(effectivePacketBytes, sharedSecret);

            // Validate RequestAuthenticator for appropriate packet types
            if ((packet is AccountingRequest
                 || packet is DisconnectRequest
                 || packet is CoaRequest) && !packet.Authenticator.AsSpan().SequenceEqual(
                     Utils.CalculateRequestAuthenticator(sharedSecret, effectivePacketBytes)))
            {
                throw new InvalidOperationException(
                    $"Invalid request authenticator in packet {packet.Identifier}, check secret?");
            }

            // If the packet contains a Message-Authenticator it must be valid regardless of if it is required
            if (messageAuthenticatorPosition != 0
                && !Utils.ValidateMessageAuthenticator(
                    effectivePacketBytes,
                    messageAuthenticatorPosition,
                    sharedSecret,
                    requestAuthenticator))
            {
                throw new InvalidMessageAuthenticatorException(
                    $"Invalid Message-Authenticator in packet {packet.Identifier}");
            }

            if (packet is AccessAccept
                || packet is AccessChallenge
                || packet is AccessReject
                || packet is AccessRequest)
            {
                // Ensure packet contains a Message-Authenticator if it contains EAP-Message attributes                                 
                // https://datatracker.ietf.org/doc/html/rfc3579#section-3.1
                if (messageAuthenticatorPosition == 0 && packet.GetAttributes<object>("EAP-Message").Count != 0)
                {
                    throw new MissingMessageAuthenticatorException(
                        "No Message-Authenticator found in packet with EAP-Message attributes");
                }

                // Ensure a Message-Authenticator exists in Access* packets
                // https://datatracker.ietf.org/doc/html/draft-ietf-radext-deprecating-radius/#section-5
                if (messageAuthenticatorPosition == 0 && !_skipBlastRadiusChecks)
                {
                    throw new MissingMessageAuthenticatorException(
                        "No Message-Authenticator found in packet and BLASTRadius checks enabled");
                }

                // The Message-Authenticator attribute should be first in AccessRequests
                // and must be first in the other Access* packets
                // https://datatracker.ietf.org/doc/html/draft-ietf-radext-deprecating-radius/#section-5.2
                if (messageAuthenticatorPosition != 20 && !_skipBlastRadiusChecks)
                {
                    _logger.LogWarning("Message-Authenticator should be first attribute");
                }
            }

            return packet;
        }


        /// <summary>
        /// Parse bytes into packet with attributes
        /// </summary>
        private (RadiusPacket packet, int messageAuthenticatorPosition) ParsePacketBytes(
            byte[] packetBytes,
            byte[] sharedSecret)
        {
            var packet = RadiusPacket.CreateFromCode((PacketCode)packetBytes[0]);
            packet.Authenticator = packetBytes.AsSpan(4, 16).ToArray();
            packet.Identifier = packetBytes[1];
            packet.Code = (PacketCode)packetBytes[0];

            var messageAuthenticatorPosition = AddAttributesToPacket(packet, packetBytes.AsSpan(), sharedSecret);

            return (packet, messageAuthenticatorPosition);
        }


        /// <summary>
        /// Get the raw packet bytes
        /// </summary>
        public byte[] GetBytes(IRadiusPacket packet, byte[] sharedSecret, byte[]? requestAuthenticator = null)
        {
            var length = checked((ushort)(20 + GetAttributesLength(packet)));

            // Max length is 4096 bytes...
            // https://datatracker.ietf.org/doc/html/rfc2865#section-3
            if (length > 4096)
            {
                throw new InvalidOperationException($"Packet length cannot exceed 4096, was {length}");
            }

            var packetBytes = new byte[length];
            packetBytes[0] = (byte)packet.Code;
            packetBytes[1] = packet.Identifier;
            BinaryPrimitives.WriteUInt16BigEndian(packetBytes.AsSpan(2, 2), length);

            var messageAuthenticatorPosition = WriteAttributes(packet, sharedSecret, packetBytes);

            // Different types of packets have different ways of handling the authenticators
            switch (packet.Code)
            {
                case PacketCode.AccountingRequest:
                case PacketCode.DisconnectRequest:
                case PacketCode.CoaRequest:
                    {
                        HandleRequestMessageAuthenticator(sharedSecret, messageAuthenticatorPosition, packetBytes);
                        Buffer.BlockCopy(Utils.CalculateRequestAuthenticator(sharedSecret, packetBytes),
                            0, packetBytes, 4, 16);
                        break;
                    }
                case PacketCode.StatusServer:
                case PacketCode.AccessRequest:
                    {
                        Buffer.BlockCopy(packet.Authenticator, 0, packetBytes, 4, 16);
                        HandleRequestMessageAuthenticator(sharedSecret, messageAuthenticatorPosition, packetBytes);
                        break;
                    }
                case PacketCode.AccessAccept:
                case PacketCode.AccessReject:
                case PacketCode.AccessChallenge:
                case PacketCode.AccountingResponse:
                case PacketCode.StatusClient:
                case PacketCode.DisconnectAck:
                case PacketCode.DisconnectNak:
                case PacketCode.CoaAck:
                case PacketCode.CoaNak:
                default:
                    {
                        if (requestAuthenticator == null)
                        {
                            throw new ArgumentNullException(nameof(requestAuthenticator),
                                "Request-Authenticator is required when creating response packets");
                        }

                        if (messageAuthenticatorPosition != 0)
                        {
                            var messageAuthenticator = Utils.CalculateResponseMessageAuthenticator(
                                packetBytes,
                                sharedSecret,
                                requestAuthenticator,
                                messageAuthenticatorPosition);

                            Buffer.BlockCopy(messageAuthenticator, 0, packetBytes, messageAuthenticatorPosition + 2, 16);
                        }

                        var authenticator = Utils.CalculateResponseAuthenticator(
                            sharedSecret,
                            requestAuthenticator,
                            packetBytes);

                        Buffer.BlockCopy(authenticator, 0, packetBytes, 4, 16);
                        break;
                    }
            }

            return packetBytes;
        }


        /// <summary>
        /// Add a request message authenticator to the packet if applicable
        /// </summary>
        private static void HandleRequestMessageAuthenticator(
            byte[] sharedSecret,
            int messageAuthenticatorPosition,
            byte[] packetBytes)
        {
            if (messageAuthenticatorPosition != 0)
            {
                var messageAuthenticator = Utils.CalculateRequestMessageAuthenticator(
                    packetBytes,
                    sharedSecret,
                    messageAuthenticatorPosition);

                Buffer.BlockCopy(messageAuthenticator, 0, packetBytes, messageAuthenticatorPosition + 2, 16);
            }
        }


        /// <summary>
        /// Get packet bytes trimmed to the packet length
        /// </summary>
        private static byte[] TrimPacketBytes(byte[] packetBytes, int packetLength)
        {
            var trimmedPacketBytes = new byte[packetLength];
            Buffer.BlockCopy(packetBytes, 0, trimmedPacketBytes, 0, packetLength);
            return trimmedPacketBytes;
        }


        /// <summary>
        /// Get the packet length from the header
        /// </summary>
        private static ushort GetPacketLength(byte[] packetBytes)
        {
            if (packetBytes.Length < 20)
            {
                throw new ArgumentOutOfRangeException(nameof(packetBytes),
                    $"Packet length mismatch, expected at least 20, actual: {packetBytes.Length}");
            }

            var packetLength = BinaryPrimitives.ReadUInt16BigEndian(packetBytes.AsSpan(2, 2));
            if (packetLength < 20)
            {
                throw new InvalidOperationException($"Packet length cannot be smaller than 20, was {packetLength}");
            }

            return packetLength;
        }


        /// <summary>
        /// Populate packet with attributes and return position of Message-Authenticator if found
        /// Yees, very mutating... anyway
        /// </summary>
        /// <returns>Message-Authenticator position if found</returns>
        private int AddAttributesToPacket(RadiusPacket packet, ReadOnlySpan<byte> packetBytes,
            byte[] sharedSecret)
        {
            var position = 20;
            var messageAuthenticatorPosition = 0;

            while (position < packetBytes.Length)
            {
                if (packetBytes.Length - position < 2)
                {
                    throw new InvalidOperationException("Attribute header is truncated");
                }

                var typeCode = packetBytes[position];
                var attributeLength = packetBytes[position + 1];
                if (attributeLength < 2 || position + attributeLength > packetBytes.Length)
                {
                    throw new InvalidOperationException($"Invalid attribute length {attributeLength} at {position}");
                }

                var attributeValueBytes = packetBytes.Slice(position + 2, attributeLength - 2);

                try
                {
                    if (typeCode == 26) // VSA
                    {
                        AddVendorSpecificAttributesToPacket(packet, attributeValueBytes, sharedSecret);
                    }
                    else
                    {
                        var attributeType = _dictionary.GetAttribute(typeCode) ??
                                            throw new ArgumentNullException(nameof(typeCode));

                        // We need the location of the Message-Authenticator later to be able to zero it for validation
                        if (attributeType.Code == 80)
                        {
                            messageAuthenticatorPosition = position;
                        }

                        try
                        {
                            packet.AddAttributeObject(
                                attributeType.Name,
                                Attribute.ToObject(
                                    attributeValueBytes,
                                    attributeType.Type,
                                    typeCode,
                                    packet.Authenticator,
                                    sharedSecret));
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Something went wrong with {attributeTypeName}", attributeType.Name);
                            _logger.LogDebug("Attribute bytes: {hex}", attributeValueBytes.ToArray().ToHexString());
                        }
                    }
                }
                catch (KeyNotFoundException)
                {
                    _logger.LogWarning("Attribute {typeCode} not found in dictionary", typeCode);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Something went wrong parsing attribute {typeCode}", typeCode);
                }

                position += attributeLength;
            }

            return messageAuthenticatorPosition;
        }


        /// <summary>
        /// Parse vendor specific attributes and add them to the packet
        /// </summary>
        private void AddVendorSpecificAttributesToPacket(
            RadiusPacket packet,
            ReadOnlySpan<byte> attributeValueBytes,
            byte[] sharedSecret)
        {
            if (attributeValueBytes.Length < 4)
            {
                throw new FormatException("Vendor specific attribute missing vendor id");
            }

            var vendorId = BinaryPrimitives.ReadUInt32BigEndian(attributeValueBytes.Slice(0, 4));
            var offset = 4;

            while (offset < attributeValueBytes.Length)
            {
                if (attributeValueBytes.Length - offset < 2)
                {
                    throw new FormatException("Vendor specific attribute header is truncated");
                }

                var vendorCode = attributeValueBytes[offset];
                var vendorLength = attributeValueBytes[offset + 1];
                if (vendorLength < 2 || offset + vendorLength > attributeValueBytes.Length)
                {
                    throw new FormatException($"Invalid vendor attribute length {vendorLength}");
                }

                var vendorAttributeType = _dictionary.GetVendorAttribute(vendorId, vendorCode);
                if (vendorAttributeType == null)
                {
                    _logger.LogInformation("Unknown vsa: {id}:{code}", vendorId, vendorCode);
                }
                else
                {
                    try
                    {
                        packet.AddAttributeObject(
                            vendorAttributeType.Name,
                            Attribute.ToObject(
                                attributeValueBytes.Slice(offset + 2, vendorLength - 2),
                                vendorAttributeType.Type,
                                26,
                                packet.Authenticator,
                                sharedSecret));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Something went wrong with vsa {name}", vendorAttributeType.Name);
                    }
                }

                offset += vendorLength;
            }
        }


        /// <summary>
        /// Calculates the total encoded attribute length for the packet
        /// </summary>
        private int GetAttributesLength(IRadiusPacket packet)
        {
            var totalLength = 0;
            foreach (var packetAttribute in packet.Attributes)
            {
                var attributeType = _dictionary.GetAttribute(packetAttribute.Key) ??
                                    throw new InvalidOperationException(
                                        $"Unknown attribute {packetAttribute.Key}, check spelling or dictionary");
                var headerLength = attributeType is DictionaryVendorAttribute ? 8 : 2;

                foreach (var attributeValue in packetAttribute.Value)
                {
                    var attributeLength = headerLength + GetAttributeContentLength(attributeType, attributeValue);
                    if (attributeLength > byte.MaxValue)
                    {
                        throw new InvalidOperationException($"Attribute max length is 255, was {attributeLength}");
                    }

                    totalLength += attributeLength;
                }
            }

            return totalLength;
        }


        /// <summary>
        /// Writes packet attributes and returns the Message-Authenticator position if found
        /// </summary>
        private int WriteAttributes(IRadiusPacket packet, byte[] sharedSecret, byte[] packetBytes)
        {
            var messageAuthenticatorPosition = 0;
            var position = 20;

            foreach (var packetAttribute in packet.Attributes)
            {
                var attributeType = _dictionary.GetAttribute(packetAttribute.Key) ??
                                    throw new InvalidOperationException(
                                        $"Unknown attribute {packetAttribute.Key}, check spelling or dictionary");

                foreach (var attributeValue in packetAttribute.Value)
                {
                    var contentLength = GetAttributeContentLength(attributeType, attributeValue);

                    switch (attributeType)
                    {
                        case DictionaryVendorAttribute vendorAttributeType:
                            if (vendorAttributeType.VendorCode > byte.MaxValue)
                            {
                                throw new InvalidOperationException(
                                    $"Vendor attribute code must fit in a byte, was {vendorAttributeType.VendorCode}");
                            }

                            packetBytes[position] = 26;
                            packetBytes[position + 1] = (byte)(8 + contentLength);
                            BinaryPrimitives.WriteUInt32BigEndian(
                                packetBytes.AsSpan(position + 2, 4),
                                vendorAttributeType.VendorId);
                            packetBytes[position + 6] = (byte)vendorAttributeType.VendorCode;
                            packetBytes[position + 7] = (byte)(2 + contentLength);
                            Attribute.WriteBytes(attributeValue, packetBytes.AsSpan(position + 8, contentLength));
                            position += 8 + contentLength;
                            break;
                        default:
                            packetBytes[position] = attributeType.Code;
                            packetBytes[position + 1] = (byte)(2 + contentLength);
                            if (attributeType.Code == 80)
                            {
                                messageAuthenticatorPosition = position;
                            }

                            if (attributeType.Code == 2)
                            {
                                var passwordBytes = new byte[Attribute.GetByteCount(attributeValue)];
                                Attribute.WriteBytes(attributeValue, passwordBytes);
                                var encryptedPassword =
                                    RadiusPassword.Encrypt(sharedSecret, packet.Authenticator, passwordBytes);
                                Buffer.BlockCopy(
                                    encryptedPassword,
                                    0,
                                    packetBytes,
                                    position + 2,
                                    encryptedPassword.Length);
                            }
                            else
                            {
                                Attribute.WriteBytes(attributeValue, packetBytes.AsSpan(position + 2, contentLength));
                            }

                            position += 2 + contentLength;
                            break;
                    }
                }
            }

            return messageAuthenticatorPosition;
        }


        /// <summary>
        /// Calculates the encoded content length for a single attribute value
        /// </summary>
        private static int GetAttributeContentLength(DictionaryAttribute attributeType, object attributeValue)
        {
            var contentLength = Attribute.GetByteCount(attributeValue);
            return attributeType.Code == 2
                ? RadiusPassword.GetEncryptedLength(contentLength)
                : contentLength;
        }
    }
}
