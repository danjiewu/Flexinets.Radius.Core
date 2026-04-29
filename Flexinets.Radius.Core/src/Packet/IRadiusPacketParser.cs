using System;
using System.IO;

namespace Flexinets.Radius.Core
{
    public interface IRadiusPacketParser
    {
        byte[] GetBytes(IRadiusPacket packet, byte[] sharedSecret, byte[]? requestAuthenticator = null);
        IRadiusPacket Parse(ReadOnlyMemory<byte> packetBytes, byte[] sharedSecret, byte[]? requestAuthenticator = null);
    }
}
