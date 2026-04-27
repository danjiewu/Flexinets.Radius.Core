using Flexinets.Radius.Core.PacketTypes;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;

namespace Flexinets.Radius.Core.Tests;

[TestFixture]
public class RadiusPacketParserOptimizationTests
{
    private static readonly byte[] DefaultSecret = "xyzzy5461"u8.ToArray();
    private static readonly IRadiusDictionary Dictionary = RadiusDictionary.Parse(DefaultDictionary.RadiusDictionary);

    [TestCase]
    public void ParseSingleVsaWithMultipleVendorAttributes()
    {
        var parser = new RadiusPacketParser(NullLogger<RadiusPacketParser>.Instance, Dictionary);
        var packetBytes = Utils.StringToByteArray(
            "0c010024000000000000000000000000000000001a10000028af08073234303031150306");

        var packet = parser.Parse(packetBytes, DefaultSecret);

        Assert.That(packet, Is.TypeOf<StatusServer>());
        Assert.Multiple(() =>
        {
            Assert.That(packet.GetAttribute<string>("3GPP-IMSI-MCC-MNC"), Is.EqualTo("24001"));
            Assert.That(packet.GetAttribute<byte[]>("3GPP-RAT-Type").ToHexString(), Is.EqualTo("06"));
        });
    }
}
