using BenchmarkDotNet.Attributes;
using Flexinets.Radius.Core.PacketTypes;
using Microsoft.Extensions.Logging.Abstractions;

namespace Flexinets.Radius.Core.Benchmarks;

[MemoryDiagnoser]
public class RadiusPacketBenchmarks
{
    private static readonly byte[] DefaultSecret = "xyzzy5461"u8.ToArray();
    private static readonly IRadiusDictionary Dictionary = RadiusDictionary.Parse(DefaultDictionary.RadiusDictionary);
    private static readonly RadiusPacketParser Parser =
        new(NullLogger<RadiusPacketParser>.Instance, Dictionary, skipBlastRadiusChecks: true);

    private byte[] _accessRequestBytes = null!;
    private byte[] _vsaPacketBytes = null!;
    private AccessRequest _accessRequest = null!;
    private byte[] _passwordBytes = null!;
    private byte[] _authenticator = null!;
    private byte[] _encryptedPasswordBytes = null!;

    [GlobalSetup]
    public void Setup()
    {
        _authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a");
        _passwordBytes = "arctangent"u8.ToArray();

        _accessRequest = new AccessRequest(0)
        {
        };
        _accessRequest.AddAttribute("User-Name", "nemo");
        _accessRequest.AddAttribute("User-Password", "arctangent");
        _accessRequest.AddAttribute("NAS-IP-Address", System.Net.IPAddress.Parse("192.168.1.16"));
        _accessRequest.AddAttribute("NAS-Port", 3);

        _accessRequestBytes = Parser.GetBytes(_accessRequest, DefaultSecret);
        _vsaPacketBytes = Utils.StringToByteArray(
            "0c010024000000000000000000000000000000001a10000028af08073234303031150306");
        _encryptedPasswordBytes = RadiusPassword.Encrypt(DefaultSecret, _authenticator, _passwordBytes);
    }

    [Benchmark]
    public IRadiusPacket ParseAccessRequest() => Parser.Parse(_accessRequestBytes, DefaultSecret);

    [Benchmark]
    public byte[] SerializeAccessRequest() => Parser.GetBytes(_accessRequest, DefaultSecret);

    [Benchmark]
    public IRadiusPacket ParseVendorSpecificPacket() => Parser.Parse(_vsaPacketBytes, DefaultSecret);

    [Benchmark]
    public byte[] EncryptUserPassword() => RadiusPassword.Encrypt(DefaultSecret, _authenticator, _passwordBytes);

    [Benchmark]
    public string DecryptUserPassword() =>
        RadiusPassword.Decrypt(DefaultSecret, _authenticator, _encryptedPasswordBytes);
}
