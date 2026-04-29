using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace Flexinets.Radius.Core
{
    public partial class RadiusDictionary : IRadiusDictionary
    {
        private readonly Dictionary<byte, DictionaryAttribute> _attributes;
        private readonly Dictionary<ulong, DictionaryVendorAttribute> _vendorSpecificAttributes;
        private readonly Dictionary<string, DictionaryAttribute> _attributeNames;

        private RadiusDictionary(
            Dictionary<byte, DictionaryAttribute> attributes,
            Dictionary<ulong, DictionaryVendorAttribute> vendorSpecificAttributes,
            Dictionary<string, DictionaryAttribute> attributeNames)
        {
            _attributes = attributes;
            _vendorSpecificAttributes = vendorSpecificAttributes;
            _attributeNames = attributeNames;
        }


        /// <summary>
        /// Parse dictionary from string content in Radiator format
        /// </summary>
        public static IRadiusDictionary Parse(string dictionaryFileContent)
        {
            var attributes = new Dictionary<byte, DictionaryAttribute>();
            var vendorSpecificAttributes = new Dictionary<ulong, DictionaryVendorAttribute>();
            var attributeNames = new Dictionary<string, DictionaryAttribute>();

            using var reader = new StringReader(dictionaryFileContent);
            while (reader.ReadLine() is { } rawLine)
            {
                var line = rawLine.Trim();
                if (line.Length == 0)
                {
                    continue;
                }

                if (line.StartsWith("Attribute", StringComparison.Ordinal))
                {
                    var lineParts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    var attributeCode = Convert.ToByte(lineParts[1]);

                    var attributeDefinition = new DictionaryAttribute(lineParts[2], attributeCode, lineParts[3]);
                    attributes[attributeCode] = attributeDefinition;
                    attributeNames[attributeDefinition.Name] = attributeDefinition;
                }
                else if (line.StartsWith("VendorSpecificAttribute", StringComparison.Ordinal))
                {
                    var lineParts = line.Split(new[] { '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    var vendorId = Convert.ToUInt32(lineParts[1]);
                    var vendorCode = Convert.ToUInt32(lineParts[2]);
                    var vsa = new DictionaryVendorAttribute(
                        vendorId,
                        lineParts[3],
                        vendorCode,
                        lineParts[4]);

                    if (vendorCode <= byte.MaxValue)
                    {
                        vendorSpecificAttributes[GetVendorAttributeKey(vendorId, (byte)vendorCode)] = vsa;
                    }

                    attributeNames[vsa.Name] = vsa;
                }
            }

            return new RadiusDictionary(attributes, vendorSpecificAttributes, attributeNames);
        }


        /// <summary>
        /// Read and parse dictionary from file in Radiator format
        /// </summary>
        public static async Task<IRadiusDictionary> LoadAsync(string dictionaryFilePath) =>
            Parse(await File.ReadAllTextAsync(dictionaryFilePath).ConfigureAwait(false));


        public DictionaryVendorAttribute? GetVendorAttribute(uint vendorId, byte vendorCode) =>
            _vendorSpecificAttributes.GetValueOrDefault(GetVendorAttributeKey(vendorId, vendorCode));


        public DictionaryAttribute? GetAttribute(byte typecode) => _attributes.GetValueOrDefault(typecode);


        public DictionaryAttribute? GetAttribute(string name) => _attributeNames.GetValueOrDefault(name);


        private static ulong GetVendorAttributeKey(uint vendorId, byte vendorCode) =>
            ((ulong)vendorId << 8) | vendorCode;
    }
}
