using System;
using System.Collections.Generic;
using System.Buffers.Binary;

namespace Flexinets.Radius.Core
{
    public class VendorSpecificAttribute
    {
        public readonly uint VendorId;
        private readonly List<VendorAttrNode> _attrNodes = new List<VendorAttrNode>();

        public IReadOnlyCollection<VendorAttrNode> AttrNodes => _attrNodes;

        /// <summary>
        /// Create a vsa from bytes
        /// </summary>
        /// <param name="contentBytes"></param>
        public VendorSpecificAttribute(byte[] contentBytes)
        {
            if (contentBytes.Length < 4)
            {
                throw new FormatException("Vendor specific attribute missing vendor id");
            }

            VendorId = BinaryPrimitives.ReadUInt32BigEndian(contentBytes.AsSpan(0, 4));

            // VendorSpecificAttribute supports multiple vendor attributes, each vendor attribute has the format of:
            // 1 byte for VendorCode
            // 1 byte for Length
            // (Length - 2) bytes for Value
            int offset = 4;
            while (offset < contentBytes.Length)
            {
                if (contentBytes.Length - offset < 2)
                {
                    throw new FormatException("Vendor specific attribute header is truncated");
                }

                byte vendorCode = contentBytes[offset];
                byte length = contentBytes[offset + 1];

                if (length < 2) // Length should be at least 2 (1 byte for VendorCode and 1 byte for Length itself)
                {
                    throw new FormatException($"Invalid vendor attribute length: {length}");
                }

                if (offset + length > contentBytes.Length)
                {
                    throw new FormatException($"Invalid vendor attribute length: {length}");
                }

                var value = new byte[length - 2];
                Buffer.BlockCopy(contentBytes, offset + 2, value, 0, length - 2);

                VendorAttrNode node = new VendorAttrNode(vendorCode, length, value);
                offset += length;

                _attrNodes.Add(node);
            }
        }

        public class VendorAttrNode
        {
            public VendorAttrNode(byte vendorCode, byte length, byte[] value)
            {
                VendorCode = vendorCode;
                Length = length;
                Value = value;
            }

            public readonly byte Length;
            public readonly byte VendorCode;
            public readonly byte[] Value;
        }
    }
}
