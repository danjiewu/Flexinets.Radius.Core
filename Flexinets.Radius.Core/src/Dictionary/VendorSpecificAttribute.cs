using System;
using System.Collections.Generic;

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
            var vendorId = new byte[4];
            Buffer.BlockCopy(contentBytes, 0, vendorId, 0, 4);
            Array.Reverse(vendorId);
            VendorId = BitConverter.ToUInt32(vendorId, 0);

            // VendorSpecificAttribute supports multiple vendor attributes, each vendor attribute has the format of:
            // 1 byte for VendorCode
            // 1 byte for Length
            // (Length - 2) bytes for Value
            int offset = 4;
            while (offset < contentBytes.Length)
            {
                var vendorType = new byte[1];
                Buffer.BlockCopy(contentBytes, offset, vendorType, 0, 1);
                byte vendorCode = vendorType[0];
                offset++;

                var vendorLength = new byte[1];
                Buffer.BlockCopy(contentBytes, offset, vendorLength, 0, 1);
                byte length = vendorLength[0];
                offset++;

                if (length < 2) // Length should be at least 2 (1 byte for VendorCode and 1 byte for Length itself)
                    throw new FormatException($"Invalid vendor attribute length: {length}");

                var value = new byte[length - 2];
                Buffer.BlockCopy(contentBytes, offset, value, 0, length - 2);
                offset += length - 2;

                VendorAttrNode node = new VendorAttrNode(vendorCode, length, value);
                offset += node.Length - 2;

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
