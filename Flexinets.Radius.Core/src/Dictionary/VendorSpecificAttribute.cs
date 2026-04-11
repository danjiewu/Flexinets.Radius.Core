using System;
using System.Collections.Generic;

namespace Flexinets.Radius.Core
{
    public class VendorSpecificAttribute
    {
        public uint VendorId;

        public List<VendorAttrNode> AttrNodes { get; } = new List<VendorAttrNode>();

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
                VendorAttrNode node = new VendorAttrNode();
                var vendorType = new byte[1];
                Buffer.BlockCopy(contentBytes, offset, vendorType, 0, 1);
                node.VendorCode = vendorType[0];
                offset++;

                var vendorLength = new byte[1];
                Buffer.BlockCopy(contentBytes, offset, vendorLength, 0, 1);
                node.Length = vendorLength[0];
                offset++;

                var value = new byte[node.Length - 2];
                Buffer.BlockCopy(contentBytes, offset, value, 0, node.Length - 2);
                node.Value = value;
                offset += node.Length - 2;

                AttrNodes.Add(node);
            }
        }

        public class VendorAttrNode
        {
            public byte Length;
            public byte VendorCode;
            public byte[]? Value;
        }
    }
}
