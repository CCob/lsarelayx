using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ntlmrelaynet {
    public class BitseryWriter : BinaryWriter {

        Encoding encoding = Encoding.UTF8;

        public BitseryWriter(Stream output) : base(output) {
        }

        public BitseryWriter(Stream output, Encoding encoding) : base(output, encoding) {
            this.encoding = encoding;
        }

        public BitseryWriter(Stream output, Encoding encoding, bool leaveOpen) : base(output, encoding, leaveOpen) {
            this.encoding = encoding;
        }

        public void WriteCompressedInt(int value) {

            if (value >= 0x40000000u) {
                throw new ArgumentOutOfRangeException("value");
            }

            if (value < 0x80u) {

                Write((byte)value);

            } else {

                if (value < 0x4000u) {
                    Write((byte)((value >> 8) | 0x80u));
                    Write((byte)value);
                } else {
                    Write((byte)((value >> 24) | 0xC0u));
                    Write((byte)(value >> 16));
                    Write((short)value);
                }
            }
        }

        public void WritePrefixedString(string value) {
            if (string.IsNullOrEmpty(value)) {
                WriteCompressedInt(0);
            } else {
                var valueData = encoding.GetBytes(value);
                WriteCompressedInt(value.Length);
                Write(valueData);
            }
        }

        public void WritePrefixedBytes(byte[] data) {
            if (data == null || data.Length == 0) {
                WriteCompressedInt(0);
            } else {
                WriteCompressedInt(data.Length);
                Write(data);
            }
        }
    }


    public class BitseryReader : BinaryReader {

        Encoding encoding = Encoding.UTF8;

        public BitseryReader(Stream input) : base(input) {
        }

        public BitseryReader(Stream input, Encoding encoding) : base(input, encoding) {
            this.encoding = encoding;
        }

        public BitseryReader(Stream input, Encoding encoding, bool leaveOpen) : base(input, encoding, leaveOpen) {
            this.encoding = encoding;
        }

        public int ReadCompressedInt() {

            byte hb = ReadByte();
            int value;

            if (hb < 0x80u) {
                value = hb;
            } else {
                byte lb = ReadByte();
                if ((hb & 0x40u) > 0) {
                    ushort lw = ReadUInt16();
                    value = ((((hb & 0x3F) << 8) | lb) << 16) | lw;
                } else {
                    value = ((hb & 0x7F) << 8) | lb;
                }
            }

            return value;
        }

        public string ReadPrefixedString() {
            var len = ReadCompressedInt();
            var characters = new List<char>();

            while (len-- > 0) {
                characters.Add(ReadChar());
            }

            return new string(characters.ToArray());    
        }

        public byte[] ReadPrefixedBytes() {
            var count = ReadCompressedInt();
            return ReadBytes(count);
        }
    }
}
