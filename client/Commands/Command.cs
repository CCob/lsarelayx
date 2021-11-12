using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace ntlmrelaynet.Commands {

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct FILE_RENAME_INFORMATION {
        public uint ReplaceIfExistsOrFlags;
        public IntPtr RootDirectory;
        public uint FileNameLength; //this needs to be in bytes not chars
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string FileName;
    }

    public enum CommandType : uint {
        Init,
        NTLMRelay,
        Negotiate
    }

    public enum RelayStatus : byte {
        Ok,
        NoConnection,
        Passive,
        Forward,
        AuthFailed,
        AuthSuccess,
        Replace
    }

    public abstract class BitseryObject {
        public abstract void Write(BitseryWriter writer);

        public void WriteToStream(Stream outputStream) {
            using(var ms = new MemoryStream()) {
                using (var writer = new BitseryWriter(ms, Encoding.Unicode)) {
                    Write(writer);

                    var objectData = ms.ToArray();
                    var outputWriter = new BinaryWriter(outputStream, Encoding.Unicode, true);
                    outputWriter.Write(objectData.Length);
                    outputWriter.Write(objectData);                    
                }
            }                  
        }

        public static BitseryObject ReadFromStream(Stream inputStream) {

            BitseryObject result = null;

            using(var reader = new BinaryReader(inputStream, Encoding.Unicode, true)) {

                var size = reader.ReadUInt32();

                //Reflection probably a bit overkill for factories based on 2 command types.
                //So lets stick to a simple factory method for now
                if(size != 0) {
                    var commandType = (CommandType)reader.ReadByte();

                    switch (commandType) {
                        case CommandType.Init:
                            result = new InitRequest();
                            break;
                        case CommandType.NTLMRelay:
                            result = new RelayRequest(inputStream);
                            break;
                        case CommandType.Negotiate:
                            result = new NegotiateRequest(inputStream);
                            break;
                    }
                }
            }

            return result;       
        }
    }
}
