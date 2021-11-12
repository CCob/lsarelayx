using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ntlmrelaynet.Negotiate {
    public class NegToken {
        public static Oid MechTypeNegoEx = new Oid("1.3.6.1.4.1.311.2.2.30");
        public static Oid MechTypeMsKerb5 = new Oid("1.2.840.48018.1.2.2");
        public static Oid MechTypeKerb5 = new Oid("1.2.840.113554.1.2.2");
        public static Oid MechTypeKerb5U2U = new Oid("1.2.840.113554.1.2.2.3");
        public static Oid MechTypeNTLM = new Oid("1.3.6.1.4.1.311.2.2.10");

        public static byte[] SessionKeyClientToServerConstant = Encoding.ASCII.GetBytes("session key to client-to-server signing key magic constant\0");
        public static byte[] SessionKeyServerToClientConstant = Encoding.ASCII.GetBytes("session key to server-to-client signing key magic constant\0");

        /*
        public byte[] CalculateSignKey(byte[] sessionKey, bool serverMode) {

            byte[] signature = sessionKey.Concat( serverMode ? SessionKeyServerToClientConstant : SessionKeyClientToServerConstant).ToArray();

            MD5

        }
        */
    }
}
