namespace ntlmrelaynet.Commands {
    public class NegotiateResponse : BitseryObject {

        public RelayStatus Status { get; private set; }

        public byte[] NegotiateTokenResponse { get; private set; } = new byte[] { };


        public NegotiateResponse(RelayStatus status) {
            Status = status;
        }

        public NegotiateResponse(byte[] negoTokenResponse) : this(negoTokenResponse, RelayStatus.Forward) {
        }

        public NegotiateResponse(byte[] negoTokenResponse, RelayStatus status) {
            NegotiateTokenResponse = negoTokenResponse;
            Status = status;
        }

        public override void Write(BitseryWriter output) {
            output.Write((byte)Status);
            output.WritePrefixedBytes(NegotiateTokenResponse);
        }
    }
}
