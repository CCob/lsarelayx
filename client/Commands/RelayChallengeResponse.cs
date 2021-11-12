namespace ntlmrelaynet.Commands {
    public class RelayChallengeResponse : BitseryObject {

        public RelayStatus Status { get; private set; }

        public byte[] NtlmChallengeData { get; private set; } = new byte[] { };


        public RelayChallengeResponse(RelayStatus status) {
            Status = status;
        }

        public RelayChallengeResponse(byte[] ntlmChallenge) {
            NtlmChallengeData = ntlmChallenge;
            Status = RelayStatus.Forward;
        }

        public override void Write(BitseryWriter output) {
            output.Write((byte)Status);
            output.WritePrefixedBytes(NtlmChallengeData);
        }
    }
}
