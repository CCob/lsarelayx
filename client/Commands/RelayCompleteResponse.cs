namespace ntlmrelaynet.Commands {

    public class RelayCompleteResponse : BitseryObject {

        public RelayStatus Status { get; private set; }
        public string Workstation { get; private set; }
        public UserInfo UserInfo { get; private set; } 

        public RelayCompleteResponse(RelayStatus status) {
            Status = status;
        }

        public RelayCompleteResponse(RelayStatus status, string workstation, UserInfo userInfo) {
            Status = status;
            Workstation = workstation;
            UserInfo = userInfo;
        }

        public override void Write(BitseryWriter output) {
            output.Write((byte)Status);
            output.WritePrefixedString(Workstation);
            UserInfo.Write(output);      
        }
    }
}
