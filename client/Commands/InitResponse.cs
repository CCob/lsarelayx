using System.Runtime.InteropServices;

namespace ntlmrelaynet.Commands {
 
    public class InitResponse : BitseryObject  {

        public RelayStatus Status { get; private set; } = RelayStatus.Ok;
        public long InitLsaContextOffset { get; set; }
        public long AcceptLsaContextOffset { get; set; }
        public long QueryLsaContextOffset { get; set; }
        public long DeleteLsaSeContextOffset { get; set; }
        public long QueryLsaCredOffset { get; set; }
        public long SpmpLookupPackageOffset { get; set; }

        public InitResponse() {
        }
        public InitResponse(long initLsaContextOffset, long acceptLsaContextOffset, long queryLsaContextOffset, long deleteSecurityContext, long queryLsaCredOffset, long spmpLookupPackageOffset) {
            InitLsaContextOffset = initLsaContextOffset;
            AcceptLsaContextOffset = acceptLsaContextOffset;
            QueryLsaContextOffset = queryLsaContextOffset;
            DeleteLsaSeContextOffset = deleteSecurityContext;
            QueryLsaCredOffset = queryLsaCredOffset;
            SpmpLookupPackageOffset = spmpLookupPackageOffset;
        }

        public override void Write(BitseryWriter output) {
            output.Write((byte)Status);
            output.Write(InitLsaContextOffset);
            output.Write(AcceptLsaContextOffset);
            output.Write(QueryLsaContextOffset);
            output.Write(DeleteLsaSeContextOffset);
            output.Write(QueryLsaCredOffset);
            output.Write(SpmpLookupPackageOffset);
        }
    }
}
