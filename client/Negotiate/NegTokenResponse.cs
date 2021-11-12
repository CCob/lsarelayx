using Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ntlmrelaynet.Negotiate {

    /*
        NegTokenResp ::= SEQUENCE {
        negState       [0] ENUMERATED {
            accept-completed    (0),
            accept-incomplete   (1),
            reject              (2),
            request-mic         (3)
        }                                 OPTIONAL,
        -- REQUIRED in the first reply from the target
        supportedMech   [1] MechType      OPTIONAL,
        -- present only in the first reply from the target
        responseToken   [2] OCTET STRING  OPTIONAL,
        mechListMIC     [3] OCTET STRING  OPTIONAL,
        ...
      }
    */

    public enum State {
        AcceptCompleted,
        AcceptIncomplete,
        Reject,
        RequestMic
    }


    public class NegTokenResponse  {

        public State NegState;
        public Oid SupportedMech;
        public byte[] ResponseToken;
        public byte[] MechListMIC;

        public NegTokenResponse(State negState, Oid supportedMech) : this(negState, supportedMech, null) {}

        public NegTokenResponse(State negState, Oid supportedMech, byte[] responseToken) {
            NegState = negState;
            SupportedMech = supportedMech;
            ResponseToken = responseToken;
        }

        public NegTokenResponse(AsnElt body)  {

            if (body.TagValue != 1 && body.Sub != null && body.Sub[0].TagClass != AsnElt.SEQUENCE) {
                throw new FormatException($"Expected negTokenResponse SEQUENCE, got {body.TagClass}");
            }

            foreach (AsnElt s in body.Sub[0].Sub) {

                switch (s.TagValue) {
                    case 0:
                        NegState = (State)s.Sub[0].GetInteger();                  
                        break;
                    case 1:
                        SupportedMech = new Oid(s.Sub[0].GetOID());               
                        break;
                    case 2:
                        ResponseToken = s.Sub[0].GetOctetString();
                        break;
                    case 3:
                        MechListMIC = s.Sub[0].GetOctetString();
                        break;
                    default:
                        throw new FormatException($"Unexpected tag {s.TagValue} found in ASN.1 body");

                }
            }
        }

        public byte[] Encode() {

            AsnElt negResponseSequence = null;

            if (ResponseToken != null) {
                negResponseSequence = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.Make(AsnElt.CONTEXT, 0, AsnElt.MakePrimitive(AsnElt.UNIVERSAL,AsnElt.ENUMERATED, new byte[]{(byte)NegState})),
                    AsnElt.Make(AsnElt.CONTEXT, 1, AsnElt.MakeOID(SupportedMech.Value)),
                    AsnElt.Make(AsnElt.CONTEXT, 2, AsnElt.MakeBlob(ResponseToken))
                });
            } else {
                negResponseSequence = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.Make(AsnElt.CONTEXT, 0, AsnElt.MakePrimitive(AsnElt.UNIVERSAL,AsnElt.ENUMERATED, new byte[]{(byte)NegState})),
                    AsnElt.Make(AsnElt.CONTEXT, 1, AsnElt.MakeOID(SupportedMech.Value))
                });

            }

            return AsnElt.Make(AsnElt.CONTEXT, 1, negResponseSequence).Encode();
        }     
    }
}
