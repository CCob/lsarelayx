using Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ntlmrelaynet.Negotiate {

    /*
         NegHints ::= SEQUENCE {
                 hintName[0] GeneralString OPTIONAL,
                 hintAddress[1] OCTET STRING OPTIONAL
         }
         NegTokenInit2 ::= SEQUENCE {
                 mechTypes[0] MechTypeList OPTIONAL,
                 reqFlags [1] ContextFlags OPTIONAL,
                 mechToken [2] OCTET STRING OPTIONAL,
                 negHints [3] NegHints OPTIONAL,
                 mechListMIC [4] OCTET STRING OPTIONAL,
                 ...
         }
     */

    [Flags]
    public enum ContextFlags {
        Delegation,
        Mutual,
        Replay,
        Sequence,
        Anonymous,
        Confidentiality,
        Integrity
    }

    public class NegTokenInit  {

        static Oid SPNEGOASNOneSpec = new Oid("1.3.6.1.5.5.2", "SPNEGOASNOneSpec");
        static string NotDefinedInRFC4718_PleaseIgnore = "not_defined_in_RFC4178@please_ignore";

        public Oid SPNegoSpec;
        public List<Oid> MechTypes = new List<Oid>();
        public ContextFlags ReqFlags;
        public byte[] MechToken;
        public byte[] MechListMIC;
        public string NegHints;

        public NegTokenInit() {

        }

        public NegTokenInit(AsnElt body)  {

            if (body.Sub == null || body.Sub.Length != 2 || body.Sub[1].TagValue > 1)
                throw new FormatException("Choice of negTokenInit[0] or negTokenResp[1] expected");

            SPNegoSpec = new Oid(body.Sub[0].GetOID(), "SPNEGOASNOneSpec");

            if (!SPNegoSpec.Value.Equals(SPNEGOASNOneSpec.Value)) {
                throw new FormatException($"Unexpected SPNEGOASNOneSpec OID received {SPNegoSpec}");
            }

            ParseBody(body.Sub[1]);
        }

        public void ParseBody(AsnElt body) {

            if (body.TagValue != 0 && body.Sub[0].TagClass != AsnElt.SEQUENCE) {
                throw new FormatException($"Expected negTokenInit CHOICE with value 0 as SEQUENCE, got {body.TagValue}");
            }

            foreach (AsnElt s in body.Sub[0].Sub) {

                switch (s.TagValue) {
                    case 0:
                        
                        if (s.Sub[0].TagValue != AsnElt.SEQUENCE)
                            throw new FormatException("Expected SEQUENCE of Oid");

                        foreach (AsnElt mech in s.Sub[0].Sub) {
                            MechTypes.Add(new Oid(mech.GetOID()));
                        }

                        break;
                    case 1:
                        ReqFlags = (ContextFlags)s.GetOctetString()[0];
                        break;
                    case 2:
                        MechToken = s.Sub[0].GetOctetString();
                        break;
                    case 3:

                        NegHints = s.Sub[0].Sub[0].Sub[0].GetString(AsnElt.UTF8String);
                        if(NegHints != NotDefinedInRFC4718_PleaseIgnore) {
                            throw new FormatException($"Unexpected NegHints value {NegHints}");
                        }
                        break;

                    default:
                        throw new FormatException($"Unexpected tag {s.TagValue} found in ASN.1 body");

                }
            }
        }

        public byte[] Encode() {

            //On encoding we don't bother with negHints/mechListMIC as these are different depending on if we are encoding
            //a NegoInit or NegoInit2 object.  There for we will leave them out and the resulting ASN.1 will be compatible with both.
            
            AsnElt negInitSequence;
            var mechTypesSeq = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.SEQUENCE, MechTypes.Select(mt => AsnElt.MakeOID(mt.Value)).ToArray());

            if(MechToken == null) {
                negInitSequence = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, mechTypesSeq),
                });
            } else {
                negInitSequence = AsnElt.Make(AsnElt.UNIVERSAL, AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, mechTypesSeq),
                    AsnElt.MakeExplicit(AsnElt.CONTEXT, 2, AsnElt.MakeBlob(MechToken)) ,
                });
            }          
           
            return AsnElt.Make(AsnElt.APPLICATION, 0, new AsnElt[] {
                AsnElt.MakeOID(SPNEGOASNOneSpec.Value),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, negInitSequence),
            }).Encode();
        }
    }
}
