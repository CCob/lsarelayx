using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.DirectoryServices;

namespace ntlmrelaynet.Commands {

    public class UserNotFoundException : Exception {
    }


    public class UserInfo : BitseryObject {

        public string UserName { get; set; }
        public string Domain { get; set; }
        public int PrimaryGroupId { get; set; }
        public SecurityIdentifier SecurityIdentifier { get; set; }
        public DateTime LastLogon { get; set; }
        public DateTime LastLogoff { get; set; }
        public List<SecurityIdentifier> Groups { get; set; } = new List<SecurityIdentifier>();

        public UserInfo(string userName, string domain) {
            UserName = userName;
            Domain = domain;  
        }

        public bool PopulateFromLDAP() {

            try {

                using (var rootDse = new DirectoryEntry("LDAP://RootDSE")) {

                    var namingContext = rootDse.Properties["defaultNamingContext"].Value;

                    using (var parentEntry = new DirectoryEntry("LDAP://" + namingContext)) {
                        using (var directorySearch = new DirectorySearcher(parentEntry)) {
                            directorySearch.Filter = $"(sAMAccountName={UserName})";
                            directorySearch.PropertiesToLoad.Add("memberOf");
                            directorySearch.PropertiesToLoad.Add("objectSid");
                            directorySearch.PropertiesToLoad.Add("userAccountControl");
                            directorySearch.PropertiesToLoad.Add("primaryGroupId");
                            directorySearch.PropertiesToLoad.Add("lastLogon");
                            directorySearch.PropertiesToLoad.Add("lastLogoff");
                            var result = directorySearch.FindOne();

                            if (result == null) {
                                return false;
                            }

                            SecurityIdentifier = new SecurityIdentifier((byte[])result.Properties["ObjectSid"][0], 0);
                            PrimaryGroupId = (int)result.Properties["primaryGroupId"][0];
                            LastLogon = DateTime.FromFileTimeUtc((long)result.Properties["lastLogon"][0]);
                            LastLogoff = DateTime.FromFileTimeUtc((long)result.Properties["lastLogoff"][0]);
                            Groups = new List<SecurityIdentifier>();

                            //Add the impicit membership of "Domain Users" group
                            Groups.Add(new SecurityIdentifier(SecurityIdentifier.AccountDomainSid.ToString() + "-513"));

                            foreach (string group in result.Properties["memberOf"]) {

                                var groupSearch = new DirectorySearcher(parentEntry, $"(&(distinguishedName={group}))");
                                groupSearch.PropertiesToLoad.Add("objectSid");

                                var groupEntry = groupSearch.FindOne();

                                if (groupEntry == null)
                                    continue;

                                Groups.Add(new SecurityIdentifier((byte[])groupEntry.Properties["objectSid"][0], 0));
                            }
                        }
                    }
                }

            } catch (Exception) {
                return false;
            }

            return true;
        }

        public override void Write(BitseryWriter writer) {
            writer.WritePrefixedString(UserName);
            writer.WritePrefixedString(Domain);
            writer.WritePrefixedString(SecurityIdentifier != null ? SecurityIdentifier.ToString() : null);
            writer.WriteCompressedInt(Groups.Count);
            Groups.ForEach(g => writer.WritePrefixedString(g.ToString()));
        }
    }
}
