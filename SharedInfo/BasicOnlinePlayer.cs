using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace RainMeadow.Shared
{
    public partial class BasicOnlinePlayer : IEquatable<BasicOnlinePlayer>
    {
        public MeadowPlayerId id; // big id for matchmaking
        public ushort inLobbyId; // small id in lobby serialization

        public bool needsAck;
        public bool isMe;
        public bool hasLeft;

        public BasicOnlinePlayer(MeadowPlayerId id) {
            this.id = id;
        }

        public override string ToString()
        {
            return $"{inLobbyId}:{id}";
        }

        public override bool Equals(object obj) => this.Equals(obj as BasicOnlinePlayer);
        public bool Equals(BasicOnlinePlayer other) {
            return other != null && id == other.id;
        }
        public override int GetHashCode() => id.GetHashCode();
        public virtual string GetUniqueID() {
            if (id is RouterPlayerId routid) {
                return routid.RoutingId.ToString();
            } else if (id is LANPlayerId) {
                return inLobbyId.ToString();
            } else if (id is NetPlayerId) {
                return inLobbyId.ToString();
            } else {
                throw new Exception("Unknown MeadowPlayerId type");
            }
        }
        public static bool operator ==(BasicOnlinePlayer lhs, BasicOnlinePlayer rhs)
        {
            return lhs is null ? rhs is null : lhs.Equals(rhs);
        }
        public static bool operator !=(BasicOnlinePlayer lhs, BasicOnlinePlayer rhs) => !(lhs == rhs);
    }
}
