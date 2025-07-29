using System.IO;
using System;

namespace RainMeadow.Shared
{
    public class RouterAcceptPublishPacket : Packet
    {
        public override Type type => Type.RouterAcceptPublish;
        // Role: S->H

        public ulong lobbyId;

        public RouterAcceptPublishPacket(): base() {}
        public RouterAcceptPublishPacket(ulong lobbyId)
        {
            this.lobbyId = lobbyId;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(lobbyId);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            lobbyId = reader.ReadUInt64();
        }

//         public override void Process() {
// #if IS_SERVER
//             throw new Exception("This function must only be called player-side");
// #else
//             if (MatchmakingManager.currentDomain != MatchmakingManager.MatchMakingDomain.Router) return;
//             if (OnlineManager.lobby != null) {
//                 if (OnlineManager.lobby.isOwner) {
//                     SharedCodeLogger.DebugMe();
//                     RouterMatchmakingManager matchmaker = MatchmakingManager.routerInstance;
//                     matchmaker.OnLobbyPublished(lobbyId);
//                 }
//             }
// #endif
//         }
    }
}
