using System;
using System.IO;
using MonoMod.Utils;  // for WriteNullTerminatedString

namespace RainMeadow.Shared
{
    public class RouterRequestLobbyPacket : Packet
    {
        public override Type type => Type.RouterRequestLobby;
        // Role: P->S

        public string meadowVersion = "";

        public RouterRequestLobbyPacket() {}
        public RouterRequestLobbyPacket(string version) {
            meadowVersion = version;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.WriteNullTerminatedString(meadowVersion);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            meadowVersion = reader.ReadNullTerminatedString();
        }

//         public override void Process() {
// #if IS_SERVER
//             // TODO: use version string
//             if (false) { //(UDPPeerManager.isEndpointLocal(((RouterPlayerId)processingPlayer.id).endPoint)) {
//                 LobbyServer.netIo.SendP2P(
//                     processingPlayer,
//                     new RouterGenericFailurePacket("Cannot route players with local-network addresses!"),
//                     NetIO.SendType.Reliable
//                 );
//             } else {
//                 if (LobbyServer.lobby != null) {
//                     LobbyServer.netIo.SendP2P(processingPlayer, new RouterInformLobbyPacket(
//                         (ulong)1,
//                         LobbyServer.maxPlayers,
//                         LobbyServer.lobby.name,
//                         LobbyServer.lobby.hasPassword,
//                         LobbyServer.lobby.mode,
//                         LobbyServer.lobbyPlayers.Count,
//                         LobbyServer.lobby.requiredMods,
//                         LobbyServer.lobby.bannedMods
//                     ), NetIO.SendType.Reliable);
//                 } else {
//                     LobbyServer.netIo.SendAcknoledgement(processingPlayer);
//                 }
//             }
// #else
//             throw new Exception("This function must only be called server-side");
// #endif
//         }
    }
}
