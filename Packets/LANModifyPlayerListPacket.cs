using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using MonoMod.Utils;  // for WriteNullTerminatedString

namespace RainMeadow.Shared
{
    public enum ModifyPlayerListPacketOperation : byte
    {
        Add,
        Remove,
    }
    public class LANModifyPlayerListPacket : Packet
    {
        public override Type type => Type.LANModifyPlayerList;

        public ModifyPlayerListPacketOperation modifyOperation;
        public LANPlayerId[] players;

        public LANModifyPlayerListPacket() : base() { }
        public LANModifyPlayerListPacket(ModifyPlayerListPacketOperation modifyOperation, BasicOnlinePlayer[] players) : base()
        {
            this.modifyOperation = modifyOperation;
            this.players = players.Select(x => (LANPlayerId)x.id).ToArray();
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write((byte)modifyOperation);
            var lanids = players.Where(x => x.endPoint != null);


            bool includeme = lanids.FirstOrDefault(x => x.isLoopback()) is not null;
            if (includeme)
                lanids = lanids.Where(x => !x.isLoopback());
            var processinglanid = (LANPlayerId)processingPlayer.id;
            UDPPeerManager.SerializeEndPoints(writer, lanids.Select(x => x.endPoint).ToArray(), processinglanid.endPoint, includeme);

            if (modifyOperation == ModifyPlayerListPacketOperation.Add) {
                if (includeme)
                    writer.WriteNullTerminatedString(NetIOPlatform.mePlayer.name);

                foreach (MeadowPlayerId id in lanids)
                    writer.WriteNullTerminatedString(id.name);
            }
        }

        public override void Deserialize(BinaryReader reader)
        {
            modifyOperation = (ModifyPlayerListPacketOperation)reader.ReadByte();
            var endpoints = UDPPeerManager.DeserializeEndPoints(reader, (processingPlayer.id as LANPlayerId).endPoint);
            players = endpoints.Select(x => new LANPlayerId(x)).ToArray();

            if (modifyOperation == ModifyPlayerListPacketOperation.Add) {
                for (int i = 0; i < players.Length; i++){
                    players[i].name = reader.ReadNullTerminatedString();
                }
            } else if (modifyOperation == ModifyPlayerListPacketOperation.Remove) {
                for (int i = 0; i < players.Length; i++){
                    players[i].name = "PLAYER_UNDERGOING_REMOVAL";
                }
            }
        }

//         public override void Process()
//         {
// #if IS_SERVER
//             throw new Exception("This function must only be called player-side");
// #else
//             switch (modifyOperation)
//             {
//                 case ModifyPlayerListPacketOperation.Add:
//                     SharedCodeLogger.Debug("Adding players...\n\t" + string.Join<BasicOnlinePlayer>("\n\t", players));
//                     for (int i = 0; i < players.Length; i++)
//                     {
//                         if (((LANPlayerId)players[i].id).isLoopback()) {
//                             // That's me
//                             // Put me where I belong. (...at the end of the player list?)
//                             OnlineManager.players.Remove(OnlineManager.mePlayer);
//                             OnlineManager.players.Add(OnlineManager.mePlayer);
//                             continue;
//                         }

//                         (MatchmakingManager.instances[MatchmakingManager.MatchMakingDomain.LAN] as LANMatchmakingManager).AcknoledgeLANPlayer(players[i]);
//                     }
//                     break;

//                 case ModifyPlayerListPacketOperation.Remove:
//                     SharedCodeLogger.Debug("Removing players...\n\t" + string.Join<BasicOnlinePlayer>("\n\t", players));
//                     for (int i = 0; i < players.Length; i++)
//                     {
//                         (MatchmakingManager.instances[MatchmakingManager.MatchMakingDomain.LAN] as LANMatchmakingManager).RemoveLANPlayer(players[i]);
//                     }
//                     break;
//             }
// #endif
//         }
    }
}
