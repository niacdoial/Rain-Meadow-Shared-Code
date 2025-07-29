using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using MonoMod.Utils;  // for WriteNullTerminatedString

namespace RainMeadow.Shared
{
    public class RouterModifyPlayerListPacket : Packet
    {
        public override Type type => Type.RouterModifyPlayerList;
        // Roles: any

        public ModifyPlayerListPacketOperation modifyOperation;
        public RouterPlayerId[] players;

        public RouterModifyPlayerListPacket() : base() { }
        public RouterModifyPlayerListPacket(ModifyPlayerListPacketOperation modifyOperation, BasicOnlinePlayer[] players) : base()
        {
            this.modifyOperation = modifyOperation;
            this.players = players.Select(x => (RouterPlayerId)x.id)
                                  .Where(x => x != null)
                                  .ToArray();
        }

        public override void Serialize(BinaryWriter writer)
        {
            writer.Write((byte)modifyOperation);

            var lanids = players.Where(x => x.endPoint != null && x.RoutingId != 0);

            bool includeme = lanids.FirstOrDefault(x => x.isLoopback()) is not null;
            if (includeme)
                lanids = lanids.Where(x => !x.isLoopback());
            var processingid = (RouterPlayerId)processingPlayer.id;
            UDPPeerManager.SerializeEndPoints(writer, lanids.Select(x => x.endPoint).ToArray(), processingid.endPoint, includeme);

            if (includeme)
                writer.Write(
                    ((RouterPlayerId) NetIOPlatform.mePlayer).RoutingId
                );
            foreach (RouterPlayerId id in lanids)
                writer.Write(id.RoutingId);

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
            var endpoints = UDPPeerManager.DeserializeEndPoints(reader, (processingPlayer.id as RouterPlayerId).endPoint);

            List<RouterPlayerId> routids = new List<RouterPlayerId>();
            foreach (IPEndPoint end in endpoints) {
                RouterPlayerId id = new RouterPlayerId();
                id.endPoint = end;
                id.RoutingId = reader.ReadUInt64();
                routids.Add(id);
            }
            players = routids.ToArray();

            if (modifyOperation == ModifyPlayerListPacketOperation.Add) {
                for (int i = 0; i < players.Length; i++){
                    players[i].name = reader.ReadNullTerminatedString();
                }
            }

            else if (modifyOperation == ModifyPlayerListPacketOperation.Remove) {
                for (int i = 0; i < players.Length; i++){
                    players[i].name = "PLAYER_UNDERGOING_REMOVAL";
                }
// #if IS_SERVER
//                 players = routids.Select(x => LobbyServer.GetLobbyPlayer(x)).Where(x => x != null).ToArray();
// #else
//                 RouterMatchmakingManager matchmaker = MatchmakingManager.routerInstance;
//                 players = routids.Select(x => matchmaker.GetPlayerRouter(x)).ToArray();
// #endif
            }
        }

        public override void Process()
        {
            // uses: for ModifyPlayerListPacketOperation.Add
            // Host -> Server: normal meaning: keeping track of the player list
            // Server -> Host: inform of an incoming player
            // Host -> Player: normal meaning
            // Server -> Player: normal meaning plus ack to ask the host
            // Player -> Host, Player -> Player: invalid use
            // Player -> Server: invalid use for both Add and Remove

// #if IS_SERVER
//             if ((RouterPlayerId)processingPlayer.id != (RouterPlayerId)LobbyServer.lobby.host) {
//                 SharedCodeLogger.Error("received RouterModifyPlayerListPacket from wrong source...");
//                 SharedCodeLogger.Debug("lobby host: %" + ((RouterPlayerId)LobbyServer.lobby.host).RoutingId.ToString());
//                 SharedCodeLogger.Debug("processing: %" + ((RouterPlayerId)processingPlayer.id).RoutingId.ToString());
//                 return;
//             }
//             switch (modifyOperation)
//             {
//                 case ModifyPlayerListPacketOperation.Add:
//                     SharedCodeLogger.Debug("Adding players...\n\t" + string.Join<OnlinePlayer>("\n\t", players));
//                     for (int i = 0; i < players.Length; i++) {
//                         LobbyServer.lobbyPlayers.Add((OnlinePlayer) players[i]);
//                     }
//                     break;

//                 case ModifyPlayerListPacketOperation.Remove:
//                     SharedCodeLogger.Debug("Removing players...\n\t" + string.Join<OnlinePlayer>("\n\t", players));
//                     for (int i = 0; i < players.Length; i++) {
//                         LobbyServer.lobbyPlayers.Remove((OnlinePlayer)players[i]);  // TODO: manage owner rotation
//                     }
//                     break;
//             }
// #else
//             switch (modifyOperation)
//             {
//                 case ModifyPlayerListPacketOperation.Add:
//                     if (((RouterPlayerId)processingPlayer.id).isServer()) {
//                         if (OnlineManager.lobby?.isOwner ?? false) {
//                             // in the future, maybe ensure incoming players have talked to the matchmaking server first
//                             // (in other words: ensure this codepath is hit before they arrive)
//                             foreach (OnlinePlayer player in players) {
//                                 NetIO.routerInstance.SendAcknoledgement(player); // pierce NAT
//                                 MatchmakingManager.routerInstance.AcknoledgeRouterPlayer(player);  // TODO: maybe this is a little early to announce this to everyone
//                             }
//                         } else {
//                             MatchmakingManager.routerInstance.OnLobbyInfoSubmitted(players.ToArray());
//                         }
//                     } else {
//                         if (OnlineManager.lobby == null) {
//                             return;
//                         }
//                         if (OnlineManager.lobby.isOwner || ((RouterPlayerId)OnlineManager.lobby.owner.id) != ((RouterPlayerId)processingPlayer.id)) {
//                             SharedCodeLogger.Error("cheeky user is trying to force-introduce themselves!");
//                             return;
//                         }
//                         for (int i = 0; i < players.Length; i++)
//                         {
//                             if (((RouterPlayerId)players[i].id).isLoopback()) {
//                                 // That's me
//                                 // move the existing "me" entry there rather than adding a new "me" entry without isMe flag.
//                                 OnlineManager.players.Remove(OnlineManager.mePlayer);
//                                 OnlineManager.players.Add(OnlineManager.mePlayer);
//                                 continue;
//                             }

//                             MatchmakingManager.routerInstance.AcknoledgeRouterPlayer(players[i]);
//                         }
//                     }
//                     break;

//                 case ModifyPlayerListPacketOperation.Remove:
//                     if (((RouterPlayerId)processingPlayer.id).isServer()) {
//                         SharedCodeLogger.Error("received player removal notice from server: this isn't supposed to happen");
//                     }
//                     SharedCodeLogger.Debug("Removing players...\n\t" + string.Join<OnlinePlayer>("\n\t", players));
//                     for (int i = 0; i < players.Length; i++)
//                     {
//                         MatchmakingManager.routerInstance.RemoveRouterPlayer(players[i]);
//                     }
//                     break;
//             }
// #endif
        }
    }
}
