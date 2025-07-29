using System;

namespace RainMeadow.Shared
{
    public class LANRequestLobbyPacket : Packet
    {
        public override Type type => Type.LANRequestLobby;

//         public override void Process() {
// #if IS_SERVER
//             throw new Exception("This function must only be called player-side");
// #else
//             if (MatchmakingManager.currentDomain != MatchmakingManager.MatchMakingDomain.LAN) return;
//             if (OnlineManager.lobby != null) {
//                 SharedCodeLogger.DebugMe();
//                 (MatchmakingManager.instances[MatchmakingManager.MatchMakingDomain.LAN] as LANMatchmakingManager).SendLobbyInfo(processingPlayer);
//             }
// #endif
//         }
    }
}
