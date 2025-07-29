using System;
using System.Net;

namespace RainMeadow.Shared
{
    // trimmed down version for listing lobbies in menus
    public abstract class LobbyInfo
    {
        public string name;
        public string mode;
        public int playerCount;
        public bool hasPassword;
        public int maxPlayerCount;
        public string requiredMods;
        public string bannedMods;

        public LobbyInfo(string name, string mode, int playerCount, bool hasPassword, int? maxPlayerCount, string highImpactMods = "", string bannedMods = "")
        {
            this.name = name;
            this.mode = mode;
            this.playerCount = playerCount;
            this.hasPassword = hasPassword;
            this.maxPlayerCount = (int)maxPlayerCount;
            this.requiredMods = highImpactMods;
            this.bannedMods = bannedMods;
        }

        public abstract string GetLobbyJoinCode(string? password = null);

    }


    public class INetLobbyInfo : LobbyInfo {
        public MeadowPlayerId host;
        public ulong lobbyId = 0;  // TODO: maybe more separation than that?
        public INetLobbyInfo(MeadowPlayerId host, string name, string mode, int playerCount, bool hasPassword, int maxPlayerCount, string highImpactMods = "", string bannedMods = "") :
            base(name, mode, playerCount, hasPassword, maxPlayerCount, highImpactMods, bannedMods) {
            this.host = host;
        }

        public override string GetLobbyJoinCode(string? password = null)
        {
            if (host is LANPlayerId pHost) {
                if (password != null)
                    return $"+connect_lan_lobby {pHost.endPoint.Address.Address} {pHost.endPoint.Port} +lobby_password {password}";
                return $"+connect_lan_lobby {pHost.endPoint.Address.Address} {pHost.endPoint.Port}";
            } else if (host is RouterPlayerId rHost) {
                if (password != null)
                    return $"+connect_router_lobby {this.lobbyId} {rHost.RoutingId} +lobby_password {password}";
                return $"+connect_router_lobby {this.lobbyId} {rHost.RoutingId}";
            } else {
                throw new Exception("wrong lobby type");
            }
        }
    }
}
