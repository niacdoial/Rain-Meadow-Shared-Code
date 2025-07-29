using System;
using System.Net;
//using Menu;

namespace RainMeadow.Shared
{
    // TODO: deal with ICustomSerializable after
    public abstract class MeadowPlayerId : IEquatable<MeadowPlayerId>  //, Serializer.ICustomSerializable
    {
        public string name = "UNSET_PLAYER_NAME";

        public virtual string GetPersonaName() { return name; }

        // public virtual void OpenProfileLink() {
        //     OnlineManager.instance.manager.ShowDialog(new DialogNotify(Utils.Translate("This player does not have a profile."), OnlineManager.instance.manager, null));
        // }

        public virtual bool canOpenProfileLink { get => false; }
        public virtual void OpenProfileLink() {
            SharedCodeLogger.Error("This player does not have a profile.");
        }

        protected MeadowPlayerId() { }
        protected MeadowPlayerId(string name)
        {
            this.name = name;
        }

        //public abstract void CustomSerialize(Serializer serializer);

        public abstract bool Equals(MeadowPlayerId other);
        public override bool Equals(object obj)
        {
            return Equals(obj as MeadowPlayerId);
        }
        public abstract override int GetHashCode();
        public override string ToString()
        {
            return name;
        }
        public static bool operator ==(MeadowPlayerId lhs, MeadowPlayerId rhs)
        {
            return lhs is null ? rhs is null : lhs.Equals(rhs);
        }
        public static bool operator !=(MeadowPlayerId lhs, MeadowPlayerId rhs) => !(lhs == rhs);
    }

    public abstract class NetPlayerId : MeadowPlayerId {
        public IPEndPoint endPoint;
        public NetPlayerId(): base() { endPoint = NetIOPlatform.BlackHole; }
        public NetPlayerId(IPEndPoint? endPoint) : base(
            UsernameGenerator.GenerateRandomUsername(endPoint?.GetHashCode() ?? 0)
        ) {
            this.endPoint = endPoint ?? NetIOPlatform.BlackHole;
        }
    }

    public class RouterPlayerId : NetPlayerId {
        public ulong RoutingId = 0;

        public RouterPlayerId(): base() {}
        public RouterPlayerId(ulong id = 0): base() { RoutingId = id; }

        override public int GetHashCode() { unchecked { return (int)RoutingId; } }

        // override public void CustomSerialize(Serializer serializer) {
        //     serializer.Serialize(ref RoutingId);
        // }

        public bool isLoopback() {
            return this.Equals(NetIOPlatform.mePlayer);
        }
        public bool isServer() {
            return RoutingId == 0xffff_ffff_ffff_ffff;
        }

        public override bool Equals(MeadowPlayerId other) {
            if (other is RouterPlayerId other_router_id) {
                return RoutingId == other_router_id.RoutingId;
            }
            return false;
        }
    }


    public class LANPlayerId : NetPlayerId
    {

        public LANPlayerId(IPEndPoint? endPoint): base(endPoint) {}

        public void reset() {
            this.endPoint = NetIOPlatform.BlackHole;
        }

        public override int GetHashCode() {
            return this.endPoint?.GetHashCode() ?? 0;
        }

        // public override void CustomSerialize(Serializer serializer)
        // {
        //     if (serializer.IsWriting) {
        //         if (this.isLoopback()) {
        //             serializer.writer.Write(true);
        //         } else {
        //             serializer.writer.Write(false);
        //             serializer.writer.Write((int)endPoint.Port);
        //             serializer.writer.Write((int)endPoint.Address.GetAddressBytes().Length);
        //             serializer.writer.Write(endPoint.Address.GetAddressBytes());
        //         }
        //     } else if (serializer.IsReading) {
        //         bool issender = serializer.reader.ReadBoolean();
        //         if (issender) {
        //             this.endPoint = (serializer.currPlayer.id as LANPlayerId)?.endPoint ?? NetIOPlatform.BlackHole;
        //         } else {
        //             int port = serializer.reader.ReadInt32();
        //             byte[] endpointbytes = serializer.reader.ReadBytes(serializer.reader.ReadInt32());
        //             this.endPoint = new IPEndPoint(new IPAddress(endpointbytes), port);
        //         }
        //     }
        // }

        public bool isLoopback() {
            if (NetIOPlatform.PlatformUDPManager.port != endPoint?.Port) return false;
            return UDPPeerManager.isLoopback(endPoint.Address);
        }

        public override bool Equals(MeadowPlayerId other)
        {
            if (other is LANPlayerId lanid) {
                return UDPPeerManager.CompareIPEndpoints(endPoint, lanid.endPoint);
            }
            return false;
        }
    }

    // public class SteamPlayerId : MeadowPlayerId
    // {
    //     public CSteamID steamID;
    //     public SteamNetworkingIdentity oid;

    //     public SteamPlayerId() { }
    //     public SteamPlayerId(CSteamID steamID) : base(SteamFriends.GetFriendPersonaName(steamID) ?? string.Empty)
    //     {
    //         this.steamID = steamID;
    //         oid = new SteamNetworkingIdentity();
    //         oid.SetSteamID(steamID);
    //     }

    //     // public override void CustomSerialize(Serializer serializer)
    //     // {
    //     //     serializer.Serialize(ref steamID.m_SteamID);
    //     // }

    //     public override bool Equals(MeadowPlayerId other)
    //     {
    //         return other is SteamPlayerId otherS && steamID == otherS.steamID;
    //     }

    //     public override int GetHashCode()
    //     {
    //         return steamID.GetHashCode();
    //     }

    //     public override string GetPersonaName() {
    //         return SteamFriends.GetFriendPersonaName(steamID);
    //     }

    //     // public override bool canOpenProfileLink { get => true; }
    //     // public override void OpenProfileLink() {
    //     //     string url = $"https://steamcommunity.com/profiles/{steamID}";
    //     //     SteamFriends.ActivateGameOverlayToWebPage(url);
    //     // }
    // }


}
