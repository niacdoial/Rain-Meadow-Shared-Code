using System.Net;

namespace RainMeadow.Shared {
    class NetIOPlatform {
        // Blackhole Endpoint
        // https://superuser.com/questions/698244/ip-address-that-is-the-equivalent-of-dev-null
        public static readonly IPEndPoint BlackHole = new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999);

        public static UDPPeerManager? PlatformUDPManager { get; } = new();
        public static MeadowPlayerId mePlayer;

        // settings
        public static ulong heartbeatTime = 50; //(ulong)RainMeadow.rainMeadowOptions.UdpHeartbeat.Value;
        public static ulong timeoutTime = 5_000; //(ulong)RainMeadow.rainMeadowOptions.UdpTimeout.Value;

        public const string MeadowNetcodeVersionStr = "0.1.5.1";

    }
}
