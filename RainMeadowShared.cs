using System.Net;

namespace RainMeadow.Shared {
    class SharedPlatform
    {
        // Blackhole Endpoint
        // https://superuser.com/questions/698244/ip-address-that-is-the-equivalent-of-dev-null
        public static readonly IPEndPoint BlackHole = new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999);

        // settings
        public static ulong heartbeatTime = 50;
        public static ulong timeoutTime = 5_000; 
        public const string MeadowNetcodeVersionStr = "0.1.5.1";

    }
}
