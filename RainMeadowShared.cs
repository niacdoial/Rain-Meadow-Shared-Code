using System.Net;

namespace RainMeadow.Shared {
    static partial class SharedPlatform
    {
        // Blackhole Endpoint
        // https://superuser.com/questions/698244/ip-address-that-is-the-equivalent-of-dev-null
        public static readonly IPEndPoint BlackHole = new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999);

        // settings
        public static ulong heartbeatTime
        {
            get
            {
                ulong time = 0; getHeartBeatTime(ref time);
                return time;
            }
        }
        public static ulong timeoutTime
        {
            get
            {
                ulong time = 0; getTimeoutTime(ref time);
                return time;
            }
        }

        public static ulong TimeMS
        {
            get
            {
                ulong time = 0; getTimeMS(ref time);
                return time;
            }
        }

        static partial void getHeartBeatTime(ref ulong heartbeatTime);
        static partial void getTimeoutTime(ref ulong TimeoutTime); 
        static partial void getTimeMS(ref ulong time); 
    }
}
