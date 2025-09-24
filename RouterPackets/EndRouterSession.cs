using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class EndRouterSession : Packet
    {
        // always used as a server->player packet

        public EndRouterSession() { }

        public override Type type => Type.EndRouterSession;

        static public event Action<EndRouterSession>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
