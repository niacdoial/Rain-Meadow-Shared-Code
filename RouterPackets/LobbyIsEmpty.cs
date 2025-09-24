using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class LobbyIsEmpty : Packet
    {
        // always used as a server->player packet

        public LobbyIsEmpty() { }

        public override Type type => Type.LobbyIsEmpty;

        static public event Action<LobbyIsEmpty>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
