using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class JoinRouterLobby : Packet
    {
        public override Type type => Type.JoinRouterLobby;
            
        public override void Serialize(BinaryWriter writer)
        {

        } 
        
        public override void Deserialize(BinaryReader reader)
        {

        }

        static public event Action<JoinRouterLobby>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}