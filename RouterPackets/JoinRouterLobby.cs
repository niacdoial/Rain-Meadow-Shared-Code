using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class JoinRouterLobby : Packet
    {
        public ushort yourRoutingID;
        public JoinRouterLobby() { }

        public JoinRouterLobby(ushort yourRoutingID)
        {
            this.yourRoutingID = yourRoutingID;
        }

        public override Type type => Type.JoinRouterLobby;
            
        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(yourRoutingID);
        } 
        
        public override void Deserialize(BinaryReader reader)
        {
            yourRoutingID = reader.ReadUInt16();
        }

        static public event Action<JoinRouterLobby>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}