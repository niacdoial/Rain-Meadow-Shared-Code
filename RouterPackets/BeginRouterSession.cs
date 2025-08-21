using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class BeginRouterSession : Packet
    {
        public override Type type => Type.BeginRouterSession;
        public bool exposeIPAddress;

        public BeginRouterSession() { }
        public BeginRouterSession(bool exposeIPAddress)
        {
            this.exposeIPAddress = exposeIPAddress;
        }
            
        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(exposeIPAddress);
        } 
        
        public override void Deserialize(BinaryReader reader)
        {
            exposeIPAddress = reader.ReadBoolean();
        }

        static public event Action<BeginRouterSession>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}