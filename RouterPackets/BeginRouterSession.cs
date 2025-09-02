using System;
using System.IO;
using System.Net;
using MonoMod.Utils;

namespace RainMeadow.Shared
{
    public class BeginRouterSession : Packet
    {
        // always used as a player->server packet
        public override Type type => Type.BeginRouterSession;
        public bool exposeIPAddress;
        public string name;

        public BeginRouterSession() { }
        public BeginRouterSession(bool exposeIPAddress, string name)
        {
            this.exposeIPAddress = exposeIPAddress;
            this.name = name;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(exposeIPAddress);
            writer.WriteNullTerminatedString(name);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            exposeIPAddress = reader.ReadBoolean();
            name = reader.ReadNullTerminatedString();
        }

        static public event Action<BeginRouterSession>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
