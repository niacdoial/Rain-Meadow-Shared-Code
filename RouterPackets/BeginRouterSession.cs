using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class BeginRouterSession : Packet
    {
        // always used as a player->server packet
        public override Type type => Type.BeginRouterSession;
        public bool exposeIPAddress;
        public string name;
        public string? gameliftID;

        public BeginRouterSession() { }
        public BeginRouterSession(bool exposeIPAddress, string name, string? gameliftID)
        {
            this.exposeIPAddress = exposeIPAddress;
            this.name = name;
            this.gameliftID = gameliftID;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(exposeIPAddress);
            writer.Write(name);

            writer.Write(gameliftID is not null);
            if (gameliftID is not null) writer.Write(gameliftID);
            
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            exposeIPAddress = reader.ReadBoolean();
            name = reader.ReadString();
            gameliftID = reader.ReadBoolean()? reader.ReadString() : null;
        }

        static public event Action<BeginRouterSession>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
