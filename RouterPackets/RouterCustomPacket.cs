using System;
using System.IO;

namespace RainMeadow.Shared
{
    public class RouterCustomPacket : RoutePacket
    {
        // always used in player-to-player communication

        public override Type type => Type.RouterCustomPacket;
        public string key = "";
        public byte[] data;

        public RouterCustomPacket() { }
        public RouterCustomPacket(ushort toRouterID, ushort fromRouterID, string key, byte[] data, ushort size) : base(toRouterID, fromRouterID)
        {
            this.key = key;
            this.data = data;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(key);
            writer.Write(data);
        }

        public override void Deserialize(BinaryReader reader)
        {
            long orig = reader.BaseStream.Position;
            base.Deserialize(reader);
            key = reader.ReadString();
            data = reader.ReadBytes((int)(size-(reader.BaseStream.Position-orig)));
        }

        static public event Action<RouterCustomPacket>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
