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
            this.size = (ushort)(size +4);  // +4 because we added 2×u16 to the payload
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(key);
            writer.Write(data, 0, size-4);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            key = reader.ReadString();
            data = reader.ReadBytes(size-4);
        }

        static public event Action<RouterCustomPacket>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
