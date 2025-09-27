using System;
using System.IO;

namespace RainMeadow.Shared
{
    public class RouterCustomPacket : Packet
    {
        // always used in player-to-player communication

        public override Type type => Type.RouterCustomPacket;
        public ushort fromRouterID;
        public ushort toRouterID;
        public string key = "";
        public byte[] data;

        public RouterCustomPacket() { }
        public RouterCustomPacket(ushort toRouterID, ushort fromRouterID, string key, byte[] data, ushort size)
        {
            this.toRouterID = toRouterID;
            this.fromRouterID = fromRouterID;
            this.key = key;
            this.data = data;
            this.size = (ushort)(size +4);  // +4 because we added 2×u16 to the payload
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(toRouterID);
            writer.Write(fromRouterID);
            writer.Write(key);
            writer.Write(data, 0, size-4);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            toRouterID = reader.ReadUInt16();
            fromRouterID = reader.ReadUInt16();
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
