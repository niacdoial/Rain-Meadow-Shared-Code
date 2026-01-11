using System;
using System.IO;

namespace RainMeadow.Shared
{
    public class RouteSessionData : RoutePacket
    {
        // always used in player-to-player communication

        public override Type type => Type.RouteSessionData;
        public byte[] data;

        public RouteSessionData() { }
        public RouteSessionData(ushort toRouterID, ushort fromRouterID, byte[] data, ushort size) : base(toRouterID, fromRouterID)
        {
            this.data = data;
            this.size = (ushort)(size +4);  // +4 because we added 2×u16 to the payload
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(data, 0, size-4);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            data = reader.ReadBytes(size-4);
        }

        static public event Action<RouteSessionData>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
