using System;
using System.IO;

namespace RainMeadow.Shared
{
    public class RouteSessionData : RoutePacket
    {
        // always used in player-to-player communication

        public override Type type => Type.RouteSessionData;
        public ArraySegment<byte> data;

        public RouteSessionData() { }
        public RouteSessionData(ushort toRouterID, ushort fromRouterID, ArraySegment<byte> data) : base(toRouterID, fromRouterID)
        {
            this.data = data;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(data.Array, data.Offset, data.Count);
        }

        public override void Deserialize(BinaryReader reader)
        {
            long orig = reader.BaseStream.Position;
            base.Deserialize(reader);
            data = new ArraySegment<byte>(reader.ReadBytes((int)(size-(reader.BaseStream.Position-orig))));
        }

        static public event Action<RouteSessionData>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
