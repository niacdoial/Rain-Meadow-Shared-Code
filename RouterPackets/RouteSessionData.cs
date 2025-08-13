using System;
using System.IO;

namespace RainMeadow.Shared
{
    public class RouteSessionData : Packet
    {
        public override Type type => Type.RouteSessionData;
        public ushort processingRouterID;
        public byte[] data;

        public RouteSessionData() { }
        public RouteSessionData(ushort processingRouterID, byte[] data, ushort size)
        {
            this.processingRouterID = processingRouterID;
            this.data = data;
            this.size = (ushort)(size + sizeof(ushort));
        }
            
        public override void Serialize(BinaryWriter writer)
        {
            writer.Write(processingRouterID);
            writer.Write(data, 0, size - sizeof(ushort));
        }

        public override void Deserialize(BinaryReader reader)
        {
            processingRouterID = reader.ReadUInt16();
            data = reader.ReadBytes(size - sizeof(ushort));
        }

        static public event Action<RouteSessionData>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}