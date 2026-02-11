using System;
using System.IO;

namespace RainMeadow.Shared
{
    public abstract class RoutePacket : Packet
    {
        // For player-to-player communication

        public override Type type => Type.RouteSessionData;
        public ushort fromRouterID;
        public ushort toRouterID;
        public const ushort ROUTING_OVERHEAD = 4;
        public RoutePacket() { }
        public RoutePacket(ushort toRouterID, ushort fromRouterID)
        {
            this.toRouterID = toRouterID;
            this.fromRouterID = fromRouterID;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(toRouterID);
            writer.Write(fromRouterID);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            toRouterID = reader.ReadUInt16();
            fromRouterID = reader.ReadUInt16();
        }
    }
}
