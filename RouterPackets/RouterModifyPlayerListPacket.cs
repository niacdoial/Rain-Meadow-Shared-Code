using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;

namespace RainMeadow.Shared
{
    public class RouterModifyPlayerListPacket : Packet
    {
        // roles: Server->Host or Server->Player
        public override Type type => Type.RouterModifyPlayerList;
        public enum Operation : byte
        {
            Add,
            Remove
        }

        public Operation operation { get; private set; }
        public List<ushort> routerIds { get; private set; }

        public RouterModifyPlayerListPacket ( ) { }
        public RouterModifyPlayerListPacket(Operation operation, List<ushort> routerIds)
        {
            this.operation = operation;
            this.routerIds = routerIds;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write((byte)operation);
            writer.Write((ushort)routerIds.Count);
            foreach (ushort id in routerIds) writer.Write(id);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            operation = (Operation)reader.ReadByte();
            ushort count = reader.ReadUInt16();
            routerIds = new(count);

            for (int i = 0; i < count; i++)
            {
                routerIds.Add(reader.ReadUInt16());
            }
        }

        static public event Action<RouterModifyPlayerListPacket>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
