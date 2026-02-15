using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using RainMeadow.Shared.Models;

namespace RainMeadow.Shared
{
    public class RouterModifyPlayerListPacket : Packet
    {
        // roles: Server->Host or Server->Player
        public override Type type => Type.RouterModifyPlayerList;
        public enum Operation : byte
        {
            Add,
            Update,  // special Add that updates existing players if found
            Remove
        }

        public Operation operation { get; private set; }
        public List<ushort> routerIds { get; private set; }
        public List<SecuredPeerId?> endPoints { get; private set; }
        public List<PlayerInfo> userData { get; private set; }

        public RouterModifyPlayerListPacket ( ) { }
        public RouterModifyPlayerListPacket(Operation operation, List<ushort> routerIds, List<SecuredPeerId?> endPoints, List<PlayerInfo> userData)
        {
            
            if (routerIds.Count != endPoints.Count || routerIds.Count != userData.Count) throw new Exception("incoherent counts in ModifyPlayerList arguments");

            boxed = true;
            this.operation = operation;
            this.routerIds = routerIds;
            this.endPoints = endPoints;
            this.userData = userData;
        }

        public RouterModifyPlayerListPacket(Operation operation, List<ushort> routerIds)
        {
            this.operation = operation;
            this.routerIds = routerIds;
            this.endPoints = new List<SecuredPeerId?>{};
            this.userData = new List<PlayerInfo>{};
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write((byte)operation);
            writer.Write((ushort)routerIds.Count);
            foreach (ushort id in routerIds) writer.Write(id);
            if (operation != Operation.Remove) 
            {
                SecuredPeerId.SerializeArray(writer, endPoints.ToArray(), processingPeer, mePeer, true);
                foreach (PlayerInfo data in userData) data.Serialize(writer);
            }
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

            if (operation != Operation.Remove) 
            {
                endPoints = SecuredPeerId.DeserializeArray(reader, processingPeer, mePeer, true).ToList();
                userData = new(count);
                for (ushort i=0; i<count ; i++) {
                    userData.Add(new PlayerInfo(reader));
                }
            } else {
                endPoints = new(0);
                userData = new(0);
            }
        }

        static public event Action<RouterModifyPlayerListPacket>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
