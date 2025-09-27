using System;
using System.IO;

namespace RainMeadow.Shared
{
    public class RouterChatMessage : Packet
    {
        // always used in player-to-player communication

        public override Type type => Type.RouterChatMessage;
        public ushort fromRouterID;
        public string message;

        public RouterChatMessage() { }
        public RouterChatMessage(ushort fromRouterID, string message)
        {
            this.fromRouterID = fromRouterID;
            this.message = message;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(fromRouterID);
            writer.Write(message);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            fromRouterID = reader.ReadUInt16();
            message = reader.ReadString();
        }

        static public event Action<RouterChatMessage>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
