using System;
using System.IO;
// TODO: why are there packets that rely on length-prefixed strings
// and others that rely on null-terminated ones?

namespace RainMeadow.Shared
{
    public class ChatMessagePacket : Packet
    {
        public string message = "";

        public ChatMessagePacket(): base() {}
        public ChatMessagePacket(string message)
        {
            this.message = message;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(message);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            message = reader.ReadString();
        }


        public override Type type => Type.ChatMessage;

//         public override void Process() {
// #if IS_SERVER
//             throw new Exception("This function must only be called player-side");
// #else
//             MatchmakingManager.currentInstance.RecieveChatMessage(processingPlayer, message);
// #endif
//         }
    }
}
