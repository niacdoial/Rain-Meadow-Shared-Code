using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public abstract class Packet
    {
        public enum Type : byte
        {
            None,

            // LAN stuff
            RequestJoin,
            JoinLobby,
            ModifyPlayerList,
            Session,

            [Obsolete("Stop communication to disconnect instead")]
            SessionEnd,
            RequestLobby,
            InformLobby,
            ChatMessage,
            CustomPacket,

            // Router stuff
            BeginRouterSession,

            [Obsolete("Stop communication to disconnect instead")]
            EndRouterSession, 
            RouterModifyPlayerList,
            PlayerJoiningDecision,
            JoinRouterLobby,
            RouteSessionData,
            RouterChatMessage,
            RouterCustomPacket,

            // placeholder Router stuff
            [Obsolete]
            PublishRouterLobby,
            [Obsolete]
            LobbyIsEmpty,
        }

        public delegate void BuildPacket_t(Type type, ref Packet? packet);
        public static event BuildPacket_t packetFactory = delegate { };

        public abstract Type type { get; }
        public ushort size = 0;
        public bool boxed = false;

        public virtual void Serialize(BinaryWriter writer) { } // Write into bytes
        public virtual void Deserialize(BinaryReader reader) { } // Read from bytes
        public virtual void Process() { } // Do the payload


        #pragma warning disable CS8618
        public SecuredPeerId processingPeer;
        public SecuredPeerId mePeer;
        #pragma warning restore CS8618


        public static void Encode(Packet packet, BinaryWriter writer, SecuredPeerId toPeer, SecuredPeerId mePeer)
        {
            packet.processingPeer = toPeer;
            packet.mePeer = mePeer;
            writer.Write((byte)packet.type);
            long payloadPos = writer.Seek(2, SeekOrigin.Current);


            packet.Serialize(writer);
            packet.size = (ushort)(writer.BaseStream.Position - payloadPos);

            writer.Seek((int)payloadPos - 2, SeekOrigin.Begin);
            writer.Write(packet.size);
            writer.Seek(packet.size, SeekOrigin.Current);
        }

        public static void Decode(BinaryReader reader, SecuredPeerId fromPeer, SecuredPeerId mePeer, bool wasBoxed)
        {
            Type type = (Type)reader.ReadByte();
            // RainMeadow.Debug($"Recieved {type}");
            //RainMeadow.Debug("Got packet type: " + type);

            Packet? packet = null;
            packetFactory?.Invoke(type, ref packet);



            if (packet == null)
            {
                // throw new Exception($"Undetermined packet type ({type}) received");
                RainMeadow.Error($"Bad Packet Type Recieved {(int)type}");
                return;
            }

            packet.boxed = wasBoxed;
            packet.processingPeer = fromPeer;
            packet.mePeer = mePeer;
            packet.size = reader.ReadUInt16();
            var startingPos = reader.BaseStream.Position;

            try
            {
                packet.Deserialize(reader);
                var readLength = reader.BaseStream.Position - startingPos;

                if (readLength != packet.size) throw new Exception($"Payload size mismatch, expected {packet.size} but read {readLength}");

                packet.Process();
            }
            finally
            {
                // Move stream position to next part of packet
                reader.BaseStream.Position = startingPos + packet.size;
            }
        }

        public static void RouterFactory(Type type, ref Packet? packet)
        {
            if (packet is null)
            {
                packet = type switch
                {
                    Type.BeginRouterSession => new BeginRouterSession(),
                    // Type.EndRouterSession => new EndRouterSession(),
                    Type.RouterModifyPlayerList => new RouterModifyPlayerListPacket(),
                    Type.JoinRouterLobby => new JoinRouterLobby(),
                    Type.RouteSessionData => new RouteSessionData(),
                    // Type.LobbyIsEmpty => new LobbyIsEmpty(),
                    // Type.PublishRouterLobby => new PublishRouterLobby(),
                    Type.RouterChatMessage => new RouterChatMessage(),
                    Type.RouterCustomPacket => new RouterCustomPacket(),
                    Type.PlayerJoiningDecision => new PlayerJoiningDecision(),
                    _ => null
                };
            }

        }

    }
}
