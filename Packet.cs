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
            SessionEnd,
            RequestLobby,
            InformLobby,
            ChatMessage,

            // Router stuff
            BeginRouterSession,
            EndRouterSession,
            RouterModifyPlayerList,
            JoinRouterLobby,
            RouteSessionData,

            // placeholder Router stuff
            PublishRouterLobby,
            LobbyIsEmpty,
        }

        public delegate void BuildPacket_t(Type type, ref Packet? packet);
        public static event BuildPacket_t? packetFactory;

        public abstract Type type { get; }
        public ushort size = 0;

        public virtual void Serialize(BinaryWriter writer) { } // Write into bytes
        public virtual void Deserialize(BinaryReader reader) { } // Read from bytes
        public virtual void Process() { } // Do the payload

        public IPEndPoint processingEndpoint;




        public static void Encode(Packet packet, BinaryWriter writer, IPEndPoint toEndpoint)
        {
            packet.processingEndpoint = toEndpoint;

            writer.Write((byte)packet.type);
            long payloadPos = writer.Seek(2, SeekOrigin.Current);


            packet.Serialize(writer);
            packet.size = (ushort)(writer.BaseStream.Position - payloadPos);

            writer.Seek((int)payloadPos - 2, SeekOrigin.Begin);
            writer.Write(packet.size);
            writer.Seek(packet.size, SeekOrigin.Current);
        }

        public static void Decode(BinaryReader reader, IPEndPoint fromEndpoint)
        {
            Type type = (Type)reader.ReadByte();
            // RainMeadow.Debug($"Recieved {type}");
            //RainMeadow.Debug("Got packet type: " + type);

            Packet? packet = null;
            packetFactory?.Invoke(type, ref packet);



            if (packet == null)
            {
                // throw new Exception($"Undetermined packet type ({type}) received");
                RainMeadow.Error($"Bad Packet Type Recieved {type}");
                return;
            }

            packet.processingEndpoint = fromEndpoint;
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
                    Type.EndRouterSession => new EndRouterSession(),
                    Type.RouterModifyPlayerList => new RouterModifyPlayerListPacket(),
                    Type.JoinRouterLobby => new JoinRouterLobby(),
                    Type.RouteSessionData => new RouteSessionData(),
                    Type.LobbyIsEmpty => new LobbyIsEmpty(),
                    Type.PublishRouterLobby => new PublishRouterLobby(),
                    _ => null
                };
            }

        }

    }
}
