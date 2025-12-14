using System;
using System.IO;
using System.Net;
using MonoMod.Utils;

namespace RainMeadow.Shared
{
    public class PlayerJoiningDecision : Packet
    {
        // always used as a player->server packet
        public override Type type => Type.PlayerJoiningDecision;

        public enum Decision : byte
        {
            Accept,
            Reject
        }

        public Decision decision;
        public ushort player;

        public PlayerJoiningDecision() { }
        public PlayerJoiningDecision(ushort player, Decision decision)
        {
            this.player = player;
            this.decision = decision;
        }

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write((byte)decision);
            writer.Write(player);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            decision = (Decision)reader.ReadByte();
            player = reader.ReadUInt16();
        }

        static public event Action<PlayerJoiningDecision>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
