using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class JoinRouterLobby : Packet
    {
        // always used as a server->player packet
        public int maxplayers = default;
        public bool passwordprotected = default;
        public string name = "";
        public string mode = "";
        public string mods = "";
        public string bannedMods = "";
        public ushort assignedRoutingID;

        public JoinRouterLobby() { }
        public JoinRouterLobby(ushort assignedRoutingID, int maxplayers, string name, bool passwordprotected, string mode, string highImpactMods = "", string bannedMods = "")
        {
            this.maxplayers = maxplayers;
            this.name = name;
            this.passwordprotected = passwordprotected;
            this.mode = mode;
            this.mods = highImpactMods;
            this.bannedMods = bannedMods;

            this.assignedRoutingID = assignedRoutingID;
        }

        public override Type type => Type.JoinRouterLobby;

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(maxplayers);
            writer.Write(passwordprotected);
            writer.Write(name);
            writer.Write(mode);
            writer.Write(mods);
            writer.Write(bannedMods);
            writer.Write(assignedRoutingID);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            maxplayers = reader.ReadInt32();
            passwordprotected = reader.ReadBoolean();
            name = reader.ReadString();
            mode = reader.ReadString();
            mods = reader.ReadString();
            bannedMods = reader.ReadString();
            assignedRoutingID = reader.ReadUInt16();
        }


        static public event Action<JoinRouterLobby>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
