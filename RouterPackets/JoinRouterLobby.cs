using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class JoinRouterLobby : Packet
    {
        public int currentplayercount = default;
        public int maxplayers = default;
        public bool passwordprotected = default;
        public string name = "";
        public string mode = "";
        public string mods = "";
        public string bannedMods = "";
        public ushort yourRoutingID;

        public JoinRouterLobby() { }
        public JoinRouterLobby(ushort yourRoutingID, int maxplayers, string name, bool passwordprotected, string mode, int currentplayercount, string highImpactMods = "", string bannedMods = "")
        {
            this.maxplayers = maxplayers;
            this.name = name;
            this.passwordprotected = passwordprotected;
            this.mode = mode;
            this.currentplayercount = currentplayercount;
            this.mods = highImpactMods;
            this.bannedMods = bannedMods;

            this.yourRoutingID = yourRoutingID;
        }

        public override Type type => Type.JoinRouterLobby;

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(maxplayers);
            writer.Write(currentplayercount);
            writer.Write(passwordprotected);
            writer.Write(name);
            writer.Write(mode);
            writer.Write(mods);
            writer.Write(bannedMods);
            writer.Write(yourRoutingID);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            maxplayers = reader.ReadInt32();
            currentplayercount = reader.ReadInt32();
            passwordprotected = reader.ReadBoolean();
            name = reader.ReadString();
            mode = reader.ReadString();
            mods = reader.ReadString();
            bannedMods = reader.ReadString();
            yourRoutingID = reader.ReadUInt16();
        }


        static public event Action<JoinRouterLobby>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}