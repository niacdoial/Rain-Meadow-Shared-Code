using System;
using System.IO;
using System.Net;

namespace RainMeadow.Shared
{
    public class PublishRouterLobby : Packet
    {
        // always used as a player->server packet
        public int maxplayers = default;
        public bool passwordprotected = default;
        public string name = "";
        public string mode = "";
        public string mods = "";
        public string bannedMods = "";
        public ushort assignedRoutingID;

        public PublishRouterLobby() { }
        public PublishRouterLobby(int maxplayers, string name, string mode, bool passwordprotected, string highImpactMods = "", string bannedMods = "")
        {
            this.maxplayers = maxplayers;
            this.name = name;
            this.passwordprotected = passwordprotected;
            this.mode = mode;
            this.mods = highImpactMods;
            this.bannedMods = bannedMods;
        }

        public override Type type => Type.PublishRouterLobby;

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(maxplayers);
            writer.Write(passwordprotected);
            writer.Write(name);
            writer.Write(mode);
            writer.Write(mods);
            writer.Write(bannedMods);
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
        }


        static public event Action<PublishRouterLobby>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
