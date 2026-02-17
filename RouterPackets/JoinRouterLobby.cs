using System;
using System.IO;
using System.Net;
using RainMeadow.Shared.Models;

namespace RainMeadow.Shared
{
    public class JoinRouterLobby : Packet
    {
        // always used as a server->player packet
        public string name;
        public LobbyParameters lobbyParameters;
        public ushort assignedRoutingID;

        public JoinRouterLobby() { }
        public JoinRouterLobby(ushort assignedRoutingID,  string name, LobbyParameters lobbyParameters)
        {
            this.name = name;
            this.lobbyParameters = lobbyParameters;
            this.assignedRoutingID = assignedRoutingID;
        }

        public override Type type => Type.JoinRouterLobby;

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(assignedRoutingID);
            writer.Write(name);
            lobbyParameters.Serialize(writer);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            assignedRoutingID = reader.ReadUInt16();
            name = reader.ReadString();
            lobbyParameters = new LobbyParameters(reader);
        }


        static public event Action<JoinRouterLobby>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
