using System;
using System.IO;
using System.Net;
using RainMeadow.Shared.Models;

namespace RainMeadow.Shared
{
    public class PublishRouterLobby : Packet
    {
        // always used as a server->player packet
        public string lobbyName;
        public string userName;
        public LobbyParameters lobbyParameters;
        public bool exposeIPAddress;

        public PublishRouterLobby() { }
        public PublishRouterLobby(string lobbyName, LobbyParameters lobbyParameters, string userName, bool exposeIPAddress)
        {
            this.lobbyName = lobbyName;
            this.userName = userName;
            this.lobbyParameters = lobbyParameters;
            this.exposeIPAddress = exposeIPAddress;
        }

        public override Type type => Type.PublishRouterLobby;

        public override void Serialize(BinaryWriter writer)
        {
            base.Serialize(writer);
            writer.Write(exposeIPAddress);
            writer.Write(userName);
            writer.Write(lobbyName);
            lobbyParameters.Serialize(writer);
        }

        public override void Deserialize(BinaryReader reader)
        {
            base.Deserialize(reader);
            exposeIPAddress = reader.ReadBoolean();
            userName = reader.ReadString();
            lobbyName = reader.ReadString();
            lobbyParameters = new LobbyParameters(reader);
        }


        static public event Action<PublishRouterLobby>? ProcessAction = null;
        public override void Process()
        {
            ProcessAction?.Invoke(this);
        }
    }
}
