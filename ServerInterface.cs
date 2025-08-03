using System.IO;
using System.Net;

namespace RainMeadow.Shared 
{
    abstract class RouterPacket
    {
        public enum Type : byte
        {
            // the packet sent to the server by the owner after the server was created by the matchmaker.
            // contains a secret key to confirm the player isindeed the one who created the server. 
            // if the server doesn't recieve this packet within a designated timeframe it will automatically close.
            BeginSession, 

            // For regular clients joining the server 
            JoinLobby,

            // routing session data from one to another
            Session,

            // chat messages distrobuted among the entire server
            ChatMessage,

            EndSession
        }

        public abstract Type type { get; }
        public ushort size = 0;

        public virtual void Serialize(BinaryWriter writer) { } // Write into bytes
        public virtual void Deserialize(BinaryReader reader) { } // Read from bytes
        public virtual void Process() { } // Do the payload
    }

    class ServerInterface
    {
        public UDPPeerManager.RemotePeer serverPeer { get; private set; }
        public ServerInterface(UDPPeerManager.RemotePeer server)
        {
            serverPeer = server;
        }

        public 
    }
}
