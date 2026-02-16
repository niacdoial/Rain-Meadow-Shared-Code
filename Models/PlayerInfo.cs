using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace RainMeadow.Shared.Models
{
    public class PlayerInfo
    {
        public string sub;
        public string username;
        public string publicKey;
        
        public bool IsDev = false;
        public bool IsTrustedCommunity = false;
        public string? CapeEntry;


        public PlayerInfo() {}
        public PlayerInfo(BinaryReader reader)
        {
            if (reader.ReadBoolean())
            {
                sub = reader.ReadString();
                publicKey = reader.ReadString();
            }
            
            username = reader.ReadString();
            IsDev = reader.ReadBoolean();
            IsTrustedCommunity = reader.ReadBoolean();
            CapeEntry = reader.ReadBoolean()? reader.ReadString() : null;
        }

        public void Serialize(BinaryWriter writer)
        {
            if (sub is not null)
            {
                writer.Write(true);
                writer.Write(sub);
                writer.Write(publicKey!);
            }
            else
            {
                writer.Write(false);
            }
            
            writer.Write(username);
            writer.Write(IsDev);
            writer.Write(IsTrustedCommunity);
            writer.Write(CapeEntry is not null);
            if (CapeEntry is not null) writer.Write(CapeEntry);
        }
    }
}