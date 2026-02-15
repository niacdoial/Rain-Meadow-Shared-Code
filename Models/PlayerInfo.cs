namespace RainMeadow.Shared.Models
{
    public record class GameLiftPlayerInfo
    {
        public required string sub;
        public required string username;
        public required string publicKey;
        public bool IsDev = false;
        public bool IsTrustedCommunity = false;
        public string? CapeEntry;
    }
}