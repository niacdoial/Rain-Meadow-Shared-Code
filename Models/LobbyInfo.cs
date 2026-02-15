
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net;

namespace RainMeadow.Shared.Models
{

    public record class LobbyParameters
    {   
        public const string MODE_KEY = "mode";
        public const string MODS_KEY = "mods";
        public const string BANNED_MODS_KEY = "banned_mods";
        public const string PINNED_KEY = "pinned";
        public const string PASSWORD_KEY = "password";

        public int MaxPlayers = 32;
        public bool Pinned;
        public bool PasswordProtected;
        required public string Mode;
        required public string Mods;
        required public string BannedMods;

        public Dictionary<string, string> Metadata;

        public LobbyParameters()
        {
            Metadata = new Dictionary<string, string>();
        }

        [SetsRequiredMembers]
        public LobbyParameters(IDictionary<string, string> parameters)
        {
            Metadata = new Dictionary<string, string>(parameters);

            Pinned = false;
            if (Metadata.TryGetValue(PINNED_KEY, out var pinnedval)) 
            {
                if (bool.TryParse(pinnedval, out var haspassword)) Pinned = haspassword;
                Metadata.Remove(PINNED_KEY);
            }

            PasswordProtected = false;
            if (Metadata.TryGetValue(PASSWORD_KEY, out var passwordval)) 
            {
                if (bool.TryParse(passwordval, out var haspassword)) PasswordProtected = haspassword;
                Metadata.Remove(PASSWORD_KEY);
            }

            
            if (Metadata.TryGetValue(MODE_KEY, out var modeval))
            {
                Mode = modeval;
                Metadata.Remove(MODE_KEY);
            }
            else throw new FormatException($"Property {MODE_KEY} was not filled");


            if (Metadata.TryGetValue(MODS_KEY, out var modsval))
            {
                Mods = modsval;
                Metadata.Remove(MODS_KEY);
            }
            else throw new FormatException($"Property {MODS_KEY} was not filled");

            BannedMods = "";
            if (Metadata.TryGetValue(BANNED_MODS_KEY, out var bannedmodsval))
            {
                BannedMods = bannedmodsval;
                Metadata.Remove(BANNED_MODS_KEY);
            }
            else throw new FormatException($"Property {BANNED_MODS_KEY} was not filled");
        }


    }


    public record class GameLiftLobbyInfo
    {
        public required string Name;
        public required string ID;
        public required string EndPoint;
        public required int PlayerCount = 0;
        public required LobbyParameters Parameters;
        public GameLiftLobbyInfo() {}
    }
}
