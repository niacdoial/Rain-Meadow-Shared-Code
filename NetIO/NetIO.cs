using System.Collections.Generic;

namespace RainMeadow.Shared
{
    public abstract class NetIO
    {
        public enum SendType : byte
        {
            Reliable,
            Unreliable,
        }

        public virtual void SendSessionData(BasicOnlinePlayer toPlayer) {}
        public virtual void ForgetPlayer(BasicOnlinePlayer player) {}
        public virtual void ForgetEverything() {}
        public abstract bool IsActive();

        public abstract void RecieveData();

        public virtual void Update() {
            RecieveData();
        }

    }
}
