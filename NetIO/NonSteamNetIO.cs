using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace RainMeadow.Shared {

    public abstract class NonSteamNetIO : NetIO {

        // If using a domain requires you to start a conversation, then any packet sent before before starting a conversation is ignored.
        // otherwise, the parameter "start_conversation" is ignored.
        public virtual void SendP2P(BasicOnlinePlayer player, Packet packet, SendType sendType, bool start_conversation = false) {
            if (!IsActive()) return;

            if (player.id is NetPlayerId netid) {
                using (MemoryStream memory = new MemoryStream(128))
                using (BinaryWriter writer = new BinaryWriter(memory)) {
                    Packet.Encode(packet, writer, player);
                    NetIOPlatform.PlatformUDPManager.Send(
                        memory.GetBuffer(),
                        netid.endPoint,
                        sendType switch {
                            NetIO.SendType.Reliable => UDPPeerManager.PacketType.Reliable,
                            // TODO: there was a switch using start_conversation to choose between Unreliable and UnreliableBroadcast: WHY?
                            NetIO.SendType.Unreliable => UDPPeerManager.PacketType.Unreliable,
                            _ => UDPPeerManager.PacketType.Unreliable,
                        },
                        start_conversation
                    );
                }
            }
        }


        public void SendAcknoledgement(BasicOnlinePlayer player) {
            if (!IsActive()) return;

            if (player.id is NetPlayerId netid) {
                NetIOPlatform.PlatformUDPManager.Send(
                    Array.Empty<byte>(),
                    netid.endPoint,
                    UDPPeerManager.PacketType.Reliable,
                    true
                );
            }
        }

        public override void ForgetPlayer(BasicOnlinePlayer player) {
            if (!IsActive()) return;

            if (player.id is NetPlayerId netid) {
                NetIOPlatform.PlatformUDPManager.ForgetPeer(netid.endPoint);
            }
        }

        public override void ForgetEverything() {
            if (!IsActive()) return;
            NetIOPlatform.PlatformUDPManager.ForgetAllPeers();
        }

        public abstract BasicOnlinePlayer? GetPlayerFromEndPoint(IPEndPoint iPEndPoint);
        public abstract void ProcessPacket(Packet packet, BasicOnlinePlayer player);

        public override void RecieveData()
        {
            if (!IsActive()) return;

            while (NetIOPlatform.PlatformUDPManager.IsPacketAvailable())
            {
                try
                {
                    //SharedCodeLogger.Debug("To read: " + UdpPeer.debugClient.Available);
                    byte[]? data = NetIOPlatform.PlatformUDPManager.Recieve(out EndPoint? remoteEndpoint);
                    if (data == null) continue;
                    IPEndPoint? iPEndPoint = remoteEndpoint as IPEndPoint;
                    if (iPEndPoint is null) continue;

                    using (MemoryStream netStream = new MemoryStream(data))
                    using (BinaryReader netReader = new BinaryReader(netStream)) {
                        if (netReader.BaseStream.Position == ((MemoryStream)netReader.BaseStream).Length) {
                            // nothing to read, for example as a result of SendAck
                            continue;
                        }
                        BasicOnlinePlayer? player = GetPlayerFromEndPoint(iPEndPoint);
                        if (player is BasicOnlinePlayer plr) {
                            var packet = Packet.Decode(netReader, plr);
                            if (packet != null) {
                                ProcessPacket(packet, plr);
                            }
                        }

                    }
                }
                catch (Exception e)
                {
                    SharedCodeLogger.Error(e);
                    // TODO: find better place
                    //OnlineManager.serializer.EndRead();
                }
            }
        }

        public override void Update()
        {
            if (NetIOPlatform.PlatformUDPManager is null) return;
            NetIOPlatform.PlatformUDPManager.Update();
            base.Update();
        }

    }
}
