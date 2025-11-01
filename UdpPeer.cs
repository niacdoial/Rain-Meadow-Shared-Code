using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
//using UnityEngine;

namespace RainMeadow.Shared
{

    public class UDPPeerManager : BasePeerManager
    {
        public bool IsDisposed { get => _isDisposed; }
        private bool _isDisposed = false;

        public enum PacketType : byte
        {
            Unreliable = 0,
            UnreliableBroadcast,
            Reliable, // and ordered!
            HeartBeat,  // also serves as acknowledgement
        }


        public class RemotePeer {
            public IPEndPoint PeerEndPoint { get; set; } = new IPEndPoint(IPAddress.Any, 0);
            public ulong TicksSinceLastIncomingPacket = 0;
            public ulong OutgoingPacketAcummulator = 0;


            public Queue<byte[]> outgoingpacket = new Queue<byte[]>();
            public ulong wanted_acknowledgement = 0;  // the 'packet ID' of the last reliable packet ack'd by peer (1-indexed)
            public ulong remote_acknowledgement = 0;  // the 'packet ID' of the last reliable packet recv'd by us  (1-indexed)
            public bool need_begin_conversation_ack = true;

        }


        public UDPPeerManager(int default_port = DEFAULT_PORT, int port_attempts = FIND_PORT_ATTEMPTS) {
            InitSocket();
        }

        List<RemotePeer> peers = new();
        public RemotePeer? GetRemotePeer(IPEndPoint endPoint, bool make_one = false) {
            RemotePeer? peer = peers.FirstOrDefault(x => CompareIPEndpoints(endPoint, x.PeerEndPoint));
            if (peer == null && make_one) {
                peer = new RemotePeer() {PeerEndPoint = endPoint};
                peers.Add(peer);
            }

            return peer;
        }

        public delegate void OnPeerForgotten_t(IPEndPoint endPoint);
        public event OnPeerForgotten_t OnPeerForgotten = delegate { };


        public void ForgetPeer(RemotePeer peer) {
            peers.Remove(peer);  // remove first, in case this peer's removal callback recurses into here
            OnPeerForgotten.Invoke(peer.PeerEndPoint);
        }
        public void ForgetPeer(IPEndPoint endPoint) {
            var remove_peers = peers.FindAll(x => CompareIPEndpoints(endPoint, x.PeerEndPoint));
            foreach (RemotePeer peer in remove_peers) {
                ForgetPeer(peer);
            }
        }

        public void ForgetAllPeers() {
            var remove_peers = peers.ToList();
            foreach (RemotePeer peer in remove_peers) {
                ForgetPeer(peer);
            }
        }

        public void Send(byte[] packet, IPEndPoint endPoint, PacketType packet_type = PacketType.Reliable, bool begin_conversation = false) {
            if (GetRemotePeer(endPoint, true) is RemotePeer peer) {
                if (packet_type == PacketType.Reliable) {
                    if (begin_conversation && !peer.need_begin_conversation_ack) {
                        SharedCodeLogger.Debug("redundant begin_conversation flag? adding this flag to the next Reliable packet sent, which might not be the one currently queued.");
                        peer.need_begin_conversation_ack = true;
                    }
                    if (!peer.outgoingpacket.Any()) SendRaw(packet, peer, packet_type, begin_conversation); // send immediately if there are no pending packets
                    peer.outgoingpacket.Enqueue(packet);
                } else {
                    SendRaw(packet, peer, packet_type, begin_conversation);
                }
            } else SharedCodeLogger.Error("Failed to get remote peer");
        }

        public void SendRaw(byte[] packet, RemotePeer peer, PacketType packet_type, bool begin_conversation = false) {
            int extraLength = 1;
            switch (packet_type) {
            case PacketType.Reliable:
                extraLength = 2 + sizeof(ulong);
                break;
            case PacketType.HeartBeat:
                extraLength = 1 + sizeof(ulong);
                break;
            };

            if ((extraLength + packet.Length) == 0) return;
            using (MemoryStream stream = new(packet.Length + extraLength))
            using (BinaryWriter writer = new(stream))
            {
                writer.Write((byte)packet_type);
                if (packet_type == PacketType.Reliable)
                {
                    writer.Write(begin_conversation);
                    writer.Write(peer.wanted_acknowledgement + 1);
                }


                if (packet_type == PacketType.HeartBeat)
                {
                    writer.Write(peer.remote_acknowledgement);
                }
                writer.Write(packet);
                socket.SendTo(stream.GetBuffer(), peer.PeerEndPoint);
            }
        }


        long? lastTime = null!;
        public void Update()
        {
            long time = (long)SharedPlatform.TimeMS;
            long elapsedTime;
            if (!lastTime.HasValue)
            {
                lastTime = time;
                elapsedTime = 0;
            }
            else
            {
                elapsedTime = time - lastTime.Value;
                lastTime = time;
            }

            List<RemotePeer> peersToRemove = new();
            for (int i = peers.Count - 1; i >= 0; i--)
            {
                RemotePeer peer = peers[i];
                peer.TicksSinceLastIncomingPacket += (ulong)elapsedTime;

                // TODO: separate heartbeat freq between player/player and player/server
                ulong heartbeatTime = SharedPlatform.heartbeatTime;
                ulong timeoutTime = SharedPlatform.timeoutTime;
                if (peer.TicksSinceLastIncomingPacket >= timeoutTime)
                {
                    SharedCodeLogger.Error($"Forgetting {describeEndPoint(peer.PeerEndPoint)} due to Timeout, Timeout is {timeoutTime}ms");
                    peersToRemove.Add(peer);
                    continue;
                }

                peer.OutgoingPacketAcummulator += (ulong)elapsedTime;
                while (peer.OutgoingPacketAcummulator > heartbeatTime)
                {
                    peer.OutgoingPacketAcummulator -= heartbeatTime;
                    peer.OutgoingPacketAcummulator = Math.Max(peer.OutgoingPacketAcummulator, 0); // just to be sure
                    if (peer.outgoingpacket.Any())
                    {
                        SendRaw(peer.outgoingpacket.Peek(), peer, PacketType.Reliable, peer.need_begin_conversation_ack);
                    }
                    else
                    {
                        SendRaw(
                            Array.Empty<byte>(),
                            peer,
                            PacketType.HeartBeat
                        );
                    }
                }
            }

            foreach (var peer in peersToRemove) ForgetPeer(peer);
        }

        public byte[]? Recieve(out EndPoint? sender) {
            sender = null;

            if (socket.Available != 0) {
                sender = new IPEndPoint(IPAddress.Loopback, 8720);

                byte[] buffer;
                int len = 0;
                try {
                    buffer = new byte[socket.Available];
                    len = socket.ReceiveFrom(buffer, ref sender);
                } catch (Exception except) {
                    SharedCodeLogger.Error(except);
                    return null;
                }


                IPEndPoint? ipsender = sender as IPEndPoint;
                if (ipsender == null) return null;

                RemotePeer? peer = GetRemotePeer(ipsender);

                using (MemoryStream stream = new(buffer, 0, len, false))
                using (BinaryReader reader = new(stream)) {
                    try {
                        PacketType type = (PacketType)reader.ReadByte();

                        if (type == PacketType.Reliable) {
                            bool begin_conversation = reader.ReadBoolean();
                            if (begin_conversation && peer == null) {
                                peer = GetRemotePeer(ipsender, true);
                            }
                        }

                        if (type != PacketType.UnreliableBroadcast) // If it's a broadcast, we don't need to start a converstation.
                        if (peer == null) {
                            SharedCodeLogger.Debug("Recieved packet from peer we haven't started a conversation with.");
                            SharedCodeLogger.Debug(describeEndPoint(ipsender));
                            SharedCodeLogger.Debug(Enum.GetName(typeof(PacketType), type));

                            foreach (RemotePeer otherpeer in this.peers)
                            {
                                SharedCodeLogger.Debug(describeEndPoint(otherpeer.PeerEndPoint));
                            }

                            return null;
                        }

                        if (peer != null) peer.TicksSinceLastIncomingPacket = 0;



                        switch (type) {
                            case PacketType.UnreliableBroadcast:
                            case PacketType.Unreliable:
                                return reader.ReadBytes(len - 1);

                            case PacketType.Reliable:
                                if (peer == null) return null;

                                ulong wanted_ack = reader.ReadUInt64();
                                byte[]? new_data = null;

                                if (EventMath.IsNewer(wanted_ack, peer.remote_acknowledgement)) {
                                    peer.remote_acknowledgement++ ;
                                    if (EventMath.IsNewer(wanted_ack, peer.remote_acknowledgement)) {
                                        SharedCodeLogger.Error("Reliable Packet too advanced! We have skipped a packet in an ordered stream of packets!");
                                        peer.remote_acknowledgement = wanted_ack;
                                    }
                                    new_data = reader.ReadBytes(len - 2 - sizeof(ulong));
                                }
                                SendRaw(
                                    Array.Empty<byte>(),
                                    peer,
                                    PacketType.HeartBeat
                                );
                                return new_data;
                            case PacketType.HeartBeat:
                                if (peer == null) return null;
                                peer.need_begin_conversation_ack = false;
                                ulong remote_ack = reader.ReadUInt64();
                                if (EventMath.IsNewer(remote_ack, peer.wanted_acknowledgement)) {
                                    ++peer.wanted_acknowledgement;
                                    if (EventMath.IsNewer(remote_ack, peer.wanted_acknowledgement)) {
                                        // this can happen if we leave the Meadow menu then reenter it before the matchmaking server times us out
                                        SharedCodeLogger.Error("Reliable Packet Acknowledgement too advanced! We might have sent a packet too early?");
                                        // we can make packet delivery recover from this, by just... skipping numbers in the next packets IDs sent
                                        peer.wanted_acknowledgement = remote_ack;
                                    }
                                    if (peer.outgoingpacket.Count > 0) {
                                        peer.outgoingpacket.Dequeue();
                                    } else {
                                        SharedCodeLogger.Error("Reliable Packet Acknowledgement without corresponding queued message! Expect more problems in ordered communications.");
                                    }
                                } // else, this is a delayed copy of an already ack'd packet. no problem.
                                return null;

                            default:
                                return null; // Ignore it.
                        }
                    } catch (Exception except) {
                        SharedCodeLogger.Debug(except);
                        SharedCodeLogger.Debug($"Error: {except.Message}");
                        return null;
                    }
                }
            }
            return null;
        }

        void IDisposable.Dispose() {
            socket.Dispose();
            _isDisposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
