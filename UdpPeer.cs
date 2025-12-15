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

    public class UDPPeerId : PeerId {
        public IPEndPoint endPoint;
        public UDPPeerId(IPEndPoint endPoint) {
            this.endPoint = endPoint;
        }
        public override bool Equals(PeerId other)
        {
            if (other is UDPPeerId id)
            {
                return BasePeerManager.CompareIPEndpoints(this.endPoint, id.endPoint);
            }
            return false;
        }
        public override bool isLoopback()
        {
            if (endPoint is null) return false;
            if (SharedPlatform.PlatformPeerManager?.port != endPoint.Port) return false;
            return BasePeerManager.isLoopback(endPoint.Address);
        }
        public override bool isNetworkLocal()
        {
            if (endPoint is null) return false;
            return BasePeerManager.isEndpointLocal(endPoint);
        }
        // Blackhole Endpoint
        // https://superuser.com/questions/698244/ip-address-that-is-the-equivalent-of-dev-null
        public static IPEndPoint BlackHoleEndPoint = new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999);
        public override bool isBlackHole()
        {
            if (endPoint is null) return false;
            return BasePeerManager.CompareIPEndpoints(endPoint, BlackHoleEndPoint);
        }
    }

    public class UDPPeerManager : BasePeerManager
    {
        public enum RawPacketType : byte
        {
            Unreliable = 0,
            UnreliableBroadcast,
            Reliable, // and ordered!
            HeartBeat,  // also serves as acknowledgement
        }

        class RemotePeer {
            public IPEndPoint PeerEndPoint { get; set; } = new IPEndPoint(IPAddress.Any, 0);
            public ulong TicksSinceLastIncomingPacket = 0;
            public ulong OutgoingPacketAcummulator = 0;


            public Queue<byte[]> outgoingpacket = new Queue<byte[]>();
            public ulong wanted_acknowledgement = 0;  // the 'packet ID' of the last reliable packet ack'd by peer (1-indexed)
            public ulong remote_acknowledgement = 0;  // the 'packet ID' of the last reliable packet recv'd by us  (1-indexed)
            public bool need_begin_conversation_ack = true;

        }


        public UDPPeerManager(int default_port = DEFAULT_PORT, int port_attempts = FIND_PORT_ATTEMPTS) {
            BlackHole = new UDPPeerId(UDPPeerId.BlackHoleEndPoint);
            InitSocket();
        }

        public override PeerId GetSelf() {
            return new UDPPeerId(new IPEndPoint(
                BasePeerManager.getInterfaceAddresses()[0],
                this.port
            ));
        }
        public override PeerId[] GetBroadcastPeerIDs() {
            List<PeerId> broadcastables = new List<PeerId>();
            for (int broadcast_port = BasePeerManager.DEFAULT_PORT;
                broadcast_port < (BasePeerManager.FIND_PORT_ATTEMPTS + BasePeerManager.DEFAULT_PORT);
                broadcast_port++)
            {
                broadcastables.Add(new UDPPeerId(new(IPAddress.Broadcast, broadcast_port)));
            }
            return broadcastables.ToArray();
        }

        public /*static*/ override PeerId? GetPeerIdByName(string name) {
            IPEndPoint? endPoint = GetEndPointByName(name);
            if (endPoint is null) return null;
            return new UDPPeerId(endPoint);
        }

        public /*static*/ override string describePeerId(PeerId endPoint, PeerId? serverEndPoint=null){
            var peerId = endPoint as UDPPeerId;
            if (peerId is null) {
                return "[Bad PeerId type, expected UDP PeerId]";
            }
            return String.Format(
                "[IP: is machine local: {0}, is network local: {1}, is devnull: {2}]",
                peerId.isLoopback(),
                isEndpointLocal(peerId.endPoint),
                endPoint.isBlackHole()
            );
        }

        /// the functions that (de)serialize multiple endpoints at once can deal with the sender seeing itself differently as everyone else.
        /// The functions that do not need a separate mechanism to deal with this.
        public /*static*/ override void SerializePeerIDs(BinaryWriter writer, PeerId[] endPoints, PeerId addressedto, bool includeme = true) {
            var filteredEndPoints = endPoints.Select(x => x as UDPPeerId)
                .Where(x=> x != null)
                .Select(x=>x.endPoint).ToArray();
            var dest = addressedto as UDPPeerId;
            if (dest is null) {return;}
            SerializeIPEndPoints(writer, filteredEndPoints, dest.endPoint, includeme);
        }
        public /*static*/ override PeerId[] DeserializePeerIDs(BinaryReader reader, PeerId fromWho) {
            UDPPeerId? sender = fromWho as UDPPeerId;
            if (sender is null) {throw new Exception("bad PeerId as sender");}
            var rawEndPoints = DeserializeIPEndPoints(reader, sender.endPoint);
            return rawEndPoints.Select(x => new UDPPeerId(x)).ToArray();
        }

        public /*static*/ override void SerializePeerId(BinaryWriter writer, PeerId peerId) {
            UDPPeerId? truePeerId = peerId as UDPPeerId;
            if (truePeerId is null) {throw new Exception("bad PeerId to serialize");}
            BasePeerManager.SerializeIPEndPoint(writer, truePeerId.endPoint);
        }
        public /*static*/ override PeerId DeserializePeerId(BinaryReader reader) {
            return new UDPPeerId(BasePeerManager.DeserializeIPEndPoint(reader));
        }

        List<RemotePeer> peers = new();
        RemotePeer? GetRemotePeer(PeerId peerId, bool make_one = false) {
            var udpPeerId = peerId as UDPPeerId;
            if (udpPeerId is null) return null;
            RemotePeer? peer = peers.FirstOrDefault(x => CompareIPEndpoints(udpPeerId.endPoint, x.PeerEndPoint));
            if (peer == null && make_one) {
                peer = new RemotePeer() {PeerEndPoint = udpPeerId.endPoint};
                peers.Add(peer);
            }

            return peer;
        }

        public override void EnsureRemotePeerCreated(PeerId peerId) {
            GetRemotePeer(peerId, true);
        }

        void ForgetPeer(RemotePeer peer) {
            peers.Remove(peer);  // remove first, in case this peer's removal callback recurses into here
            Run_OnPeerForgotten(new UDPPeerId(peer.PeerEndPoint));
        }
        public override void ForgetPeer(PeerId peerId) {
            var udpPeerId = peerId as UDPPeerId;
            if (udpPeerId is null) return;
            var remove_peers = peers.FindAll(x => CompareIPEndpoints(udpPeerId.endPoint, x.PeerEndPoint));
            foreach (RemotePeer peer in remove_peers) {
                ForgetPeer(peer);
            }
        }

        public override void ForgetAllPeers() {
            var remove_peers = peers.ToList();
            foreach (RemotePeer peer in remove_peers) {
                ForgetPeer(peer);
            }
        }

        public override void Send(byte[] packet, PeerId peerId, PacketType packet_type = PacketType.Reliable, bool begin_conversation = false) {
            RawPacketType rawPacketType = packet_type switch {
                PacketType.Unreliable => RawPacketType.Unreliable,
                PacketType.Reliable => RawPacketType.Reliable,
                PacketType.UnreliableBroadcast => RawPacketType.UnreliableBroadcast,
            };
            if (GetRemotePeer(peerId, true) is RemotePeer peer) {
                if (packet_type == PacketType.Reliable) {
                    if (begin_conversation && !peer.need_begin_conversation_ack) {
                        SharedCodeLogger.Debug("redundant begin_conversation flag? adding this flag to the next Reliable packet sent, which might not be the one currently queued.");
                        peer.need_begin_conversation_ack = true;
                    }
                    if (!peer.outgoingpacket.Any()) SendRaw(packet, peer, rawPacketType, begin_conversation); // send immediately if there are no pending packets
                    peer.outgoingpacket.Enqueue(packet);
                } else {
                    SendRaw(packet, peer, rawPacketType, begin_conversation);
                }
            } else SharedCodeLogger.Error("Failed to get remote peer");
        }

        void SendRaw(byte[] packet, RemotePeer peer, RawPacketType packet_type, bool begin_conversation = false) {
            int extraLength = 1;
            switch (packet_type) {
            case RawPacketType.Reliable:
                extraLength = 2 + sizeof(ulong);
                break;
            case RawPacketType.HeartBeat:
                extraLength = 1 + sizeof(ulong);
                break;
            };

            if ((extraLength + packet.Length) == 0) return;
            using (MemoryStream stream = new(packet.Length + extraLength))
            using (BinaryWriter writer = new(stream))
            {
                writer.Write((byte)packet_type);
                if (packet_type == RawPacketType.Reliable)
                {
                    writer.Write(begin_conversation);
                    writer.Write(peer.wanted_acknowledgement + 1);
                }


                if (packet_type == RawPacketType.HeartBeat)
                {
                    writer.Write(peer.remote_acknowledgement);
                }
                writer.Write(packet);
                socket.SendTo(stream.GetBuffer(), peer.PeerEndPoint);
            }
        }


        long? lastTime = null!;
        public override void Update()
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
                    SharedCodeLogger.Error($"Forgetting {describePeerId(new UDPPeerId(peer.PeerEndPoint))} due to Timeout, Timeout is {timeoutTime}ms");
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
                        SendRaw(peer.outgoingpacket.Peek(), peer, RawPacketType.Reliable, peer.need_begin_conversation_ack);
                    }
                    else
                    {
                        SendRaw(
                            Array.Empty<byte>(),
                            peer,
                            RawPacketType.HeartBeat
                        );
                    }
                }
            }

            foreach (var peer in peersToRemove) ForgetPeer(peer);
        }

        public override byte[]? Receive(out PeerId? sender, bool blocking=false) {
            sender = null;

            if ((!blocking) && socket.Available != 0) {
                EndPoint senderEndPoint = new IPEndPoint(IPAddress.Loopback, 8720);

                byte[] buffer;
                int len = 0;

                if (blocking) {
                    socket.Blocking = true;
                    socket.ReceiveTimeout = (int)SharedPlatform.heartbeatTime;
                }
                try {
                    if (socket.Available > MTU) {
                        buffer = new byte[socket.Available];
                    } else {
                        buffer = reusableRecvBuffer;
                    }
                    len = socket.ReceiveFrom(buffer, ref senderEndPoint);
                } catch (Exception except) {
                    if (except is SocketException skEx && skEx.ErrorCode != 10060)
                    {
                        // if the error is not a timeout
                        SharedCodeLogger.Error(except);
                    }
                    return null;
                }
                if (blocking) {
                    socket.Blocking = false;
                }

                IPEndPoint? ipsender = senderEndPoint as IPEndPoint;
                if (ipsender == null) return null;
                sender = new UDPPeerId(ipsender);

                RemotePeer? peer = GetRemotePeer(sender);

                using (MemoryStream stream = new(buffer, 0, len, false))
                using (BinaryReader reader = new(stream)) {
                    try {
                        RawPacketType type = (RawPacketType)reader.ReadByte();

                        if (type == RawPacketType.Reliable) {
                            bool begin_conversation = reader.ReadBoolean();
                            if (begin_conversation && peer == null) {
                                peer = GetRemotePeer(sender, true);
                            }
                        }

                        if (type != RawPacketType.UnreliableBroadcast) // If it's a broadcast, we don't need to start a converstation.
                        if (peer == null) {
                            SharedCodeLogger.Debug("Recieved packet from peer we haven't started a conversation with.");
                            SharedCodeLogger.Debug(describePeerId(sender));
                            SharedCodeLogger.Debug(Enum.GetName(typeof(RawPacketType), type));

                            foreach (RemotePeer otherpeer in this.peers)
                            {
                                SharedCodeLogger.Debug(describePeerId(new UDPPeerId(otherpeer.PeerEndPoint)));
                            }

                            return null;
                        }

                        if (peer != null) peer.TicksSinceLastIncomingPacket = 0;



                        switch (type) {
                            case RawPacketType.UnreliableBroadcast:
                            case RawPacketType.Unreliable:
                                return reader.ReadBytes(len - 1);

                            case RawPacketType.Reliable:
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
                                    RawPacketType.HeartBeat
                                );
                                return new_data;
                            case RawPacketType.HeartBeat:
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
    }
}
