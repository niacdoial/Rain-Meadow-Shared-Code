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

    public class UDPPeerManager : IDisposable
    {
        public bool IsDisposed { get => _isDisposed; }
        private bool _isDisposed = false;
        public Socket socket;
        public int port;

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

        public const int DEFAULT_PORT = 8720;
        public const int FIND_PORT_ATTEMPTS = 8; // 8 players somehow hosting from the same machine is ridiculous.
        public UDPPeerManager(int default_port = DEFAULT_PORT, int port_attempts = FIND_PORT_ATTEMPTS) {
            try {
                this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                this.socket.Blocking = false;
                this.socket.EnableBroadcast = true;

                port = default_port;
                var activeUdpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
                bool alreadyinuse = false;
                for (int i = 0; i < port_attempts; i++) {
                    port = default_port + i;
                    alreadyinuse = activeUdpListeners.Any(p => p.Port == port);
                    if (!alreadyinuse)
                        break;
                }

                if (alreadyinuse) {
                    throw new Exception("Failed to claim a socket port");
                }


                socket.Bind(new IPEndPoint(IPAddress.Any, port));
            } catch (SocketException except) {
                SharedCodeLogger.Error(except.SocketErrorCode);
                throw;
            }

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


        static IPAddress[] interface_addresses = null;
        static public IPAddress[] getInterfaceAddresses() {
            if (interface_addresses == null) {
                var adapters = NetworkInterface.GetAllNetworkInterfaces();
                var adapter_interface_addresses = adapters.Where(x =>
                    x.Supports(NetworkInterfaceComponent.IPv4) &&
                        (x.NetworkInterfaceType is NetworkInterfaceType.Ethernet ||
                         x.NetworkInterfaceType is NetworkInterfaceType.Wireless80211) &&
                        x.OperationalStatus == OperationalStatus.Up
                    )
                    .Select(x => x.GetIPProperties().UnicastAddresses)
                    .SelectMany(u => u)
                    .Select(u => u.Address)
                    .Where(u => u.AddressFamily == AddressFamily.InterNetwork && u != IPAddress.Loopback);
                if (!adapter_interface_addresses.Contains(IPAddress.Loopback))
                    adapter_interface_addresses = adapter_interface_addresses.Append(IPAddress.Loopback);
                interface_addresses = adapter_interface_addresses.ToArray();
                foreach(var addr in interface_addresses) {
                    SharedCodeLogger.Debug(addr);
                }
            }

            return interface_addresses;
        }

        static public bool isLoopback(IPAddress address) {
            return getInterfaceAddresses().Contains(address);
        }
        public static bool CompareIPEndpoints(IPEndPoint a, IPEndPoint b) {
            if (!a.Port.Equals(b.Port)) {
                return false;
            }

            if (isLoopback(a.Address) && isLoopback(b.Address)) return true;

            return a.Address.MapToIPv4().Equals(b.Address.MapToIPv4());
        }
        public static bool isEndpointLocal(IPEndPoint endpoint) {
            var addressbytes = endpoint.Address.GetAddressBytes();
            if (endpoint.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
                if (addressbytes[0] == 10) return true;

                if (addressbytes[0] == 172)
                if (addressbytes[1] >= 16 && addressbytes[1] <= 31) return true;


                if (addressbytes[0] == 192)
                if (addressbytes[1] == 168) return true;

                if (addressbytes[0] == 127) return true;
                if (endpoint.Address.Equals(IPAddress.Loopback)) return true;
            }
            return false;
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
        public static IPEndPoint? GetEndPointByName(string name)
        {
            string[] parts = name.Split(':');
            if (parts.Length != 2) {
                SharedCodeLogger.Debug("Invalid IP format without colon: " + name);
                parts = new string[2];
                parts[0] = name;
                parts[1] = "8720"; //default port
            }


            IPAddress? address = null;
            try {
                address = IPAddress.Parse(parts[0]);
            } catch (FormatException) {
                try {
                    address = Dns.GetHostEntry(parts[0])
                        .AddressList
                        .Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                        .FirstOrDefault();
                } catch (SocketException) {
                    if (address == null) return null;
                }
            }

            if (!ushort.TryParse(parts[1], out ushort port)) {
                SharedCodeLogger.Debug("Invalid port format: " + parts[1]);
                return null;
            }

            return new IPEndPoint(address, port);
        }


        public void Send(byte[] packet, IPEndPoint endPoint, PacketType packet_type = PacketType.Reliable, bool begin_conversation = false) {
            if (GetRemotePeer(endPoint, true) is RemotePeer peer) {
                if (packet_type == PacketType.Reliable) {
                    if (begin_conversation && !peer.need_begin_conversation_ack) {
                        SharedCodeLogger.Debug("redundant begin_conversation flag? adding this flag to the next Reliable packet sent, which might not be the one currently queued.");
                        peer.need_begin_conversation_ack = true;
                    }
                    if (!peer.outgoingpacket.Any()) SendRaw(packet, peer, packet_type, begin_conversation); // send immidietly if there are no pending packets
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
                    SharedCodeLogger.Error($"Forgetting {peer.PeerEndPoint} due to Timeout, Timeout is {timeoutTime}ms");
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
        public bool IsPacketAvailable() { return socket.Available > 0; }
        public static void SerializeEndPoints(BinaryWriter writer, IPEndPoint[] endPoints, IPEndPoint addressedto, bool includeme = true) {
            writer.Write(includeme);
            writer.Write((int)endPoints.Length);
            foreach (IPEndPoint point in endPoints) {
                var sendpoint = point;
                if (CompareIPEndpoints(point, addressedto)) {
                    sendpoint = new IPEndPoint(IPAddress.Loopback, point.Port);
                }

                writer.Write(sendpoint.Address.MapToIPv4().GetAddressBytes()); // writes 4 bytes.
                // IPEndPoint.Port is an Int32 but that's only because .NET doesn't want unsigned ints in public APIs.
                // so let's unwaste 2 bytes of bandwidth
                writer.Write((UInt16)sendpoint.Port);
            }
        }

        public static IPEndPoint[] DeserializeEndPoints(BinaryReader reader, IPEndPoint fromWho) {
            bool includesender = reader.ReadBoolean();
            IPEndPoint[] ret = new IPEndPoint[reader.ReadInt32() + (includesender? 1 : 0)];
            int i = 0;
            if (includesender) {
                ret[i] = fromWho;
                ++i;
            }

            for (; i != ret.Length; i++) {
                byte[] address_bytes = reader.ReadBytes(4);
                int port = (int)reader.ReadUInt16();
                ret[i] = new IPEndPoint(new IPAddress(address_bytes), port);
            }

            return ret.ToArray();
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
                            SharedCodeLogger.Debug(ipsender.ToString());
                            SharedCodeLogger.Debug(Enum.GetName(typeof(PacketType), type));

                            foreach (RemotePeer otherpeer in this.peers)
                            {
                                SharedCodeLogger.Debug(otherpeer.PeerEndPoint.ToString());
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
