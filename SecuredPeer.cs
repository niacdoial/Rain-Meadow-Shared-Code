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
using Sodium;

namespace RainMeadow.Shared
{

    public class SecuredPeerId : PeerId {

        public enum PeerStatus: byte {
            ClearTextOnly = 0,  // network-local broadcast purposes, also allowed for the BlackHole placeholder
            Connected, // Has a known connection pubkey
        }

        public PeerStatus status;
        public IPEndPoint endPoint;
        public byte[] boxPubkey;

        // public SecuredPeerId() {
        //     this.status = PeerStatus::Unsecure;
        //     this.endPoint = null;
        //     this.boxPubkey = null;
        // }

        public SecuredPeerId(IPEndPoint endPoint, byte[] boxPubkey) {
            this.status = PeerStatus.Connected;
            this.endPoint = endPoint;
            this.boxPubkey = boxPubkey;
        }
        public static SecuredPeerId MakeClearText(IPEndPoint endPoint) {
            SecuredPeerId newSelf = new SecuredPeerId(endPoint, null);
            newSelf.status = PeerStatus.ClearTextOnly;
            return newSelf;
        }

        public override bool Equals(PeerId other)
        {
            // note that this equality function just means "are we sure this is the same peer?"
            if (other is SecuredPeerId id)
            {
                if (this.status == PeerStatus.Connected && id.status == PeerStatus.Connected) {
                    unsafe {
                        fixed (byte* p_thPk = this.boxPubkey, p_otPk = id.boxPubkey) {
                            return LibSodium.sodium_memcmp(p_thPk, p_otPk, (UIntPtr)LibSodium.BOX_PK_SIZE)==0;
                        }
                    }
                } else if (this.status == PeerStatus.ClearTextOnly && id.status == PeerStatus.ClearTextOnly) {
                    return  BasePeerManager.CompareIPEndpoints(this.endPoint, id.endPoint);
                } else {
                    return false;
                }
            }
            return false;
        }
        public override bool isLoopback()
        {
            // TODO: determine how a self PeerId is emitted
            if (endPoint is null) return false;
            if (SharedPlatform.PlatformPeerManager?.port != endPoint.Port) return false;
            return BasePeerManager.isLoopback(endPoint.Address);
        }
        public override bool isNetworkLocal()
        {
            if (endPoint is null) return false;
            return BasePeerManager.isEndpointLocal(endPoint);
        }

        public void ValidateCryptStatus(bool peerIsSender = false) {
            switch (this.status) {
                case PeerStatus.Connected:
                    var blackHoleEndPoint = new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999);
                    if (BasePeerManager.CompareIPEndpoints(this.endPoint, blackHoleEndPoint)) {
                        throw new Exception("assertion failed: BlackHole peers cannot be connected");
                    }
                    if ((this.boxPubkey?.Length ?? 0) != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("assertion failed: Correctly initialised pubkey");
                    }
                    break;
                case PeerStatus.ClearTextOnly:
                    if (peerIsSender && isNetworkLocal()) {
                        // only network-local packet entry
                        return;
                    } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                        return;
                    }
                    throw new Exception("assertion failed: Cleartext peers can only exist for local-network broacasts");
                    break;
                default:
                    throw new Exception("bad code update: failed to handle new PeerId status");
                    break;
            }
        }
    }

    public partial class SecuredPeerManager : BasePeerManager, IDisposable
    {
        byte[] connection_sk;
        byte[] connection_pk;

        public enum OuterPacketType: byte {
            CleartextBroadcast_v1 = 0,
            Boxed_v1,
            BoxedWithPubKey_v1,
            VersionError = 255,  // to be sent as an answer to a packet of wrong version
        }
        public enum InnerPacketType : byte {
            Unreliable_v1 = 0,
            Reliable_v1, // and ordered!
            HeartBeat_v1,  // also serves as acknowledgement
            VersionError = 255,
        }

        // Blackhole Endpoint
        // https://superuser.com/questions/698244/ip-address-that-is-the-equivalent-of-dev-null
        public readonly PeerId BlackHole = SecuredPeerId.MakeClearText(new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999));

        class RemotePeer : IDisposable {
            // data for connection itself
            public SecuredPeerId id;
            public byte[] connection_computed_k;


            public ulong TicksSinceLastIncomingPacket = 0;
            public ulong OutgoingPacketAcummulator = 0;

            public Queue<byte[]> outgoingpacket = new Queue<byte[]>();
            public ulong wanted_acknowledgement = 0;  // the 'packet ID' of the last reliable packet ack'd by peer (1-indexed)
            public ulong remote_acknowledgement = 0;  // the 'packet ID' of the last reliable packet recv'd by us  (1-indexed)
            public bool need_begin_conversation_ack = true;

            void IDisposable.Dispose() {
                unsafe {
                    fixed (byte* p_csk = this.connection_computed_k) {
                        LibSodium.sodium_memzero(p_csk, (UIntPtr)LibSodium.BOX_DERVK_SIZE);
                    }
                }
            }

        }

        public SecuredPeerManager(int default_port = DEFAULT_PORT, int port_attempts = FIND_PORT_ATTEMPTS) {
            InitSocket();
            // this.identity_pk = new byte[LibSodium.SIGN_PK_SIZE];
            // this.identity_sk = new byte[LibSodium.SIGN_SK_SIZE];
            this.connection_pk = new byte[LibSodium.BOX_PK_SIZE];
            this.connection_sk = new byte[LibSodium.BOX_SK_SIZE];
            this.ResetKeys();
        }

        public override PeerId GetSelf() {
            return new SecuredPeerId(
                new IPEndPoint(
                    BasePeerManager.getInterfaceAddresses()[0],
                    this.port
                ),
                this.connection_pk
            );
        }
        public override PeerId[] GetBroadcastPeerIDs() {
            List<PeerId> broadcastables = new List<PeerId>();
            for (int broadcast_port = BasePeerManager.DEFAULT_PORT;
                broadcast_port < (BasePeerManager.FIND_PORT_ATTEMPTS + BasePeerManager.DEFAULT_PORT);
                broadcast_port++)
            {
                broadcastables.Add(SecuredPeerId.MakeClearText(new(IPAddress.Broadcast, broadcast_port)));
            }
            return broadcastables.ToArray();
        }

        public /*static*/ override PeerId? GetPeerIdByName(string name) {
            IPEndPoint? endPoint = GetEndPointByName(name);
            if (endPoint is null) return null;
            return new UDPPeerId(endPoint);
        }

        SecuredPeerId GetIdFromEndpoint(IPEndPoint endPoint) {
            RemotePeer? peer = peers.FirstOrDefault(x => CompareIPEndpoints(x.id.endPoint, endPoint));
            if (peer == null) {
                return null;
            } else {
                return peer.id;
            }
        }

        public /*static*/ override string describePeerId(PeerId endPoint, PeerId? serverEndPoint=null){
            var peerId = endPoint as SecuredPeerId;
            if (peerId is null) {
                return "[Bad PeerId type, expected Secured PeerId]";
            }
            return String.Format(
                "[pubkey: {3}, IP: [is machine local: {0}, is network local: {1}, is devnull: {2}]]",
                peerId.isLoopback(),
                isEndpointLocal(peerId.endPoint),
                (endPoint == BlackHole),
                LibSodium.BoxPubKeyToHex(peerId.boxPubkey)
            );
        }

        /// the functions that (de)serialize multiple endpoints at once can deal with the sender seeing itself differently as everyone else.
        /// The functions that do not need a separate mechanism to deal with this.
        public /*static*/ override void SerializePeerIDs(BinaryWriter writer, PeerId[] endPoints, PeerId addressedto, bool includeme = true) {
            // note that outside of Blackhole, only status:connected peerIds can be serialized
            var filteredPeerIDs = endPoints.Select(x => x as SecuredPeerId)
                .Where(x=> x != null).ToArray();
            var dest = addressedto as SecuredPeerId;
            if (dest is null) {return;}

            writer.Write(includeme);
            writer.Write((int)filteredPeerIDs.Length);
            foreach (SecuredPeerId point in filteredPeerIDs) {
                if (point == addressedto) {
                    SerializeIPEndPoint(writer, new IPEndPoint(IPAddress.Loopback, point.endPoint.Port));
                    continue;
                }
                SerializeIPEndPoint(writer, point.endPoint);
                if (point != ((SecuredPeerId)BlackHole)) {
                    if (point.boxPubkey.Length != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("bad pubkey length, something fucked up bad");
                    }
                    writer.Write(point.boxPubkey);
                }
            }
        }

        public /*static*/ override PeerId[] DeserializePeerIDs(BinaryReader reader, PeerId fromWho) {
            SecuredPeerId? sender = fromWho as SecuredPeerId;
            if (sender is null) {throw new Exception("bad PeerId as sender");}

            bool includesender = reader.ReadBoolean();
            SecuredPeerId[] ret = new SecuredPeerId[reader.ReadInt32() + (includesender? 1 : 0)];
            int i = 0;
            if (includesender) {
                ret[i] = sender;
                ++i;
            }

            for (; i != ret.Length; i++) {
                IPEndPoint endPoint = DeserializeIPEndPoint(reader);
                if (CompareIPEndpoints(endPoint, new IPEndPoint(IPAddress.Loopback, this.port))) {
                    ret[i] = new SecuredPeerId(endPoint, this.connection_pk);
                } else if (CompareIPEndpoints(endPoint, ((SecuredPeerId)BlackHole).endPoint)) {
                    ret[i] = (SecuredPeerId)BlackHole;
                } else {
                    byte[] pubkey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                    ret[i] = new SecuredPeerId(endPoint, pubkey);
                }
            }
            return ret.ToArray();
        }

        public /*static*/ override void SerializePeerId(BinaryWriter writer, PeerId peerId) {
            SecuredPeerId? truePeerId = peerId as SecuredPeerId;
            if (truePeerId is null) {throw new Exception("bad PeerId to serialize");}
            BasePeerManager.SerializeIPEndPoint(writer, truePeerId.endPoint);
            if (truePeerId.boxPubkey.Length != LibSodium.BOX_PK_SIZE) {
                throw new Exception("bad pubkey length, something fucked up bad");
            }
            writer.Write(truePeerId.boxPubkey);
        }
        public /*static*/ override PeerId DeserializePeerId(BinaryReader reader) {
            return new SecuredPeerId(
                BasePeerManager.DeserializeIPEndPoint(reader),
                reader.ReadBytes(LibSodium.BOX_PK_SIZE)
            );
        }

        List<RemotePeer> peers = new();
        bool _allow_unsecure_creation = false;
        RemotePeer? GetRemotePeer(PeerId peerId, bool make_one = false) {
            var securedPeerId = peerId as SecuredPeerId;
            if (securedPeerId is null) return null;
            RemotePeer? peer = peers.FirstOrDefault(x => x.id == securedPeerId);
            if (peer == null && make_one) {
                if (securedPeerId.status == SecuredPeerId.PeerStatus.ClearTextOnly) {
                    throw new Exception("Let's see what actually requests cleartext peers from the outside");
                }
                peer = new RemotePeer() {id = securedPeerId};
                peers.Add(peer);
            }

            return peer;
        }

        public override void EnsureRemotePeerCreated(PeerId peerId) {
            GetRemotePeer(peerId, true);
        }

        void ForgetPeer(RemotePeer peer) {
            peers.Remove(peer);  // remove first, in case this peer's removal callback recurses into here
            Run_OnPeerForgotten(peer.id);
        }
        public override void ForgetPeer(PeerId peerId) {
            var secPeerId = peerId as SecuredPeerId;
            var remove_peers = peers.FindAll(x => secPeerId == x.id);
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
            var secPeerId = peerId as SecuredPeerId;
            if (secPeerId == null) {
                throw new Exception("cannot send packet to wrong kind of PeerId");
            }
            secPeerId.ValidateCryptStatus();
            if (GetRemotePeer(peerId, true) is RemotePeer peer) {
                switch (packet_type) {
                    case PacketType.UnreliableBroadcast:
                        if (secPeerId.status != SecuredPeerId.PeerStatus.ClearTextOnly) {
                            throw new Exception("Broadcast packets can only be sent as cleartext");
                        }
                        SendRaw(packet, peer, InnerPacketType.Unreliable_v1, OuterPacketType.CleartextBroadcast_v1);
                        break;
                    case PacketType.Unreliable:
                        if (secPeerId.status == SecuredPeerId.PeerStatus.ClearTextOnly) {
                            throw new Exception("Non-broadcast packets cannot be sent as cleartext");
                        }
                        if (begin_conversation) {
                            SendRaw(packet, peer, InnerPacketType.Unreliable_v1, OuterPacketType.BoxedWithPubKey_v1);
                        } else {
                            SendRaw(packet, peer, InnerPacketType.Unreliable_v1, OuterPacketType.Boxed_v1);
                        }
                        break;
                    case PacketType.Reliable:
                        if (secPeerId.status == SecuredPeerId.PeerStatus.ClearTextOnly) {
                            throw new Exception("Non-broadcast packets cannot be sent as cleartext");
                        }

                        if (begin_conversation && !peer.need_begin_conversation_ack) {
                            SharedCodeLogger.Debug("redundant begin_conversation flag? adding this flag to the next Reliable packet sent, which might not be the one currently queued.");
                            peer.need_begin_conversation_ack = true;
                        }
                        if (!peer.outgoingpacket.Any()) {
                            // send immediately if there are no pending packets
                            if (begin_conversation) {
                                SendRaw(packet, peer, InnerPacketType.Reliable_v1, OuterPacketType.BoxedWithPubKey_v1);
                            } else {
                                SendRaw(packet, peer, InnerPacketType.Reliable_v1, OuterPacketType.Boxed_v1);
                            }
                        }
                        peer.outgoingpacket.Enqueue(packet);
                        break;
                }
            } else SharedCodeLogger.Error("Failed to get remote peer");
        }

        void SendRaw(byte[] packet, RemotePeer peer, InnerPacketType innerType, OuterPacketType outerType) {
            int extraLength = 1;
            switch (innerType) {
            case InnerPacketType.Unreliable_v1:
                break;
            case InnerPacketType.Reliable_v1:
                extraLength = 1 + sizeof(ulong);
                break;
            case InnerPacketType.HeartBeat_v1:
                extraLength = 1 + sizeof(ulong);
                break;
            default:
                throw new Exception("unknown inner Packet type... bad code update?");
            };
            if ((extraLength + packet.Length) == 0) return;

            int clearLength = extraLength + packet.Length;
            byte[] clearText = null;

            using (MemoryStream stream = new(packet.Length + extraLength))
            using (BinaryWriter writer = new(stream))
            {
                writer.Write((byte)innerType);
                if (innerType == InnerPacketType.Reliable_v1)
                {
                    writer.Write(peer.wanted_acknowledgement + 1);
                }
                else if (innerType == InnerPacketType.HeartBeat_v1)
                {
                    writer.Write(peer.remote_acknowledgement);
                }
                writer.Write(packet);

                clearText = stream.GetBuffer();
            }

            switch (outerType) {
            case OuterPacketType.Boxed_v1:
                extraLength = 1 + sizeof(UInt16) + LibSodium.BOX_NONCE_SIZE + LibSodium.BOX_MAC_SIZE;
                break;
            case OuterPacketType.BoxedWithPubKey_v1:
                extraLength = 1 + LibSodium.BOX_PK_SIZE + sizeof(UInt16) + LibSodium.BOX_NONCE_SIZE + LibSodium.BOX_MAC_SIZE;
                break;
            case OuterPacketType.CleartextBroadcast_v1:
                extraLength = 1 + sizeof(UInt16);
                break;
            default:
                throw new Exception("unknown outer Packet type... bad code update?");
            };

            using (MemoryStream stream = new(extraLength + clearLength))
            using (BinaryWriter writer = new(stream))
            {
                writer.Write((byte)outerType);
                if (outerType == OuterPacketType.CleartextBroadcast_v1) {
                    writer.Write((UInt16)clearLength);
                    writer.Write(clearText);
                } else {
                    if (outerType == OuterPacketType.BoxedWithPubKey_v1) {
                        writer.Write(connection_pk);
                    }
                    writer.Write((UInt16)clearLength);
                    byte[] nonce = GetNonce();
                    writer.Write(nonce);
                    writer.Write(SodiumEncodePacket(clearText, nonce, extraLength + packet.Length, peer));
                }
                socket.SendTo(stream.GetBuffer(), peer.id.endPoint);
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
                    SharedCodeLogger.Error($"Forgetting {describePeerId(peer.id)} due to Timeout, Timeout is {timeoutTime}ms");
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
                        if (peer.need_begin_conversation_ack) {
                            SendRaw(peer.outgoingpacket.Peek(), peer, InnerPacketType.Reliable_v1, OuterPacketType.BoxedWithPubKey_v1);
                        } else {
                            SendRaw(peer.outgoingpacket.Peek(), peer, InnerPacketType.Reliable_v1, OuterPacketType.Boxed_v1);
                        }
                    }
                    else
                    {
                        SendRaw(
                            Array.Empty<byte>(),
                            peer,
                            InnerPacketType.HeartBeat_v1,
                            OuterPacketType.Boxed_v1
                        );
                    }
                }
            }

            foreach (var peer in peersToRemove) ForgetPeer(peer);
        }

        public override byte[]? Recieve(out PeerId? sender) {
            sender = null;

            if (socket.Available == 0) {
                return null;
            }

            EndPoint senderEndPoint = new IPEndPoint(IPAddress.Loopback, 8720);

            byte[] rawBuffer;
            byte[] cleartextBuffer;
            int len = 0;
            try {
                rawBuffer = new byte[socket.Available];
                len = socket.ReceiveFrom(rawBuffer, ref senderEndPoint);
            } catch (Exception except) {
                SharedCodeLogger.Error(except);
                return null;
            }
            IPEndPoint? ipsender = senderEndPoint as IPEndPoint;
            if (ipsender == null) return null;
            SecuredPeerId remoteId = null;
            RemotePeer peer = null;

            try {
                using (MemoryStream stream = new(rawBuffer, 0, len, false))
                using (BinaryReader reader = new(stream)) {
                    OuterPacketType? type = reader.ReadByte() as OuterPacketType?;
                    if (type==null) {
                        SharedCodeLogger.Error("unknown packet type!");
                        // TODO: error handling
                        return null;
                    } else if (type == OuterPacketType.VersionError) {
                        SharedCodeLogger.Error("Peer does not know our packet format! make sure all peers use compatible versions of Rain Meadow");
                        return null;
                    } else if (type == OuterPacketType.CleartextBroadcast_v1) {
                        SecuredPeerId possibleExistingId = GetIdFromEndpoint(ipsender);
                        if (possibleExistingId != null) {
                            SharedCodeLogger.Error("Existing peer should not switch to cleartext communications!");
                            return null;
                        }
                    } else if (type == OuterPacketType.BoxedWithPubKey_v1) {
                        byte[] pubKey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                        SecuredPeerId newId = new SecuredPeerId(ipsender, pubKey);
                        SecuredPeerId possibleExistingId = GetIdFromEndpoint(ipsender);
                        if (possibleExistingId != null) {
                            if (newId != possibleExistingId) {
                                SharedCodeLogger.Error("Change of pubkey halfway through? IDK, looks kinda sus to me!");
                                return null;
                            }
                        } else {
                            EnsureRemotePeerCreated(newId);
                            remoteId = newId;
                        }
                    } else if (type == OuterPacketType.Boxed_v1) {
                        remoteId = GetIdFromEndpoint(ipsender);
                        if (remoteId == null) {
                            SharedCodeLogger.Error("Received encrypted packet from unknown peer: nothing to do");
                            return null;
                        }
                    }

                    // checks done, now get the inner packet:
                    UInt16 packetSize = reader.ReadUInt16();
                    peer = GetRemotePeer(remoteId);
                    if (peer == null) {
                        throw new Exception("sanity check failed: somehow no peer mapped to peerId despite a decrypted packet");
                    }
                    if (type == OuterPacketType.CleartextBroadcast_v1) {
                        // TODO: uuuuuugh this is a mess
                        cleartextBuffer = reader.ReadBytes((int)packetSize);
                    } else {
                        byte[] nonce = reader.ReadBytes(LibSodium.BOX_NONCE_SIZE);
                        cleartextBuffer = SodiumDecodePacket(
                            reader.ReadBytes((int)packetSize + LibSodium.BOX_MAC_SIZE),
                            nonce,
                            packetSize,
                            peer
                        );
                        if (cleartextBuffer == null) {
                            SharedCodeLogger.Error("Failed to decrypt packet");
                            return null;
                        }
                    }
                }

                using (MemoryStream stream = new(cleartextBuffer, 0, cleartextBuffer.Length, false))
                using (BinaryReader reader = new(stream)) {
                    InnerPacketType? innerType = reader.ReadByte() as InnerPacketType?;
                    if (innerType==null) {
                        SharedCodeLogger.Error("unknown packet type!");
                        // TODO: error handling
                        return null;
                    } else if (innerType == InnerPacketType.VersionError) {
                        SharedCodeLogger.Error("Peer does not know our packet format! make sure all peers use compatible versions of Rain Meadow");
                        return null;
                    }

                    if (peer != null) peer.TicksSinceLastIncomingPacket = 0;

                    switch (innerType) {
                        case InnerPacketType.Unreliable_v1:
                            return reader.ReadBytes(cleartextBuffer.Length - 1);

                        case InnerPacketType.Reliable_v1:

                            ulong wanted_ack = reader.ReadUInt64();
                            byte[]? new_data = null;

                            if (EventMath.IsNewer(wanted_ack, peer.remote_acknowledgement)) {
                                peer.remote_acknowledgement++ ;
                                if (EventMath.IsNewer(wanted_ack, peer.remote_acknowledgement)) {
                                    SharedCodeLogger.Error("Reliable Packet too advanced! We have skipped a packet in an ordered stream of packets!");
                                    peer.remote_acknowledgement = wanted_ack;
                                }
                                new_data = reader.ReadBytes(cleartextBuffer.Length - 1 - sizeof(ulong));
                            }
                            SendRaw(//TODO
                                Array.Empty<byte>(),
                                peer,
                                InnerPacketType.HeartBeat_v1,
                                OuterPacketType.Boxed_v1
                            );
                            return new_data;
                        case InnerPacketType.HeartBeat_v1:
                            peer.need_begin_conversation_ack = false;  // TODO
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
                }
            } catch (Exception except) {
                SharedCodeLogger.Debug(except);
                SharedCodeLogger.Debug($"Error: {except.Message}");
                return null;
            }
        }


        void IDisposable.Dispose() {
            unsafe{
                fixed(byte* p_bpk = this.connection_pk, p_bsk = this.connection_sk) {
                    //LibSodium.sodium_memzero(this.identity_pk, (UIntPtr)LibSodium.SIGN_PK_SIZE);
                    //LibSodium.sodium_memzero(this.identity_sk, (UIntPtr)LibSodium.SIGN_SK_SIZE);
                    LibSodium.sodium_memzero(p_bpk, (UIntPtr)LibSodium.BOX_PK_SIZE);
                    LibSodium.sodium_memzero(p_bsk, (UIntPtr)LibSodium.BOX_SK_SIZE);
                }
            }

            socket.Dispose();
            _isDisposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
