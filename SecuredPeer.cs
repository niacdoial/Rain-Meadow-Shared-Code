using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
//using System.Security.Cryptography;
using Sodium;

/// //////////////////////////////////////////
/// BasePeer describes the common interface for the lowest part of the network stack (for non-steam networking): Peer management
/// This file describes a variant of that that includes encryption
///
/// Internally, the packets have two types:
/// - an Outer type that indicates the structure up to the cyphertext (including the cleartext length, and also implicitly the exact overhead of encryption)
/// - an Inner type that indicates the structure within the cleartext
///
/// Currently, as all cryptographic material is generated while setting everything up, there is no way to properly identify peers.
/// For now, we only ensure that communications cannot be intercepted or rewritten.
/// This might not be the best model for public lobbies where any stranger using Rain Meadow is allowed,
/// but at least the arrival of a new player leaves traces, unlike network snooping.
/// This is more useful for password-protected lobbies, assuming the password is shared over a secure-enough channel,
/// as no information (from player list, chat messages, game updates) should be transmitted to someone that has not completed the password check. // TODO
///
///
/// The main threat model for the moment is this:
/// - in LAN contexts, somebody might be trying to snoop on connections
/// - in Routed (worldwide) contexts, somebody might be trying to snoop or MITM
///
/// Peers come in three statuses:
/// - ClearTextOnly, for Broadcast packets (and that only)
/// - Unknown, for peers whose public key is not yet known (note that those can only be created locally, typically through the Direct Connect menu)
///   - in general, they are only allowed to exist for a player that is currently contacting a lobby's server (Routed) or host player (LAN) but only knows the IP Endpoint.
///   - they cannot occur for the sender of a given packet, as previously-unknown peers are assumed to introduce themselves by presenting their public key.
///     (and, in Routed lobbies, only the server is expected to receive unannounced peers) // TODO
/// - Connected, for peers whose IP endpoint and public key are known.
///   - They are the only type of PeerId allowed through serialisation.
///
/// Protections against downgrading the peer type:
/// - ClearTextOnly broadcast can only be sent to broadcast IPs
/// - ClearTextOnly peers can only be created for incoming packets if they come from network-local addresses
/// - ClearTextOnly peers can only be created on IP Endpoints where no existing peer exist (ClearTextOnly peers are not remembered)
/// - TODO: how to switch from broadcasted advertisement to unicast connection? where does the pubkey come from?
/// - Unknown peers can only be used to send public key sollicitations
/// - Unknown peers cannot be serialised through the network, and cannot be created upon receiving a packet
///
/// Protections against about MITMing:
/// - It is true that in LAN contexts, and the server in Routed contexts, do not check the public key of previously-unknown peers
/// - However, players in Routed contexts do not accept unsollicited packets // TODO check
/// - It is up to the Routed players to either know the public key in advance (transmitted by the HTTPS-based matchmaking server or the direct-connect endpoint)
///   or check it in a popup (if the key is given in reply to a PubKey sollicitation packet)
/// - This won't prevent MITM-capable bad actors to pretend to be a specific player to the server, but since the true player breaks the connection,
///   the bad actor can only pretend to be "yet another player", and are bound to either fail a password check, or leave traces of their arrival for public lobbies.
///
/// Protections against other things:
/// - TODO: make sure that the host is actually informed when somebody is "in enough" to receive chat messages
///   (otherwise an attacker can create a modified client that doesn't complete the spin-RPC-layer-up process)
///
///
/// Future plan: add a permanent player ID to each player through simple signatures:
/// - This would increase the PeerManager's guarantees
///   from "nobody's snooping/MITMing without being another player"
///   to "when I receive a meaningful packet from somebody, I know it comes from them"
/// - authentication would occur by signing the pair of communication pubkeys between machines, plus some extra metadata like a version number?
/// - the big challenge is to mix this guarantee with packets that are routed through the server.
///   - properly signing messages for game updates would be too slow, likely
///   - relying on the communication channel between players being sign is possible, but it means that proxied message need to be proxied as cyphertext, meaning more routing info is needed
///     - the best way is to have two cyphertext payloads for the same nonce, one for the server (redirection/provenence info) and one for the destination
///     - this means 24 bytes of added overhead (encrypted packets already have 44 bytes of overhead while the UDP peermanager has 1)
///

namespace RainMeadow.Shared
{

    public class SecuredPeerId : PeerId {

        // TODO: ClearTextOnly reception is jank: lobby enumeration needs to feed the pubkeys
        public enum PeerStatus: byte {
            ClearTextOnly = 0,  // network-local broadcast purposes, also allowed for the BlackHole placeholder
            Unknown,  // one current use case: connect to a server then asking the user to double-check the pubkey
            Connected,  // Has a known connection pubkey
        }

        public PeerStatus status;
        public IPEndPoint endPoint;
        public byte[] boxPubkey;

        public SecuredPeerId(IPEndPoint endPoint, byte[] boxPubkey) {
            this.status = PeerStatus.Connected;
            this.endPoint = endPoint;
            this.boxPubkey = boxPubkey;
            if (boxPubkey != null && boxPubkey.Length != LibSodium.BOX_PK_SIZE) {
                throw new Exception("malformed pubkey: wrong size");
            }
        }
        public static SecuredPeerId MakeClearText(IPEndPoint endPoint) {
            SecuredPeerId newSelf = new SecuredPeerId(endPoint, null);
            newSelf.status = PeerStatus.ClearTextOnly;
            return newSelf;
        }
        public static SecuredPeerId MakeUnknown(IPEndPoint endPoint) {
            SecuredPeerId newSelf = new SecuredPeerId(endPoint, null);
            newSelf.status = PeerStatus.Unknown;
            return newSelf;
        }

        public bool Equals(SecuredPeerId id)
        {
            if (this.status == PeerStatus.Connected && id.status == PeerStatus.Connected) {
                return ComparePubKeys(this.boxPubkey, id.boxPubkey);
            } else if (this.status == PeerStatus.Unknown && id.status == PeerStatus.Unknown) {
                return  BasePeerManager.CompareIPEndpoints(this.endPoint, id.endPoint);
            } else if (this.status == PeerStatus.ClearTextOnly && id.status == PeerStatus.ClearTextOnly) {
                return  BasePeerManager.CompareIPEndpoints(this.endPoint, id.endPoint);
            } else {
                return false;
            }
        }

        public static bool ComparePubKeys(byte[] first, byte[] second) {
            unsafe {
                fixed (byte* p_thPk = first, p_otPk = second) {
                    return LibSodium.sodium_memcmp(p_thPk, p_otPk, (UIntPtr)LibSodium.BOX_PK_SIZE)==0;
                }
            }
        }

        public override bool Equals(PeerId other)
        {
            // note that this equality function just means "are we sure this is the same peer?"
            if (other is SecuredPeerId id)
            {
                return Equals(id);
            }
            return false;
        }
        public override bool CompareAndUpdate(PeerId other) {
            // note that this equality function just means "are we sure this is the same peer?"
            if (other is SecuredPeerId id)
            {
                if (this.status == PeerStatus.Unknown && id.status == PeerStatus.Connected) {
                    if (BasePeerManager.CompareIPEndpoints(this.endPoint, id.endPoint)) {
                        this.boxPubkey = id.boxPubkey;
                        this.status = PeerStatus.Connected;
                        return true;
                    } else {
                        return false;
                    }
                } else {
                    return Equals(id);
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

        public void ValidateCryptStatus(bool peerIsSender = false, bool forClearText = false, bool internalChecksOnly = false) {
            var blackHoleEndPoint = new IPEndPoint(IPAddress.Parse("253.253.253.253"), 999);
            switch (this.status) {
                case PeerStatus.Unknown:
                    if (peerIsSender && !internalChecksOnly) {
                        throw new Exception("assertion failed: unknown-encryption peers can only be message recipients, not senders");
                    }
                    if (forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: peer must be suited for encrypted");
                    }
                    if (BasePeerManager.CompareIPEndpoints(this.endPoint, blackHoleEndPoint)) {
                        throw new Exception("assertion failed: BlackHole peers must be cleartext");
                    } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                        throw new Exception("assertion failed: Broadcast peers must be cleartext");
                    }
                    break;
                case PeerStatus.Connected:
                    if (forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: peer must be suited for encrypted");
                    }
                    if (BasePeerManager.CompareIPEndpoints(this.endPoint, blackHoleEndPoint)) {
                        throw new Exception("assertion failed: BlackHole peers must be cleartext");
                    } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                        throw new Exception("assertion failed: Broadcast peers must be cleartext");
                    }
                    if ((this.boxPubkey?.Length ?? 0) != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("assertion failed: Correctly initialised pubkey");
                    }
                    break;
                case PeerStatus.ClearTextOnly:
                    if (! (forClearText || internalChecksOnly)) {
                        throw new Exception("assertion failed: peer must be suited for cleartext communications");
                    }
                    if ((peerIsSender || internalChecksOnly) && isNetworkLocal()) {
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
            RequestPubKey_v1,
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
            var parts = name.Split('@');
            IPEndPoint? endPoint = null;
            byte[] pubKey = new byte[0];

            if (parts.Count() == 2) {
                if (parts[0].Length != 2*LibSodium.BOX_PK_SIZE) return null;
                endPoint = GetEndPointByName(parts[1]);
                if (endPoint is null) return null;
                pubKey = LibSodium.BoxPubKeyFromHex(parts[0]);
                return new SecuredPeerId(endPoint, pubKey);
            } else if (parts.Count() == 1) {
                endPoint = GetEndPointByName(parts[0]);
                if (endPoint is null) return null;
                return SecuredPeerId.MakeUnknown(endPoint);
            } else {
                return null;
            }
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
            var pubkeyString = "[NULL]";
            if (peerId.boxPubkey != null) {
                pubkeyString = LibSodium.BoxPubKeyToHex(peerId.boxPubkey);
            }

            return String.Format(
                "[pubkey: {3}, IP: [is machine local: {0}, is network local: {1}, is devnull: {2}]]",
                peerId.isLoopback(),
                isEndpointLocal(peerId.endPoint),
                (endPoint == BlackHole),
                pubkeyString
            );
        }

        public string GetGenericInviteCode() {
            var invitecode = LibSodium.BoxPubKeyToHex(this.connection_pk);
            return $"{invitecode}@X.X.X.X:{this.port}";
        }

        /// the functions that (de)serialize multiple endpoints at once can deal with the sender seeing itself differently as everyone else.
        /// The functions that do not need a separate mechanism to deal with this.
        public /*static*/ override void SerializePeerIDs(BinaryWriter writer, PeerId[] endPoints, PeerId addressedto, bool includeme = true) {
            // note that outside of Blackhole, only status:connected peerIds can be serialized
            var filteredPeerIDs = endPoints.Select(x => x as SecuredPeerId)
                .Where(x=> x != null).ToArray();
            if (filteredPeerIDs.Where(x => x.status != SecuredPeerId.PeerStatus.Connected).Count()>0) {
                throw new Exception("Serialisation only allowed if all peers serialised have known pubkeys!");
            }
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
            if (truePeerId.status != SecuredPeerId.PeerStatus.Connected) {throw new Exception("cannot serialize peer with no pubkey");}
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
        RemotePeer? GetRemotePeer(SecuredPeerId peerId, bool makeOrUpdate = false) {
            if (makeOrUpdate) {
                RemotePeer? peer = peers.FirstOrDefault(x => x.id.CompareAndUpdate(peerId));
                if (peer == null) {
                    peerId.ValidateCryptStatus(false, false, true);
                    peer = new RemotePeer() {id = peerId};
                    if (peerId.status != SecuredPeerId.PeerStatus.ClearTextOnly) {
                        peers.Add(peer);  // Cleartext (=broadcast) peers are not to be remembered
                    }
                }
                return peer;
            } else {
                return peers.FirstOrDefault(x => x.id == peerId);
            }
        }

        public override void EnsureRemotePeerCreated(PeerId peerId) {
            SecuredPeerId? securedPeerId = peerId as SecuredPeerId;
            if (securedPeerId == null) return;
            GetRemotePeer(securedPeerId, true);
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
            if (GetRemotePeer(secPeerId, true) is RemotePeer peer) {
                switch (packet_type) {
                    case PacketType.UnreliableBroadcast:
                        secPeerId.ValidateCryptStatus(false, true);
                        SendRaw(packet, peer, InnerPacketType.Unreliable_v1, OuterPacketType.CleartextBroadcast_v1);
                        break;
                    case PacketType.Unreliable:
                        secPeerId.ValidateCryptStatus(false, false);
                        if (begin_conversation) {
                            SendRaw(packet, peer, InnerPacketType.Unreliable_v1, OuterPacketType.BoxedWithPubKey_v1);
                        } else {
                            SendRaw(packet, peer, InnerPacketType.Unreliable_v1, OuterPacketType.Boxed_v1);
                        }
                        break;
                    case PacketType.Reliable:
                        secPeerId.ValidateCryptStatus(false, false);

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
            // if the peer is not yet ready for encrypted communications, make sure not to do anything until that part is set up
            if (peer.id.status == SecuredPeerId.PeerStatus.Unknown) {
                if (innerType == InnerPacketType.Unreliable_v1) {
                    SharedCodeLogger.Error("Discarding unreliable packet for peer with unknown public key");
                }
                var buffer = new byte[connection_pk.Length +1];
                buffer[0] = (byte)OuterPacketType.RequestPubKey_v1;
                Buffer.BlockCopy(connection_pk, 0, buffer, 1, connection_pk.Length);
                socket.SendTo(
                    buffer,
                    peer.id.endPoint
                );
                return;
            }

            // first compute the "added bits" prepended in cleartext
            int extraLength = 1;
            switch (innerType) {
            case InnerPacketType.Unreliable_v1:
            case InnerPacketType.VersionError:
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
                if (innerType != InnerPacketType.VersionError) {
                    writer.Write(packet);
                }

                clearText = stream.GetBuffer();
            }

            // then compute the "added bits" added before the cyphertext (extraLength includes the fact that cyphertext is longer than cleartext)
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
            case OuterPacketType.VersionError:
                socket.SendTo(new byte[1]{(byte)OuterPacketType.VersionError}, peer.id.endPoint);
                return;
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
                    var cypherText = SodiumEncodePacket(clearText, nonce, clearLength, peer);
                    if (cypherText == null) {
                        SharedCodeLogger.Error("Failed to encrypt packet");
                    }
                    writer.Write(cypherText);
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

        public override byte[]? Receive(out PeerId? sender) {
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
            SecuredPeerId remoteId = GetIdFromEndpoint(ipsender);
            RemotePeer peer = null;

            try {
                using (MemoryStream stream = new(rawBuffer, 0, len, false))
                using (BinaryReader reader = new(stream)) {
                    byte outTyRaw = reader.ReadByte();
                    OuterPacketType? outerType = null;
                    try {outerType = (OuterPacketType)outTyRaw;}
                    catch {}
                    byte[] pubKey = null;
                    SecuredPeerId newId = null;

                    switch (outerType) {
                    case OuterPacketType.Boxed_v1:
                        if (remoteId == null) {
                            SharedCodeLogger.Error("Received encrypted packet from unknown peer: nothing to do");
                            return null;
                        }
                        remoteId.ValidateCryptStatus(true, false);
                        break;
                    case OuterPacketType.CleartextBroadcast_v1:
                        if (remoteId != null) {
                            SharedCodeLogger.Error("Existing peer should not switch to cleartext communications!");
                            return null;
                        }
                        remoteId.ValidateCryptStatus(true, true);
                        break;
                    case OuterPacketType.BoxedWithPubKey_v1:
                        pubKey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                        newId = new SecuredPeerId(ipsender, pubKey);
                        newId.ValidateCryptStatus(true, false);
                        if (remoteId != null) {
                            // reminder: the only "updates" possible are upgrades from PeerStatus.Unknown to PeerStatus.Connected
                            if (!remoteId.CompareAndUpdate(newId)) {
                                SharedCodeLogger.Error("Change of pubkey halfway through? IDK, looks kinda sus to me!");
                                return null;
                            }
                            remoteId.ValidateCryptStatus(true, false);
                        } else {
                            EnsureRemotePeerCreated(newId);
                            remoteId = newId;
                        }
                        break;
                    case OuterPacketType.RequestPubKey_v1:
                        pubKey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                        if (remoteId == null) {
                            newId = new SecuredPeerId(ipsender, pubKey);
                            newId.ValidateCryptStatus(false, false);
                            peer = GetRemotePeer(newId, true);
                            SendRaw(new byte[0], peer, InnerPacketType.Unreliable_v1, OuterPacketType.BoxedWithPubKey_v1);
                        } else {
                            if (remoteId.status == SecuredPeerId.PeerStatus.Unknown) {
                                // if we connected to a peer without knowing its pubkey, we need to ask the user if the key's correct
                                // TODO WRONG PLACE DUMBARSE
                                if (Run_ConfirmCallback("Is the following public key the one you expect for this lobby?", LibSodium.BoxPubKeyToHex(pubKey))) {
                                    remoteId.status = SecuredPeerId.PeerStatus.Connected;
                                    remoteId.boxPubkey = pubKey;
                                    remoteId.ValidateCryptStatus(false, false);
                                    peer = GetRemotePeer(remoteId);
                                    SendRaw(new byte[0], peer, InnerPacketType.Unreliable_v1, OuterPacketType.BoxedWithPubKey_v1);
                                } else {
                                    SharedCodeLogger.Error("Player rejected this peer's pubkey");
                                }
                            } else if (remoteId.status == SecuredPeerId.PeerStatus.Connected && SecuredPeerId.ComparePubKeys(remoteId.boxPubkey, pubKey)) {
                                remoteId.ValidateCryptStatus(false, false);
                                peer = GetRemotePeer(remoteId);
                                SendRaw(new byte[0], peer, InnerPacketType.Unreliable_v1, OuterPacketType.BoxedWithPubKey_v1);
                            } else {
                                SharedCodeLogger.Error("peer: " + remoteId.status.ToString() + " / " + describePeerId(remoteId));
                                SharedCodeLogger.Error(
                                    "Change of pubkey (" + LibSodium.BoxPubKeyToHex(remoteId.boxPubkey)
                                    + "->" + LibSodium.BoxPubKeyToHex(pubKey) +
                                    ") halfway through? IDK, looks kinda sus to me!"
                                );
                            }
                        }
                        return null;
                        break;
                    case OuterPacketType.VersionError:
                        SharedCodeLogger.Error("Peer does not know our packet format! make sure all peers use compatible versions of Rain Meadow");
                        return null;
                        break;
                    default:
                        SharedCodeLogger.Error("unknown packet outerType: " + outTyRaw.ToString() + "!");
                        remoteId.ValidateCryptStatus(false, false);
                        SendRaw(new byte[0], GetRemotePeer(remoteId), InnerPacketType.Unreliable_v1, OuterPacketType.VersionError);
                        return null;
                        break;
                    }

                    // checks done, now get the inner packet:
                    UInt16 packetSize = reader.ReadUInt16();
                    peer = GetRemotePeer(remoteId);
                    if (peer == null) {
                        throw new Exception("sanity check failed: somehow no peer mapped to peerId despite a decrypted packet");
                    }
                    if (outerType == OuterPacketType.CleartextBroadcast_v1) {
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
                    byte inTyRaw = reader.ReadByte();
                    InnerPacketType? innerType = null;
                    try {innerType = (InnerPacketType)inTyRaw;}
                    catch {}
                    if (innerType==null) {
                        SharedCodeLogger.Error("unknown packet innerType:" + inTyRaw.ToString() +"!");
                        SendRaw(new byte[0], peer, InnerPacketType.VersionError, OuterPacketType.Boxed_v1);
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
                            SendRaw(
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
