using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Sodium;


/// //////////////////////////////////////////
/// This file describes the lowest part of the network stack (for non-steam networking): Peer management
///
/// This layer is only responsible for properly keeping track of raw connections to other machines (players or lobby server),
/// though this connection is also responsible for its own encryption.
///
/// The main concepts are:
/// - the PeerId object, each instance of which uniquely identifies another machine on the network, and (if transmitted over the network) allows to create a connection to said machine.
///   The PeerManager class is also responsible for serialising/deserialising one or many PeerIds at once.
/// - Sending/Receiving packets: this sends/returns the byte sequences used by the higher layers of the network stack, and uses a PeerId object to choose/tell which other machine is involved.
///   packets (visible outside of that layer) come in three flavours:
///   - Reliable (ordered, reliable packets to/from a single machine),
///   - Unreliable (unordered, unreliable packets to/from a single machine),
///   - Broadcast (unordered, unreliable packets to many machines, but from a single one), only used in LAN contexts to advertise one's presence
/// - though, internally other packet types exist, to make the peer management system itself work
/// - IP tools: a lot of utility functions to deal with IP EndPoints are present in this base class.
///
///
///
/// Here is how this works in more detail
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
/// - However, players in Routed contexts do not accept unsollicited packets // TODO
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

    public partial class PeerManager: IDisposable
    {
        public Socket socket;
        public int port;

        public const int MTU = 1500;  // 1500 is the MTU for general internet communications
        public const int DEFAULT_PORT = 8720;
        public const int FIND_PORT_ATTEMPTS = 8; // 8 players somehow hosting from the same machine is ridiculous.
        public byte[] reusableRecvBuffer = new byte[MTU];

        byte[] connection_sk;
        byte[] connection_pk;

        /// The PacketType enum to be used by what calls the PeerManager's functions
        public enum PacketType : byte
        {
            Unreliable = 0,
            UnreliableBroadcast,
            Reliable, // and ordered!
        }

        public enum PacketSecurity: byte {
            CleartextBroadcast_v1 = 0,
            Boxed_v1,
            BoxedWithPubKey_v1,
            RequestPubKey_v1,
            VersionError = 255,  // to be sent as an answer to a packet of wrong version
        }
        public enum RawPacketType : byte {
            Unreliable_v1 = 0,
            Reliable_v1, // and ordered!
            HeartBeat_v1,  // also serves as acknowledgement
            VersionError = 255,
        }

        public PeerManager(int default_port = DEFAULT_PORT, int port_attempts = FIND_PORT_ATTEMPTS) {
            BlackHole = PeerId.MakeClearText(PeerId.BlackHoleEndPoint);

            InitSocket(default_port, port_attempts);
            // this.identity_pk = new byte[LibSodium.SIGN_PK_SIZE];
            // this.identity_sk = new byte[LibSodium.SIGN_SK_SIZE];
            this.connection_pk = new byte[LibSodium.BOX_PK_SIZE];
            this.connection_sk = new byte[LibSodium.BOX_SK_SIZE];
            this.ResetKeys();
        }

        public void Send(byte[] packet, PeerId peerId, PacketType packet_type = PacketType.Reliable, bool begin_conversation = false) {
            if (peerId == null) {
                throw new Exception("cannot send packet to wrong kind of PeerId");
            }
            if (GetRemotePeer(peerId, true) is RemotePeer peer) {
                switch (packet_type) {
                    case PacketType.UnreliableBroadcast:
                        peerId.ValidateCryptStatus(false, true);
                        SendRaw(packet, peer, RawPacketType.Unreliable_v1, PacketSecurity.CleartextBroadcast_v1);
                        break;
                    case PacketType.Unreliable:
                        peerId.ValidateCryptStatus(false, false);
                        if (begin_conversation) {
                            SendRaw(packet, peer, RawPacketType.Unreliable_v1, PacketSecurity.BoxedWithPubKey_v1);
                        } else {
                            SendRaw(packet, peer, RawPacketType.Unreliable_v1, PacketSecurity.Boxed_v1);
                        }
                        break;
                    case PacketType.Reliable:
                        peerId.ValidateCryptStatus(false, false);

                        if (begin_conversation && !peer.need_begin_conversation_ack) {
                            SharedCodeLogger.Debug("redundant begin_conversation flag? adding this flag to the next Reliable packet sent, which might not be the one currently queued.");
                            peer.need_begin_conversation_ack = true;
                        }
                        if (!peer.outgoingpacket.Any()) {
                            // send immediately if there are no pending packets
                            if (begin_conversation) {
                                SendRaw(packet, peer, RawPacketType.Reliable_v1, PacketSecurity.BoxedWithPubKey_v1);
                            } else {
                                SendRaw(packet, peer, RawPacketType.Reliable_v1, PacketSecurity.Boxed_v1);
                            }
                        }
                        peer.outgoingpacket.Enqueue(packet);
                        break;
                }
            } else SharedCodeLogger.Error("Failed to get remote peer");
        }

        void SendRaw(byte[] packet, RemotePeer peer, RawPacketType innerType, PacketSecurity outerType) {
            // if the peer is not yet ready for encrypted communications, make sure not to do anything until that part is set up
            if (peer.id.status == PeerId.PeerStatus.Unknown) {
                if (!allowPeerCreationWithoutKey) {
                    throw new Exception("Asking a peer for their pubkey is insecure and not allowed in the current context");
                }
                if (innerType == RawPacketType.Unreliable_v1) {
                    SharedCodeLogger.Error("Discarding unreliable packet for peer with unknown public key");
                }
                SharedCodeLogger.Debug("sending pubkey request to " + describePeerId(peer.id));
                var buffer = new byte[connection_pk.Length +1];
                buffer[0] = (byte)PacketSecurity.RequestPubKey_v1;
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
            case RawPacketType.Unreliable_v1:
            case RawPacketType.VersionError:
                break;
            case RawPacketType.Reliable_v1:
                extraLength = 1 + sizeof(ulong);
                break;
            case RawPacketType.HeartBeat_v1:
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
                if (innerType == RawPacketType.Reliable_v1)
                {
                    writer.Write(peer.wanted_acknowledgement + 1);
                }
                else if (innerType == RawPacketType.HeartBeat_v1)
                {
                    writer.Write(peer.remote_acknowledgement);
                }
                if (innerType != RawPacketType.VersionError) {
                    writer.Write(packet);
                }

                clearText = stream.GetBuffer();
            }

            // then compute the "added bits" added before the cyphertext (extraLength includes the fact that cyphertext is longer than cleartext)
            switch (outerType) {
            case PacketSecurity.Boxed_v1:
                extraLength = 1 + sizeof(UInt16) + LibSodium.BOX_NONCE_SIZE + LibSodium.BOX_MAC_SIZE;
                break;
            case PacketSecurity.BoxedWithPubKey_v1:
                extraLength = 1 + LibSodium.BOX_PK_SIZE + sizeof(UInt16) + LibSodium.BOX_NONCE_SIZE + LibSodium.BOX_MAC_SIZE;
                break;
            case PacketSecurity.CleartextBroadcast_v1:
                extraLength = 1 + sizeof(UInt16);
                break;
            case PacketSecurity.VersionError:
                socket.SendTo(new byte[1]{(byte)PacketSecurity.VersionError}, peer.id.endPoint);
                return;
                break;
            default:
                throw new Exception("unknown outer Packet type... bad code update?");
            };

            // if (clearLength > MTU) {
            //     SharedCodeLogger.Error(
            //         "Too long: "+packet.Length.ToString()
            //         +" + " +(clearLength - packet.Length).ToString()
            //         +" + " +extraLength.ToString()
            //         +" = "+(extraLength+clearLength).ToString()
            //         + " > "+MTU.ToString()
            //     );
            //     throw new Exception("packet too long for the internet to accept!");
            // }
            using (MemoryStream stream = new(extraLength + clearLength))
            using (BinaryWriter writer = new(stream))
            {
                writer.Write((byte)outerType);
                if (outerType == PacketSecurity.CleartextBroadcast_v1) {
                    writer.Write((UInt16)clearLength);
                    writer.Write(clearText);
                } else {
                    if (outerType == PacketSecurity.BoxedWithPubKey_v1) {
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
                            SendRaw(peer.outgoingpacket.Peek(), peer, RawPacketType.Reliable_v1, PacketSecurity.BoxedWithPubKey_v1);
                        } else {
                            SendRaw(peer.outgoingpacket.Peek(), peer, RawPacketType.Reliable_v1, PacketSecurity.Boxed_v1);
                        }
                    }
                    else
                    {
                        SendRaw(
                            Array.Empty<byte>(),
                            peer,
                            RawPacketType.HeartBeat_v1,
                            PacketSecurity.Boxed_v1
                        );
                    }
                }
            }

            foreach (var peer in peersToRemove) ForgetPeer(peer);
        }

        public byte[]? Receive(out PeerId? sender, bool blocking=false) {
            sender = null;

            if ((!blocking) && socket.Available == 0) {
                return null;
            }

            EndPoint senderEndPoint = new IPEndPoint(IPAddress.Loopback, 8720);

            byte[] rawBuffer;
            byte[] cleartextBuffer;
            int len = 0;
            if (blocking) {
                List<Socket> listenList = new();
                listenList.Add(socket);
                try {
                    Socket.Select(listenList, null, null, (int)SharedPlatform.heartbeatTime * 1000);
                } catch (Exception except) {
                    if (except is SocketException skEx && skEx.ErrorCode == 10060)
                    {}
                    else {
                        // if the error is not a timeout
                        SharedCodeLogger.Error(except);
                    }
                    return null;
                }
                if (socket.Available==0) return null;
            }
            if (socket.Available > MTU) {
                rawBuffer = new byte[socket.Available];
            } else {
                rawBuffer = reusableRecvBuffer;
            }
            try {
                len = socket.ReceiveFrom(rawBuffer, ref senderEndPoint);
            } catch (Exception except) {
                SharedCodeLogger.Error(except);
                return null;
            }

            IPEndPoint? ipsender = senderEndPoint as IPEndPoint;
            if (ipsender == null) return null;
            PeerId remoteId = GetIdFromEndpoint(ipsender);
            RemotePeer peer = null;

            try {
                using (MemoryStream stream = new(rawBuffer, 0, len, false))
                using (BinaryReader reader = new(stream)) {
                    byte outTyRaw = reader.ReadByte();
                    PacketSecurity? outerType = null;
                    try {outerType = (PacketSecurity)outTyRaw;}
                    catch {}
                    byte[] pubKey = null;

                    switch (outerType) {
                    case PacketSecurity.Boxed_v1:
                        if (remoteId == null) {
                            SharedCodeLogger.Error("Received encrypted packet from unknown peer: nothing to do");
                            return null;
                        }
                        remoteId.ValidateCryptStatus(true, false);
                        break;
                    case PacketSecurity.CleartextBroadcast_v1:
                        if (remoteId != null) {
                            SharedCodeLogger.Error("Existing peer should not switch to cleartext communications!");
                            return null;
                        }
                        remoteId.ValidateCryptStatus(true, true);
                        break;
                    case PacketSecurity.BoxedWithPubKey_v1:
                        pubKey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                        peer = OnReceivePubkey(ref remoteId, ipsender, pubKey);
                        break;
                    case PacketSecurity.RequestPubKey_v1:
                        pubKey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                        peer = OnReceivePubkey(ref remoteId, ipsender, pubKey);
                        remoteId.ValidateCryptStatus(false, false); // also validate this remoteId as a recipient, as OnReceivePubkey validates it as a sender
                        if (peer != null) {
                            SharedCodeLogger.Debug("answering to pubkey request");
                            SendRaw(new byte[0], peer, RawPacketType.Unreliable_v1, PacketSecurity.BoxedWithPubKey_v1);
                        } else {
                            SharedCodeLogger.Debug("invalid pubkey request");
                        }
                        return null;
                        break;
                    case PacketSecurity.VersionError:
                        SharedCodeLogger.Error("Peer does not know our packet format! make sure all peers use compatible versions of Rain Meadow");
                        return null;
                        break;
                    default:
                        SharedCodeLogger.Error("unknown packet outerType: " + outTyRaw.ToString() + "!");
                        remoteId.ValidateCryptStatus(false, false);
                        SendRaw(new byte[0], GetRemotePeer(remoteId), RawPacketType.Unreliable_v1, PacketSecurity.VersionError);
                        return null;
                        break;
                    }

                    // checks done, now get the inner packet:
                    UInt16 packetSize = reader.ReadUInt16();
                    sender = (PeerId)remoteId;
                    peer = GetRemotePeer(remoteId);
                    if (peer == null) {
                        throw new Exception("sanity check failed: somehow no peer mapped to peerId despite a decrypted packet");
                    }
                    if (sender == null) {
                        throw new Exception("sanity check failed: sender ID somehow not set");
                    }
                    if (outerType == PacketSecurity.CleartextBroadcast_v1) {
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
                    RawPacketType? innerType = null;
                    try {innerType = (RawPacketType)inTyRaw;}
                    catch {}
                    if (innerType==null) {
                        SharedCodeLogger.Error("unknown packet innerType:" + inTyRaw.ToString() +"!");
                        SendRaw(new byte[0], peer, RawPacketType.VersionError, PacketSecurity.Boxed_v1);
                        return null;
                    } else if (innerType == RawPacketType.VersionError) {
                        SharedCodeLogger.Error("Peer does not know our packet format! make sure all peers use compatible versions of Rain Meadow");
                        return null;
                    }

                    if (peer != null) peer.TicksSinceLastIncomingPacket = 0;

                    switch (innerType) {
                        case RawPacketType.Unreliable_v1:
                            return reader.ReadBytes(cleartextBuffer.Length - 1);

                        case RawPacketType.Reliable_v1:

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
                                RawPacketType.HeartBeat_v1,
                                PacketSecurity.Boxed_v1
                            );
                            return new_data;
                        case RawPacketType.HeartBeat_v1:
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
                }
            } catch (Exception except) {
                SharedCodeLogger.Debug(except);
                SharedCodeLogger.Debug($"Error: {except.Message}");
                return null;
            }
        }


        RemotePeer OnReceivePubkey(ref PeerId currentPeerId, IPEndPoint ipsender, byte[] pubKey) {
            if (currentPeerId == null) {
                // TODO restrict this codepath
                var newId = new PeerId(ipsender, pubKey);
                newId.ValidateCryptStatus(true, false);
                currentPeerId = newId;
                SharedCodeLogger.Debug("created new pair from self-introduction");
                return GetRemotePeer(newId, true);
            } else {
                if (currentPeerId.status == PeerId.PeerStatus.Unknown) {
                    if (!allowPeerCreationWithoutKey) {
                        throw new Exception("unknown-status peer are not to be used in this context, nor upgraded into connected-status");
                    }
                    // if we connected to a peer without knowing its pubkey, we need to ask the user if the key's correct
                    if (Run_ConfirmCallback("Is the following public key the one you expect for this lobby?", LibSodium.BoxPubKeyToHex(pubKey))) {
                        currentPeerId.status = PeerId.PeerStatus.Connected;
                        currentPeerId.boxPubkey = pubKey;
                        currentPeerId.ValidateCryptStatus(true, false);
                        SharedCodeLogger.Debug("created new pair from confirmation");
                        return GetRemotePeer(currentPeerId);
                    } else {
                        SharedCodeLogger.Error("Player rejected this peer's pubkey");
                        return null;
                    }
                } else if (currentPeerId.status == PeerId.PeerStatus.Connected && PeerId.ComparePubKeys(currentPeerId.boxPubkey, pubKey)) {
                    SharedCodeLogger.Debug("introducing peer already registereds");
                    currentPeerId.ValidateCryptStatus(true, false);
                    return GetRemotePeer(currentPeerId);
                } else {
                    SharedCodeLogger.Error("peer: " + currentPeerId.status.ToString() + " / " + describePeerId(currentPeerId));
                    SharedCodeLogger.Error(
                        "Change of pubkey (" + LibSodium.BoxPubKeyToHex(currentPeerId.boxPubkey)
                        + "->" + LibSodium.BoxPubKeyToHex(pubKey) +
                        ") halfway through? IDK, looks kinda sus to me!"
                    );
                    return null;
                }
            }
        }


        bool _isDisposed = false;
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
