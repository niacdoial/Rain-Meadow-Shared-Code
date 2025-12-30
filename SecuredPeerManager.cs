using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;



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
    public partial class SecuredPeerManager : IDisposable
    {
        [Flags]
        public enum PacketFlags : byte
        {
            Broadcast = 0b100,
            Unreliable = 0b0,
            Reliable = 0b1, // and ordered!
            HeartBeat = 0b10,
            Termination = 0b11
        }

        [Flags] 
        public enum SecurityFlags: byte {
            ClearText = 0, // 00
            Boxed = 1, // 01
            RequestPubKey = 2, // 10
            BoxedWithPubKey = Boxed | RequestPubKey, // 11
        }

        
        public SecuredPeerManager(int default_port = DEFAULT_PORT, int port_attempts = FIND_PORT_ATTEMPTS) {
            InitSocket();
            // this.identity_pk = new byte[LibSodium.SIGN_PK_SIZE];
            // this.identity_sk = new byte[LibSodium.SIGN_SK_SIZE];
            this.ResetKeys();
        }

        public SecuredPeerId[] GetBroadcastPeerIDs() 
        {
            List<SecuredPeerId> broadcastables = new List<SecuredPeerId>();
            for (int broadcast_port = DEFAULT_PORT;
                broadcast_port < (FIND_PORT_ATTEMPTS + DEFAULT_PORT);
                broadcast_port++)
            {
                broadcastables.Add(SecuredPeerId.MakeClearText(new(IPAddress.Broadcast, broadcast_port)));
            }

            return broadcastables.ToArray();
        }



        public string GetGenericInviteCode() {
            var invitecode = LibSodium.BoxPubKeyToHex(this.public_key);
            return $"{invitecode}@X.X.X.X:{this.port}";
        }



        List<RemotePeer> peers = new();
        RemotePeer? GetRemotePeer(SecuredPeerId peerId, bool make = false) 
        {
            RemotePeer? peer = peers.FirstOrDefault(x => x.id.Equals(peerId));
            if (make && peer == null) 
            {
                peerId.ValidateCryptStatus(false, false, true);
                peer = new RemotePeer(this, peerId);

                if (peerId.Status != SecuredPeerId.PeerStatus.ClearTextOnly) 
                {
                    peers.Add(peer);  // Cleartext (broadcast) peers are not to be remembered
                }
            }

            return peer;
        }

        public delegate void OnPeerForgotten_t(RemotePeer peerId);
        public event OnPeerForgotten_t OnPeerForgotten = delegate { };


        void ForgetPeer(RemotePeer peer)
        {
            if (peers.Contains(peer))
            {
                peer.Dispose();
                peers.Remove(peer);
                OnPeerForgotten.Invoke(peer);
            }
        }

        public void ForgetPeer(SecuredPeerId peerId) 
        {
            foreach (RemotePeer peer in peers.Where(x => peerId == x.id)) 
            {
                ForgetPeer(peer);
            }
        }

        public void TerminateAllPeers()
        {
            foreach (RemotePeer peer in peers.ToArray())
            {
                peer.Terminate();
            }
        }

        public void Send(byte[] packet, SecuredPeerId peerId, PacketFlags packet_flags = PacketFlags.Reliable, bool boxed = true) 
        {
            RemotePeer? peer = GetRemotePeer(peerId, true);
            if (peer is not null) 
            {           
                if (peer.IsTerminating)
                {
                    while (peer.IsTerminating)
                    {
                        // we gotta wait until that terminates first.
                        Update();
                    }

                    peer = GetRemotePeer(peerId, true);
                }     
            }

            if (peer is not null) 
            {
                switch (packet_flags & PacketFlags.Reliable) 
                {
                    case PacketFlags.Unreliable:
                        if (packet_flags.HasFlag(PacketFlags.Broadcast)) boxed = false;
                        peerId.ValidateCryptStatus(false, false);
                        
                        SecurityFlags security_flags = SecurityFlags.ClearText;
                        if (packet_flags == PacketFlags.Unreliable || packet_flags == PacketFlags.Reliable)
                        {
                            if (peer.acked_pubkey) security_flags = security_flags | SecurityFlags.RequestPubKey;
                            if (boxed) security_flags = security_flags | SecurityFlags.Boxed;
                            
                        }

                        SendRaw(packet, peer, packet_flags, security_flags);
                        break;

                    case PacketFlags.Reliable:
                        peer.outgoingPackets.Enqueue(new OutgoingPacket() { data = packet.ToArray(), boxed = boxed, attempts = -1 } );
                        if (!peer.outgoingPackets.Any()) goto case PacketFlags.Unreliable;                        
                        break;
                }
            } 
            else throw new InvalidProgrammerException("Couldn't make remote peer");
        }

        void SendRaw(byte[] packet, RemotePeer peer, PacketFlags flags, SecurityFlags security) {
            // if the peer is not yet ready for encrypted communications, make sure not to do anything until that part is set up
            if (security.HasFlag(SecurityFlags.Boxed))
            {
                if (peer.id.Status != SecuredPeerId.PeerStatus.Connected)
                {
                    if (peer.id.Status == SecuredPeerId.PeerStatus.ClearTextOnly)
                    {
                        SharedCodeLogger.Error("Can't sent boxed packet to a cleartext only peer.");
                        return;
                    }

                    if (flags == PacketFlags.Unreliable) 
                    {
                        SharedCodeLogger.Error("Discarding unreliable packet for peer with unknown public key");
                    }

                    SendRaw(Array.Empty<byte>(), peer, PacketFlags.Unreliable, SecurityFlags.RequestPubKey);
                    return;
                }
            }

            int boilerplateLen = 1;
            if (flags == PacketFlags.HeartBeat || flags.HasFlag(PacketFlags.Reliable)) boilerplateLen += sizeof(ulong);
            // then compute the "added bits" added before the cyphertext (extraLength includes the fact that cyphertext is longer than cleartext)
            if (security.HasFlag(SecurityFlags.RequestPubKey))
            {
                boilerplateLen += LibSodium.BOX_PK_SIZE;
            }

            if (security.HasFlag(SecurityFlags.Boxed))
            {
                boilerplateLen += LibSodium.BOX_NONCE_SIZE;
            }

            using (MemoryStream stream = new(boilerplateLen + packet.Length))
            using (BinaryWriter writer = new(stream))
            {
                writer.Write((byte)flags);
                writer.Write((byte)security);

                if (security.HasFlag(SecurityFlags.RequestPubKey))
                {
                    writer.Write(public_key);
                }
                
                if (flags.HasFlag(PacketFlags.Reliable)) writer.Write(peer.wanted_acknowledgement);
                if (flags == PacketFlags.HeartBeat) writer.Write(peer.remote_acknowledgement);

                byte[]? nonce;
                if (security.HasFlag(SecurityFlags.Boxed))
                {
                    if (flags.HasFlag(PacketFlags.Reliable))
                    {
                        nonce = MakeReliableNonce(peer.wanted_acknowledgement + 1);
                    }
                    else
                    {
                        nonce = MakeUnreliableNonce();
                        writer.Write(nonce);
                    }
                }
                else
                {
                    nonce = null;
                }

                if (security.HasFlag(SecurityFlags.Boxed))
                {
                    var cypherText = SodiumEncodePacket(packet, nonce!, peer);
                    if (cypherText == null) {
                        SharedCodeLogger.Error("Failed to encrypt packet");
                        return;
                    }

                    writer.Write(cypherText);
                }
                else
                {
                    writer.Write(packet);
                }

                socket.SendTo(stream.GetBuffer(), peer.id.endPoint);
            }
        }


        public void Update()
        {
            ulong time = (ulong)SharedPlatform.TimeMS;
            foreach (RemotePeer peer in peers.ToArray())
            {
                peer.Update(time);
            }
        }

        public byte[]? Receive(out SecuredPeerId? sender) {
            sender = null;
            socket.Blocking = false;
            EndPoint senderEndPoint = new IPEndPoint(IPAddress.Loopback, 8720);

            byte[] rawBuffer = socket.Available > MTU? new byte[socket.Available] : reusableRecvBuffer;
            int len = socket.ReceiveFrom(rawBuffer, ref senderEndPoint);

            if (senderEndPoint is not IPEndPoint ipend) return null;
            sender = new SecuredPeerId(ipend as IPEndPoint, null);

            RemotePeer? peer = GetRemotePeer(sender, false);
            if (peer != null) sender = peer.id;

            try 
            {
                using (MemoryStream stream = new(rawBuffer, 0, len, false))
                using (BinaryReader reader = new(stream))
                {
                    PacketFlags flags = (PacketFlags)reader.ReadByte();
                    SecurityFlags security = (SecurityFlags)reader.ReadByte();

                    if (peer is not null && peer.Terminated && flags != PacketFlags.Termination)
                    {
                        ForgetPeer(peer);
                        peer = null;
                    }

                    // Read public key
                    if (security.HasFlag(SecurityFlags.RequestPubKey))
                    {
                        byte[] new_pub_key = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                        peer = ReceivePubkey(ref sender, ipend, new_pub_key);      
                        
                        if (security == SecurityFlags.RequestPubKey)
                        {
                            peer.acked_pubkey = false;
                        }                  
                    }
                    
                    if (peer is null && !(flags != PacketFlags.Broadcast || security != SecurityFlags.ClearText))
                    {
                        SharedCodeLogger.Debug($"Recieved packet from {sender}, who haven't started a conversation with.");
                        return null;
                    }


                    // store provided acknoledgement for later
                    ulong ack = 0;
                    if (flags.HasFlag(PacketFlags.Reliable) || flags == PacketFlags.HeartBeat) ack = reader.ReadUInt64();

                    
                    const int MAXIMUM_PACKET_BYTE = 1500;
                    if (stream.Length - stream.Position > MAXIMUM_PACKET_BYTE)
                    {
                        SharedCodeLogger.Error($"Recieved insanely big packet from {sender}.");
                        return null;
                    }

                    byte[]? encodedData = null;
                    if (flags != PacketFlags.HeartBeat)
                    {
                        // main reading / decrypting code here.
                        sender.ValidateCryptStatus(true, !security.HasFlag(SecurityFlags.Boxed));

                        byte[] clearText = new byte[stream.Length - stream.Position];
                        stream.Read(clearText, 0, clearText.Length);
                        if (security.HasFlag(SecurityFlags.Boxed))
                        {
                            byte[] nonce;
                            if (flags.HasFlag(PacketFlags.Reliable))
                            {
                                nonce = MakeReliableNonce(ack);
                            }
                            else
                            {
                                nonce = reader.ReadBytes(LibSodium.BOX_NONCE_SIZE);
                            }
                            
                            encodedData = SodiumDecodePacket(clearText, nonce, peer!);
                            if (encodedData is null)
                            {
                                SharedCodeLogger.Error($"Failed to decrypt packet {sender}: ");
                                return null;
                            }
                        }
                        else
                        {
                            encodedData = clearText;
                        }
                    }
                    
                    if (flags.HasFlag(PacketFlags.Reliable))
                    {
                        if (EventMath.IsNewerOrEqual(ack, peer!.remote_acknowledgement)) 
                        {
                            ++peer.remote_acknowledgement;
                            if (EventMath.IsNewerOrEqual(ack, peer.remote_acknowledgement)) 
                            {
                                SharedCodeLogger.Error($"skipped packets {peer.remote_acknowledgement}-{ack}");
                                peer.remote_acknowledgement = ack;
                            }
                        }
                    }
                    
                    if (flags == PacketFlags.HeartBeat)
                    {
                        if (EventMath.IsNewer(ack, peer!.wanted_acknowledgement)) 
                        {
                            ++peer.wanted_acknowledgement;
                            if (EventMath.IsNewer(ack, peer.wanted_acknowledgement)) 
                            {
                                // this can happen if we leave the Meadow menu then reenter it before the matchmaking server times us out
                                SharedCodeLogger.Error("Reliable Packet Acknowledgement too advanced! We might have sent a packet too early?");
                                // we can make packet delivery recover from this, by just... skipping numbers in the next packets IDs sent
                                peer.wanted_acknowledgement = ack;
                            }

                            if (peer.outgoingPackets.Count > 0) 
                            {
                                peer.outgoingPackets.Dequeue();
                            } 
                            else 
                            {
                                SharedCodeLogger.Error("Reliable Packet Acknowledgement without corresponding queued message! Expect more problems in ordered communications.");
                            }
                        }
                    }

                    if (flags == PacketFlags.Termination)
                    {
                        peer!.Terminated = true; 
                    }

                    return encodedData;
                }
            } catch (Exception except) {
                SharedCodeLogger.Debug(except);
                SharedCodeLogger.Debug($"Error: {except.Message}");
                return null;
            }
        }


        RemotePeer? ReceivePubkey(ref SecuredPeerId currentPeerId, IPEndPoint ipsender, byte[] pubKey) 
        {
            if (pubKey.Length != LibSodium.BOX_PK_SIZE) throw new InvalidProgrammerException("Packet too short");
            if (currentPeerId == null)
            {
                // TODO restrict this codepath
                var newId = new SecuredPeerId(ipsender, pubKey);
                newId.ValidateCryptStatus(true, false);
                currentPeerId = newId;
                SharedCodeLogger.Debug($"Created new peer {newId} from self-introduction");
                return GetRemotePeer(newId, true);
            } 
            else 
            {
                if (currentPeerId.Status == SecuredPeerId.PeerStatus.ClearTextOnly) throw new Exception("recieved pubkey from clearText only client");
                if (currentPeerId.Status == SecuredPeerId.PeerStatus.Connected) 
                {
                    if (currentPeerId.publicKey.SequenceEqual(pubKey))
                    {
                        SharedCodeLogger.Debug($"Recieved duplicate pubkey of {currentPeerId}");
                    }
                    else
                    {
                        // later we need to implement resetting keys to avoid nonce issues.
                        SharedCodeLogger.Error($"Client attempted to change pubkeys from {currentPeerId} -> {pubKey}");
                    }

                    currentPeerId.ValidateCryptStatus(true, false);
                    return GetRemotePeer(currentPeerId);
                } 
                else
                {
                    currentPeerId.publicKey = pubKey;
                    currentPeerId.ValidateCryptStatus(true, false);
                    return GetRemotePeer(currentPeerId);
                }
            }
        }


        ~SecuredPeerManager() => Dispose(false);
        private bool disposed = false;

        public void Dispose() 
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Dispose(bool disposing) 
        {
            if (disposed) return;
            if (disposing)
            {
                foreach (RemotePeer peer in peers.ToArray()) ForgetPeer(peer);
                socket.Dispose();
            }

            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
