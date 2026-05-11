using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Sodium;

namespace RainMeadow.Shared
{
    public class SecuredPeerId : IEquatable<SecuredPeerId> 
    {
        public enum PeerStatus: byte {
            PendingPublicKey,  // one current use case: connect to a server in a LAN context, without knowing the other's key in advance.
            Connected,  // Has a known connection pubkey
        }

        public PeerStatus Status
        {
            get
            {
                if (publicKey != null) return PeerStatus.Connected;
                return PeerStatus.PendingPublicKey;
            }
        }

        public readonly IPEndPoint endPoint;
        public byte[]? publicKey;
        public string? publicKeyStr => publicKey is not null? LibSodium.BinToHex(publicKey) : null;
        public SecuredPeerId(IPEndPoint endPoint, byte[]? boxPubkey)
        {
            this.endPoint = endPoint;
            this.publicKey = boxPubkey;
            if (boxPubkey != null && boxPubkey.Length != LibSodium.BOX_PK_SIZE)
                throw new Exception("malformed pubkey: wrong size");
        }

        public override bool Equals(object? obj) => obj is SecuredPeerId id? Equals(id) : false;
        public bool Equals(SecuredPeerId? id) => id == null? false : SharedPlatform.CompareIPEndpoints(this.endPoint, id.endPoint);
        public static bool operator ==(SecuredPeerId? a,SecuredPeerId? b) => a is null? b is null : a.Equals(b);
        public static bool operator !=(SecuredPeerId? a,SecuredPeerId? b) => !(a == b);
        public override int GetHashCode() => endPoint.GetHashCode();


        public bool CompareAndUpdate(SecuredPeerId? other) {
            // note that this equality function just means "are we sure this is the same peer?"
            if (other is SecuredPeerId id && Equals(id))
            {
                if (this.Status == PeerStatus.PendingPublicKey)
                {
                    this.publicKey = other.publicKey;
                }

                return true;
            }
            return false;
        }

        public bool IsLoopback() => SharedPlatform.IsLoopback(endPoint.Address);
        public bool IsNetworkLocal() => SharedPlatform.IsEndpointLocal(endPoint.Address);
        public void ValidateCryptStatus(bool peerIsSender = false, bool forClearText = false, bool internalChecksOnly = false)
        {
            switch (this.Status) {
                case PeerStatus.PendingPublicKey:
                    if (peerIsSender && !forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: unknown-encryption peers can only be message recipients, not senders");
                    }
                    break;
                case PeerStatus.Connected:
                    // if (forClearText && !internalChecksOnly) {
                    //     throw new Exception("assertion failed: peer must be suited for encrypted");
                    // }s
                    if ((this.publicKey?.Length ?? 0) != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("assertion failed: Incorrectly initialised pubkey");
                    }
                    break;
                // case PeerStatus.ClearTextOnly:
                //     if (!(forClearText || internalChecksOnly)) {
                //         throw new Exception("assertion failed: peer must be suited for cleartext communications");
                //     }
                //     if ((peerIsSender || internalChecksOnly) && IsNetworkLocal()) {
                //         // only network-local packet entry
                //         return;
                //     } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                //         return;
                //     }
                //     throw new Exception("assertion failed: Cleartext peers can only exist for local-network broacasts");
                default:
                    throw new Exception("bad code update: failed to handle new PeerId status");
            }
        }

        public override string ToString() => ToString(true);
        public string ToString(bool debug)
        {
            StringBuilder builder = new StringBuilder();
            if (publicKey != null)
            {
                builder.Append(publicKeyStr);
                builder.Append("@");
            }

            builder.Append(endPoint);

            if (debug)
            {
                builder.Append($" [is machine local: {IsLoopback()}, is network local: {IsNetworkLocal()}]");
            }
            return builder.ToString();
        }



        public static SecuredPeerId Deserialize(BinaryReader reader, SecuredPeerId from, SecuredPeerId me)
        {
            byte[]? public_key = null;
            if (reader.ReadBoolean()) public_key = reader.ReadBytes(LibSodium.BOX_PK_SIZE);

            byte flags = reader.ReadByte();
            if ((flags & 0b01) == 0b01) // It's them
            {
                return new SecuredPeerId(from.endPoint, public_key);
            }
            else if ((flags & 0b10) == 0b10) // It's me
            {
                return new SecuredPeerId(me.endPoint, public_key);
            }
            else
            {
                ushort port = reader.ReadUInt16();
                IPAddress address = new IPAddress(reader.ReadBytes(reader.ReadByte()));
                return new SecuredPeerId(new IPEndPoint(address, port), public_key);
            }
        }

        public void Serialize(BinaryWriter writer, SecuredPeerId to, SecuredPeerId me)
        {

            if (publicKey != null)
            {
                writer.Write(true);
                writer.Write(publicKey, 0, LibSodium.BOX_PK_SIZE);
            }
            else
            {
                writer.Write(false);
            }


            // we need these special cases, because of NAT: the machines at the respective ends of this packet don't
            // always see their own IP in same way as the other.
            bool isLoopback = SharedPlatform.CompareIPEndpoints(to.endPoint, me.endPoint);
            bool isThem = SharedPlatform.CompareIPEndpoints(to.endPoint, endPoint);

            int flags = 0;
            if (isLoopback) flags = flags | 0b01;
            if (isThem) flags = flags | 0b10;
            writer.Write((byte)flags);


            if (!isThem && !isLoopback)
            {
                writer.Write((ushort)endPoint.Port);
                byte[] address_bytes = endPoint.Address.GetAddressBytes();
                writer.Write((byte)address_bytes.Length);
                writer.Write(address_bytes);
            }
        }

        public static void SerializeArray(BinaryWriter writer, SecuredPeerId?[] peers, SecuredPeerId addressedto, SecuredPeerId me, bool nullable = false)
        {
            writer.Write((byte)peers.Length);
            foreach (SecuredPeerId? peer in peers)
            {

                if (nullable)
                {
                    writer.Write(peer is null);
                    if (peer is null) continue;
                }
                else if (peer is null) throw new InvalidProgrammerException("Can't serialize null in non nullable array");
                peer.Serialize(writer, addressedto, me);
            }
        }

        public static SecuredPeerId?[] DeserializeArray(BinaryReader reader, SecuredPeerId fromWho, SecuredPeerId me, bool nullable = false)
        {
            SecuredPeerId?[] ret = new SecuredPeerId[reader.ReadByte()];
            for (int i = 0; i < ret.Length; i++)
            {
                if (nullable)
                {
                    if (reader.ReadBoolean())
                    {
                        ret[i] = null;
                        continue;
                    }
                }

                ret[i] = SecuredPeerId.Deserialize(reader, fromWho, me);
            }

            return ret;
        }

        public static SecuredPeerId? GetPeerIdByName(string name)
        {
            var parts = name.Split('@');
            IPEndPoint? endPoint = null;

            if (parts.Count() == 2)
            {
                if (parts[0].Length != 2*LibSodium.BOX_PK_SIZE) return null;
                endPoint = SharedPlatform.GetEndPointByName(parts[1]);
                if (endPoint is null) return null;
                byte[] pubKey = LibSodium.HexToBin(parts[0]);
                return new SecuredPeerId(endPoint, pubKey);
            }
            else if (parts.Count() == 1)
            {
                endPoint = SharedPlatform.GetEndPointByName(parts[0]);
                if (endPoint is null) return null;
                return new SecuredPeerId(endPoint, null);
            }
            else
            {
                return null;
            }
        }
    }

    public partial class SecuredPeerManager : IDisposable
    {
        public struct OutgoingPacket
        {
            public int attempts;
            public byte[] data;
            public bool boxed;
        }

        public class RemotePeer : IDisposable
        {
            private SecuredPeerManager manager;


            // data for connection itself
            public SecuredPeerId id;
            public bool acked_pubkey = false;
            public string? terminationMessage = null;


            // whether or not that peer ever sent us a boxed packet that we could read
            // (ergo: whether we know that the key exchange succeeded, but not whether *they* know that yet)
            public bool hasEstablishedEncryption = false; 
            public ulong lastIncomingPacketTick = 0;
            public ulong lastOutgoingTick = 0;

            public Queue<OutgoingPacket> outgoingPackets = new Queue<OutgoingPacket>();
            public ulong wanted_acknowledgement = 0;  // the 'packet ID' of the last reliable packet ack'd by peer (1-indexed)
            public ulong remote_acknowledgement = 0;  // the 'packet ID' of the last reliable packet recv'd by us  (1-indexed)


            public RemotePeer(SecuredPeerManager manager, SecuredPeerId id)
            {
                this.manager = manager;
                lastIncomingPacketTick = SharedPlatform.TimeMS;
                lastOutgoingTick = SharedPlatform.TimeMS;
                this.id = id;
            }


            public void Update(ulong tick)
            {
                ulong tickSinceLastPacket = tick - lastIncomingPacketTick;
                if (tickSinceLastPacket >= SharedPlatform.timeoutTime)
                {
                    SharedCodeLogger.Error($"Forgetting {id} due to Timeout, Timeout is {SharedPlatform.timeoutTime}ms");
                    manager.ForgetPeer(this);
                    return;
                }

                ulong tickSinceLastOutgoing = tick - lastOutgoingTick;
                while (tickSinceLastOutgoing > SharedPlatform.heartbeatTime)
                {
                    lastOutgoingTick += SharedPlatform.heartbeatTime;
                    tickSinceLastOutgoing = tick - lastOutgoingTick;
                    if (outgoingPackets.Any())
                    {
                        OutgoingPacket packet = outgoingPackets.Peek();
                        SecurityFlags flags = 0;

                        if (packet.attempts > 0)
                        {
                            packet.attempts--;
                            if (packet.attempts == 0)
                            {

                                // we failed to send it.
                                SharedCodeLogger.Error($"Failed to send packet with ack {wanted_acknowledgement}");
                                wanted_acknowledgement++;
                                outgoingPackets.Dequeue();
                            }
                        }

                        if (!acked_pubkey) flags = flags | SecurityFlags.SendPubKey;
                        if (packet.boxed) flags = flags | SecurityFlags.Boxed;
                        if (id.Status != SecuredPeerId.PeerStatus.Connected) flags = flags | SecurityFlags.RequestPubKey;
                        manager.SendRaw(packet.data, this, PacketFlags.Reliable, flags);
                    }
                    else
                    {
                        if (terminationMessage is not null)
                        {
                            manager.SendTermination(this);
                        }
                        else
                        {
                            manager.SendRaw(
                                Array.Empty<byte>(),
                                this,
                                PacketFlags.Acknoledgement,
                                acked_pubkey? SecurityFlags.ClearText : SecurityFlags.SendPubKey
                            );
                        }
                    }
                }
            }

            public bool Disposed { get; private set; }
            public byte[]? shared_key;
            public void Dispose() {
                if (shared_key is not null)
                {
                    unsafe
                    {
                        fixed (byte* p_csk = this.shared_key) {
                            LibSodium.sodium_memzero(p_csk, (UIntPtr)LibSodium.BOX_DERVK_SIZE);
                        }
                    }
                }

                Disposed = true;
            }

            ~RemotePeer()
            {
                Dispose();
            }
        }

        List<RemotePeer> peers = new();
        public bool allowKeylessPeerIDs = false;  // Only allow PeerIds without keys for one specific purpose: directly connecting to LAN lobby hosts, without knowing the key
        public RemotePeer? GetRemotePeer(SecuredPeerId peerId, bool make = false)
        {
            if ((!allowKeylessPeerIDs) && peerId.Status == SecuredPeerId.PeerStatus.PendingPublicKey) {
                if (!peerId.endPoint.Address.Equals(IPAddress.Broadcast))
                    // broadcast IP gets a pass because you'll need to send packets there outside of a lobby
                    throw new Exception("Cannot contact a peer without a known key in this situation");
            }
            RemotePeer? peer = peers.FirstOrDefault(x => x.id.CompareAndUpdate(peerId));
            if (make && peer == null)
            {
                peerId.ValidateCryptStatus(false, false, true);
                peer = new RemotePeer(this, peerId);
                peers.Add(peer);
            }

            if (peer is not null && peer.id.publicKey is not null)
            {
                peer.shared_key = LibSodium.ComputeSharedKey(private_key, peer.id.publicKey);
            }

            return peer;
        }

        public RemotePeer? GetRemotePeer(IPEndPoint peerEndPoint)
        {
            RemotePeer? peer = peers.FirstOrDefault(x => SharedPlatform.CompareIPEndpoints(x.id.endPoint, peerEndPoint));
            return peer;
        }
        
        public bool AnyConnection => peers.Any();
        public void TerminateAllPeers(string reason)
        {
            foreach (RemotePeer peer in peers)
            {
                TerminatePeer(peer, reason);
            }
        }

        public void TerminatePeer(SecuredPeerId peerId, string reason)
        {
            if (GetRemotePeer(peerId, false) is RemotePeer peer) 
                TerminatePeer(peer, reason);
        }

        public void TerminatePeer(RemotePeer peer, string reason)
        {
            if (peer.terminationMessage != null)
            {
                peer.terminationMessage = reason;
                if (peer.outgoingPackets.Any())
                {
                    SendTermination(peer);
                }
                OnPeerForgotten.Invoke(peer, reason);
            }
            
        }

        public void SendTermination(RemotePeer peer)
        {
            if (peer.terminationMessage is not null)
            {
                using (MemoryStream stream = new MemoryStream())
                using (BinaryWriter writer = new BinaryWriter(stream))
                {
                    writer.Write(peer.terminationMessage);
                    SendRaw(stream.GetBuffer(), peer, PacketFlags.Termination, SecurityFlags.ClearText);
                    // if they know we agree on the pubkey, they won't accept deauth attacks liek that, so
                    // also send an encrypted version of that
                    SendRaw(stream.GetBuffer(), peer, PacketFlags.Termination, SecurityFlags.Boxed);
                }
            }
        }

        public delegate void OnPeerForgotten_t(RemotePeer peerId, string reason);
        public event OnPeerForgotten_t OnPeerForgotten = delegate { };

        public void ForgetPeer(RemotePeer peer, string reason = "")
        {
            if (peers.Contains(peer))
            {
                peer.Dispose();
                peers.Remove(peer);

                if (peer.terminationMessage is null) OnPeerForgotten.Invoke(peer, reason);  
            }
        }

        public void ForgetPeer(SecuredPeerId peerId, string reason = "") 
        {
            foreach (RemotePeer peer in peers.Where(x => peerId == x.id).ToArray()) 
            {
                ForgetPeer(peer, reason);
            }
        }

        public void ForgetAllPeers(string reason = "") 
        {
            foreach (RemotePeer peer in peers.ToArray()) 
            { 
                ForgetPeer(peer, reason);
            }
        }

    }
}
