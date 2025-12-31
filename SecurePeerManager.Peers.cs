using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using Sodium;

namespace RainMeadow.Shared
{    
    public class SecuredPeerId : IEquatable<SecuredPeerId> {
        public enum PeerStatus: byte {
            ClearTextOnly = 0,  // network-local broadcast purposes, also allowed for the BlackHole placeholder
            PendingPublicKey,  // one current use case: connect to a server then asking the user to double-check the pubkey
            Connected,  // Has a known connection pubkey
        }

        public PeerStatus Status 
        { 
            get
            {
                if (clearTextOnly) return PeerStatus.ClearTextOnly;
                if (publicKey != null) return PeerStatus.Connected;   
                return PeerStatus.PendingPublicKey;
            }
        }

        public IPEndPoint endPoint;
        public byte[]? publicKey;
        public readonly bool clearTextOnly;
   
        public SecuredPeerId(IPEndPoint endPoint, byte[]? boxPubkey, bool clearTextOnly = false) 
        {
            this.clearTextOnly = clearTextOnly;
            this.endPoint = endPoint;
            this.publicKey = boxPubkey;
            if (boxPubkey != null && boxPubkey.Length != LibSodium.BOX_PK_SIZE) 
                throw new Exception("malformed pubkey: wrong size");
        }

        public static SecuredPeerId MakeClearText(IPEndPoint endPoint) => new SecuredPeerId(endPoint, null, true);
        public static SecuredPeerId MakePending(IPEndPoint endPoint) => new SecuredPeerId(endPoint, null, false); 
        public bool Equals(SecuredPeerId? id) => id == null? false : SharedPlatform.CompareIPEndpoints(this.endPoint, id.endPoint);
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
        public bool IsNetworkLocal() => SharedPlatform.IsEndpointLocal(endPoint);
        public void ValidateCryptStatus(bool peerIsSender = false, bool forClearText = false, bool internalChecksOnly = false) 
        {
            switch (this.Status) {
                case PeerStatus.PendingPublicKey:
                    if (peerIsSender && !internalChecksOnly) {
                        throw new Exception("assertion failed: unknown-encryption peers can only be message recipients, not senders");
                    }
                    if (forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: peer must be suited for encrypted");
                    }
                    break;
                case PeerStatus.Connected:
                    if (forClearText && !internalChecksOnly) {
                        throw new Exception("assertion failed: peer must be suited for encrypted");
                    }
                    if ((this.publicKey?.Length ?? 0) != LibSodium.BOX_PK_SIZE) {
                        throw new Exception("assertion failed: Incorrectly initialised pubkey");
                    }
                    break;
                case PeerStatus.ClearTextOnly:
                    if (! (forClearText || internalChecksOnly)) {
                        throw new Exception("assertion failed: peer must be suited for cleartext communications");
                    }
                    if ((peerIsSender || internalChecksOnly) && IsNetworkLocal()) {
                        // only network-local packet entry
                        return;
                    } else if (this.endPoint.Address.Equals(IPAddress.Broadcast) ) {
                        return;
                    }
                    throw new Exception("assertion failed: Cleartext peers can only exist for local-network broacasts");
                default:
                    throw new Exception("bad code update: failed to handle new PeerId status");
            }
        }

        public override string ToString()
        {
            var pubkeyString = "";
            if (publicKey != null) 
            {
                pubkeyString = LibSodium.BoxPubKeyToHex(publicKey);
            }
            
            return (string.IsNullOrWhiteSpace(pubkeyString)? endPoint.ToString() : $"{pubkeyString}@{endPoint}") + 
                $"[is machine local: {IsLoopback()}, is network local: {IsNetworkLocal()}]";
        }

        public void Serialize(BinaryWriter writer, SecuredPeerId to, SecuredPeerManager manager) 
        {
            writer.Write(publicKey != null);
            if (publicKey != null) writer.Write(publicKey);

            if (IsLoopback() && endPoint.Port == manager.port)
            {
                writer.Write(true);
            }
            else 
            {
                writer.Write(false);
                writer.Write((ushort)endPoint.Port);
                writer.Write((ushort)endPoint.Address.GetAddressBytes().Length);
                writer.Write(endPoint.Address.GetAddressBytes());
            }
        }

        public static SecuredPeerId Deserialize(BinaryReader reader, SecuredPeerManager manager, SecuredPeerId from)
        {
            byte[]? public_key = null;
            if (reader.ReadBoolean()) reader.ReadBytes(LibSodium.BOX_PK_SIZE);

            ushort port;
            IPAddress address;
            if (reader.ReadBoolean())
            {
                port = (ushort)from.endPoint.Port;
                address = from.endPoint.Address;
            }
            else
            {
                if (reader.ReadBoolean())
                {
                    port = manager.port;
                    address = IPAddress.Loopback;
                }
                else
                {
                    port = reader.ReadByte();
                    address = new IPAddress(reader.ReadBytes(reader.ReadInt32()));
                }
            }

            return new SecuredPeerId(new IPEndPoint(address, port), public_key, false);
        }

        public void Serialize(BinaryWriter writer, SecuredPeerManager manager, SecuredPeerId to) 
        {
            writer.Write(publicKey != null);
            if (publicKey != null) writer.Write(publicKey);

            if (IsLoopback() && endPoint.Port == manager.port)
            {
                writer.Write(true);
            }
            else 
            {
                writer.Write(false);
                if (to.Equals(this))
                {
                    writer.Write(true);
                }
                else
                {
                    writer.Write(false);
                    writer.Write((ushort)endPoint.Port);
                    writer.Write((byte)endPoint.Address.GetAddressBytes().Length);
                    writer.Write(endPoint.Address.GetAddressBytes());
                }
            }
        }

                /// the functions that (de)serialize multiple endpoints at once can deal with the sender seeing itself differently as everyone else.
        /// The functions that do not need a separate mechanism to deal with this.
        public static void SerializePeerIDs(BinaryWriter writer, SecuredPeerId[] peers, SecuredPeerId addressedto, bool includeme = true) 
        {
            var dest = addressedto as SecuredPeerId;
            if (dest is null) {return;}

            writer.Write(includeme);
            writer.Write(peers.Length);
            foreach (SecuredPeerId peerID in peers) 
            {
                writer.Write((ushort)peerID.endPoint.Port);
                if (peerID.Equals(addressedto)) 
                {
                    writer.Write(true);
                }
                else
                {
                    writer.Write(false);
                    writer.Write((byte)peerID.endPoint.Address.GetAddressBytes().Length);
                    writer.Write(peerID.endPoint.Address.GetAddressBytes());
                }

                bool hasPubKey = peerID.publicKey != null;
                writer.Write(hasPubKey);
                if (peerID.publicKey != null)
                {
                    writer.Write(true);
                    writer.Write(peerID.publicKey);
                }
                else
                {
                    writer.Write(false);
                }
            }
        }

        public static SecuredPeerId[] DeserializePeerIDs(BinaryReader reader, SecuredPeerId fromWho) 
        {
            SecuredPeerId? sender = fromWho as SecuredPeerId;
            if (sender is null) {throw new Exception("bad PeerId as sender");}

            bool includesender = reader.ReadBoolean();
            SecuredPeerId[] ret = new SecuredPeerId[reader.ReadInt32() + (includesender? 1 : 0)];
            if (includesender) ret[0] = sender;

            for (int i = includesender? 1 : 0; i != ret.Length; i++) 
            {
                IPEndPoint endPoint;
                if (reader.ReadBoolean())
                {
                    endPoint = new IPEndPoint(IPAddress.Loopback, fromWho.endPoint.Port);
                }
                else
                {
                    endPoint = new IPEndPoint(new IPAddress(reader.ReadBytes(reader.ReadByte())), fromWho.endPoint.Port);
                }

                if (reader.ReadBoolean())
                {
                    byte[] pubkey = reader.ReadBytes(LibSodium.BOX_PK_SIZE);
                    ret[i] = new SecuredPeerId(endPoint, pubkey);
                }
                else
                {
                    ret[i] = new SecuredPeerId(endPoint, null);
                }
            }

            return ret.ToArray();
        }

        public static SecuredPeerId? GetPeerIdByName(string name) 
        {
            var parts = name.Split('@');
            IPEndPoint? endPoint = null;
            byte[] pubKey = new byte[0];

            if (parts.Count() == 2) 
            {
                if (parts[0].Length != 2*LibSodium.BOX_PK_SIZE) return null;
                endPoint = SharedPlatform.GetEndPointByName(parts[1]);
                if (endPoint is null) return null;
                pubKey = LibSodium.BoxPubKeyFromHex(parts[0]);
                return new SecuredPeerId(endPoint, pubKey);
            } 
            else if (parts.Count() == 1) 
            {
                endPoint = SharedPlatform.GetEndPointByName(parts[0]);
                if (endPoint is null) return null;
                return SecuredPeerId.MakePending(endPoint);
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
                if (IsTerminating && !outgoingPackets.Any())
                {
                    manager.ForgetPeer(this);
                }

                ulong tickSinceLastPacket = tick - lastIncomingPacketTick;
                if (tickSinceLastPacket >= SharedPlatform.timeoutTime)
                {
                    SharedCodeLogger.Error($"Forgetting {id} due to Timeout, Timeout is {SharedPlatform.timeoutTime}ms");
                    manager.ForgetPeer(this);
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
                                wanted_acknowledgement++;
                                outgoingPackets.Dequeue();
                            }
                        }
                        
                        if (acked_pubkey) flags = flags | SecurityFlags.RequestPubKey;
                        if (packet.boxed) flags = flags | SecurityFlags.Boxed;
                        manager.SendRaw(packet.data, this, IsTerminating? PacketFlags.Termination : PacketFlags.Reliable, flags);
                    }
                    else
                    {
                        manager.SendRaw(
                            Array.Empty<byte>(),
                            this,
                            PacketFlags.HeartBeat,
                            SecurityFlags.ClearText
                        );
                    }
                }
            }

            public bool Terminated;
            public bool IsTerminating { get; private set; }
            public void Terminate()
            {
                if (IsTerminating) throw new InvalidProgrammerException("terminating");
                wanted_acknowledgement += (ulong)outgoingPackets.Count;
                outgoingPackets.Clear();
                outgoingPackets.Append(new OutgoingPacket() { attempts = 20, data = Array.Empty<byte>(), boxed = false});
                IsTerminating = true;
            }

            

            bool disposed;
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

                disposed = false;
            }  

            ~RemotePeer()
            {
                Dispose();
            }
        }

            List<RemotePeer> peers = new();
            public RemotePeer? GetRemotePeer(SecuredPeerId peerId, bool make = false) 
            {
                RemotePeer? peer = peers.FirstOrDefault(x => x.id.CompareAndUpdate(peerId));
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

            public bool AnyPendingTermination() => peers.Any(x => x.IsTerminating);

    }
}