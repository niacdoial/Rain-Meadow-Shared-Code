using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
//using System.Security.Cryptography;

/// //////////////////////////////////////////
/// This file describes the common interface for the lowest part of the network stack (for non-steam networking): Peer management
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


namespace RainMeadow.Shared
{

    public partial class SecuredPeerManager : IDisposable
    {
        public Socket socket;
        public ushort port;

        public const int MTU = 65536;  // 1500 is the MTU for general internet communications
        public const int DEFAULT_PORT = 8720;
        public const int FIND_PORT_ATTEMPTS = 8; // 8 players somehow hosting from the same machine is ridiculous.
        public byte[] reusableRecvBuffer = new byte[MTU];

        public void InitSocket(ushort default_port = DEFAULT_PORT, ushort port_attempts = FIND_PORT_ATTEMPTS) {
            try 
            {
                this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                this.socket.Blocking = false;
                this.socket.EnableBroadcast = true;

                port = default_port;
                // Proton 8.0/Wine for FreeBSD bug: GetActiveUdpListeners is unavailable and not correctly emulated

                bool alreadyinuse = false;
                try 
                {
                    var activeUdpListeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners();
                    for (int i = 0; i < port_attempts; i++) {
                        port = (ushort)(default_port + i);
                        alreadyinuse = activeUdpListeners.Any(p => p.Port == port);
                        if (!alreadyinuse)
                            break;
                    }
                }  
                catch (Exception e) 
                {
                    RainMeadow.Error($"{e}");
                }

                if (alreadyinuse) throw new Exception("Failed to claim a socket port");
                socket.Bind(new IPEndPoint(IPAddress.Any, port));
            }
            catch (SocketException except) 
            {
                SharedCodeLogger.Error(except.SocketErrorCode);
                throw;
            }
        }

        public bool IsPacketAvailable() { return socket.Available > 0; }
    }
}
