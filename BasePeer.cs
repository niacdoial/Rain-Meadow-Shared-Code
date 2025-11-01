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
    public abstract class BasePeerManager : IDisposable
    {
        public Socket socket;
        public int port;

        public const int DEFAULT_PORT = 8720;
        public const int FIND_PORT_ATTEMPTS = 8; // 8 players somehow hosting from the same machine is ridiculous.

        voic InitSocket(int default_port = DEFAULT_PORT, int port_attempts = FIND_PORT_ATTEMPTS) {
            try {
                this.socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                this.socket.Blocking = false;
                this.socket.EnableBroadcast = true;

                port = default_port;
                // Proton 8.0/Wine for FreeBSD bug: GetActiveUdpListeners is unavailable and not correctly emulated
                try {
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
                }  catch (Exception e) {
                    RainMeadow.Error($"{e}");
                }
                socket.Bind(new IPEndPoint(IPAddress.Any, port));
            } catch (SocketException except) {
                SharedCodeLogger.Error(except.SocketErrorCode);
                throw except;
            }
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

        static public string describeEndPoint(IPEndPoint endPoint, IPEndPoint serverEndPoint=null){
            return String.Format(
                "[IP: is machine local: {0}, is network local: {1}, is devnull: {2}]",
                isLoopback(endPoint.Address),
                isEndpointLocal(endPoint),
                CompareIPEndpoints(endPoint, SharedPlatform.BlackHole)
            );
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
    }
}
