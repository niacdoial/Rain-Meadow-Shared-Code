using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RainMeadow.Shared {
    static partial class SharedPlatform
    {
        // settings
        public static ulong heartbeatTime
        {
            get
            {
                ulong time = 0; getHeartBeatTime(ref time);
                return time;
            }
        }
        public static ulong timeoutTime
        {
            get
            {
                ulong time = 0; getTimeoutTime(ref time);
                return time;
            }
        }

        public static ulong TimeMS
        {
            get
            {
                ulong time = 0; getTimeMS(ref time);
                return time;
            }
        }

        static partial void getHeartBeatTime(ref ulong heartbeatTime);
        static partial void getTimeoutTime(ref ulong TimeoutTime);
        static partial void getTimeMS(ref ulong time);

        static private IPAddress[]? interface_addresses = null;
        static private ReadOnlyCollection<IPAddress>? read_only_interface_addresses = null;
        static public ReadOnlyCollection<IPAddress> InterfaceAddresses
        {
            get
            {
                
                if (read_only_interface_addresses == null) 
                {
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
                    read_only_interface_addresses = new ReadOnlyCollection<IPAddress>(interface_addresses);
                }

                return read_only_interface_addresses;
            }
        } 
        
        static public bool IsLoopback(IPAddress address) => InterfaceAddresses.Contains(address);
        public static bool CompareIPEndpoints(IPEndPoint a, IPEndPoint b) 
        {
            if (!a.Port.Equals(b.Port)) return false;
            if (IsLoopback(a.Address) && IsLoopback(b.Address)) return true;
            return a.Address.GetAddressBytes().SequenceEqual(b.Address.GetAddressBytes())
            // note: in some setups, "a.Address == b.Address" has false negatives for no good reason?
        }


        public static bool IsEndpointLocal(IPAddress address) 
        {
            if (IsLoopback(address)) return true;
            var addressbytes = address.GetAddressBytes();
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) 
            {
                if (addressbytes[0] == 10) return true;
                if (addressbytes[0] == 127) return true;

                if (addressbytes[0] == 172)
                if (addressbytes[1] >= 16 && addressbytes[1] <= 31) return true;

                if (addressbytes[0] == 192)
                if (addressbytes[1] == 168) return true;
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

            IPAddress address;
            try 
            {
                address = IPAddress.Parse(parts[0]);
            } 
            catch (FormatException) 
            {
                try 
                {
                    address = Dns.GetHostEntry(parts[0]).AddressList
                        .Where(x => x.AddressFamily == AddressFamily.InterNetwork)
                        .First();
                } 
                catch (Exception)
                {
                    return null;
                }
            }

            if (!ushort.TryParse(parts[1], out ushort port)) 
            {
                SharedCodeLogger.Debug("Invalid port format: " + parts[1]);
                return null;
            }

            return new IPEndPoint(address, port);
        }
    }
}
