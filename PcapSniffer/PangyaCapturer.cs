using System.Net;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PcapSniffer;

public enum ServiceType : byte
{
    LoginServer,
    GameServer,
    MessageServer
}

public sealed class PangyaCapturer : IDisposable
{
    private readonly LibPcapLiveDevice _device;
    private readonly Dictionary<(ushort, ushort), ServiceInfo> _services = new();
    
    public PangyaCapturer(LibPcapLiveDevice device)
    {
        _device = device;
        _device.OnPacketArrival += OnPacketArrival;
    }

    public delegate void HandlePacket(object sender, DecryptedPacket decryptedPacket);
    public event HandlePacket? OnPacketReceived;
    public delegate void LogEvent(object sender, string message);
    public event LogEvent? OnLogEvent;
    
    public void Dispose()
    {
        _device.Dispose();
    }

    public void StartCapture()
    {
        if (!_device.Opened)
        {
            _device.Open();
            //_device.Filter = "net 203.107.140.0/24 and tcp portrange 10000-45000";
            _device.Filter = "tcp portrange 10000-45000";
        }
        _device.StartCapture();
    }
    
    public void StopCapture()
    {
        _device.StopCapture();
    }

    private void OnPacketArrival(object sender, PacketCapture rawCapture)
    {
        RawCapture? capture = rawCapture.GetPacket();
        Packet? packet = Packet.ParsePacket(capture.LinkLayerType, capture.Data);
        IPv4Packet? ipv4Packet = packet.Extract<IPv4Packet>();
        TcpPacket? tcpPacket = packet.Extract<TcpPacket>();

        if (tcpPacket == null)
        {
            return;
        }
        
        //Console.WriteLine("Crossed first check!");

        bool isServer = tcpPacket.SourcePort < tcpPacket.DestinationPort;
        ushort port1 = isServer ? tcpPacket.SourcePort : tcpPacket.DestinationPort;
        ushort port2 = isServer ? tcpPacket.DestinationPort : tcpPacket.SourcePort;
        (ushort, ushort) connectionId = (port1, port2);
        
        if (tcpPacket.Finished)
        {
            if (_services.Remove(connectionId))
            {
                OnLogEvent?.Invoke(this, $"Connection finished. {ipv4Packet.SourceAddress}:{tcpPacket.SourcePort} -> {ipv4Packet.DestinationAddress}:{tcpPacket.DestinationPort}");
            }
            return;
        }
        
        if (tcpPacket.PayloadData.Length < 2)
        {
            return;
        }
        
        //Console.WriteLine($"TcpPayloadLength: '{tcpPacket.PayloadData.Length}'");

        ServiceInfo? serviceInfo;
        List<byte[]> decryptedPackets;
        lock (_services)
        {
            serviceInfo = _services.GetValueOrDefault(connectionId);
            if (serviceInfo == null)
            {
                if (RegisterNewService(connectionId, tcpPacket.PayloadData))
                {
                    OnLogEvent?.Invoke(this, $"Connection established. {ipv4Packet.SourceAddress}:{tcpPacket.SourcePort} -> {ipv4Packet.DestinationAddress}:{tcpPacket.DestinationPort}");
                }
                return;
            }

            decryptedPackets = isServer
                ? serviceInfo.ToClientBuffer.PutPacket(tcpPacket.PayloadData)
                : serviceInfo.ToServerBuffer.PutPacket(tcpPacket.PayloadData);
        }

        if (!decryptedPackets.Any())
        {
            //Console.WriteLine("Ups, couldn't decrypt, packet too small!");
            return;
        }
        
        //Console.WriteLine($"Decrypted packet! Packets: '{decryptedPackets.Count}'");

        foreach (byte[] decryptedPacket in decryptedPackets)
        {
            OnPacketReceived?.Invoke(this, new DecryptedPacket(capture.Timeval.Date, serviceInfo.ServiceType, ipv4Packet.SourceAddress, tcpPacket.SourcePort,
                ipv4Packet.DestinationAddress, tcpPacket.DestinationPort, isServer, decryptedPacket));
        }
    }

    private bool RegisterNewService((ushort, ushort) connectionId, byte[] payloadData)
    {
        ServiceType serviceType;
        byte cryptographyKey;
        
        int packetId = (payloadData[1] << 8) | payloadData[0];
        /*StringBuilder text = new();
        foreach (byte subByte in payloadData)
        {
            text.Append($"0x{subByte:x2}, ");
        }
        
        Console.WriteLine($"Registering connection! Id: '0x{packetId:X}' Packet: '{text}'");*/
        switch (packetId)
        {
            case 0xb00:
                serviceType = ServiceType.LoginServer;
                cryptographyKey = payloadData[6];
                break;
            case 0x1500 or 0x600:
                serviceType = ServiceType.GameServer;
                cryptographyKey = payloadData[8];
                break;
            default:
                //TODO: output error
                return false;
        }

        _services[connectionId] = new ServiceInfo(serviceType, new ToClientBuffer(cryptographyKey), new ToServerBuffer(cryptographyKey));
        return true;
    }
}

public record ServiceInfo(ServiceType ServiceType, ToClientBuffer ToClientBuffer, ToServerBuffer ToServerBuffer);
public record DecryptedPacket(DateTime DateTime, ServiceType ServiceType, IPAddress Source, ushort SourcePort, IPAddress Destination, ushort DestinationPort,
    bool IsServer, byte[] Data);