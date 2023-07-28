using System.Text;

namespace PcapSniffer;

public sealed class ToClientBuffer
{
    private readonly byte[] _buffer = new byte[ushort.MaxValue];
    private int _initialIndex;
    private int _endIndex;
    private readonly byte _serverCryptKey;

    private const int FrameLength = 8;
    private const int PartialFrameLength = 6;

    public ToClientBuffer(byte serverCryptKey)
    {
        _serverCryptKey = serverCryptKey;
    }

    private void Add(ref int index, int toAdd)
    {
        index += toAdd;
        index %= _buffer.Length;
    }

    public List<byte[]> PutPacket(byte[] packet)
    {
        lock (_buffer)
        {
            if (_endIndex + packet.Length > _buffer.Length)
            {
                int diff = packet.Length - _endIndex;
                Array.Copy(packet, 0, _buffer, _endIndex, diff);
                Add(ref _endIndex, diff);
                Array.Copy(packet, diff, _buffer, _endIndex, packet.Length - diff);
                Add(ref _endIndex, packet.Length - diff);
            }
            else
            {
                Array.Copy(packet, 0, _buffer, _endIndex, packet.Length);
                Add(ref _endIndex, packet.Length);
            }

            List<byte[]> list = new();
            byte[]? result = InternalProcessPacket();
            while (result != null)
            {
                list.Add(result);
                result = InternalProcessPacket();
            }

            return list;
        }
    }

    private byte[]? InternalProcessPacket()
    {
        int currentLength = _endIndex < _initialIndex ? _buffer.Length - _initialIndex + _endIndex : _endIndex - _initialIndex;
        if (currentLength < FrameLength)
        {
            return null;
        }
            
        int payloadLength = ((_buffer[_initialIndex + 2] << 8) | _buffer[_initialIndex + 1]) - 3;
        int realPacketLength = payloadLength + PartialFrameLength;
        //Console.WriteLine($"CurrentLength: '{currentLength}' PayloadLength: '{payloadLength}' RealPacketLength: '{realPacketLength}'");
            
        /*StringBuilder builder = new();
        for (int i = _initialIndex; i < _endIndex; i++)
        {
            builder.Append("0x").Append(_buffer[i].ToString("X")).Append(", ");
        }
        Console.WriteLine(builder.ToString());*/
            
        if (currentLength < realPacketLength)
        {
            return null;
        }

        byte[] rawPacket = new byte[realPacketLength];
        if ((_initialIndex + realPacketLength) % _buffer.Length < _initialIndex)
        {
            int diff = _buffer.Length - _initialIndex;
            Array.Copy(_buffer, _initialIndex, rawPacket, 0, diff);
            Add(ref _initialIndex, diff);
            Array.Copy(_buffer, _initialIndex, rawPacket, diff, realPacketLength - diff);
            Add(ref _initialIndex, realPacketLength - diff);
        }
        else
        {
            Array.Copy(_buffer, _initialIndex, rawPacket, 0, realPacketLength);
            Add(ref _initialIndex, realPacketLength);
        }
        byte[] decryptedPacket = Cipher.DecryptServer(rawPacket, _serverCryptKey);
        return decryptedPacket;
    }
}