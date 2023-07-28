// See https://aka.ms/new-console-template for more information

using System.Text;
using PangyaSnifferCli;
using PcapSniffer;
using Serilog;
using Serilog.Core;
using SharpPcap.LibPcap;

LibPcapLiveDeviceList? devices = LibPcapLiveDeviceList.Instance;

if (devices.Count < 1)
{
    Console.WriteLine("No devices were found on this machine\n");
    return;
}

Console.WriteLine("The following devices are available on this machine:");
Console.WriteLine("----------------------------------------------------\n");

int i = 0;

// Print out the devices
foreach (LibPcapLiveDevice dev in devices)
{
    /* Description */
    Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
    i++;
}

Console.WriteLine("\n-- Please choose a device to capture: ");
int.TryParse(Console.ReadLine(), out i);

LibPcapLiveDevice? device = devices[i];
using Logger logger = new LoggerConfiguration().ConfigureLogger().CreateLogger();

using PangyaCapturer sniffer = new(device);
sniffer.OnPacketReceived += (_, packet) =>
{
    logger.Information("[{Service}][{Server}][{Source} -> {Destination}] Id: '{Id}' | Length: '{Length}'\n{Data}\n{Code}",
        packet.ServiceType, packet.IsServer ? "Server" : "Client", $"{packet.Source}:{packet.SourcePort}", $"{packet.Destination}:{packet.DestinationPort}",
        (packet.Data[1] << 8) | packet.Data[0], packet.Data.Length, HexDump(packet.Data), ToCode(packet.Data));
};
sniffer.OnLogEvent += (_, message) => { logger.Information("{Message}", message); };
sniffer.StartCapture();
logger.Information("Listening the device!");

while (true)
{
    string? text = Console.ReadLine();
    if (text is "exit")
    {
        break;
    }
}

static string HexDump(byte[] bytes, int bytesPerLine = 16)
{
    int bytesLength = bytes.Length;

    char[] HexChars = "0123456789ABCDEF".ToCharArray();

    int firstHexColumn =
          8                   // 8 characters for the address
        + 3;                  // 3 spaces

    int firstCharColumn = firstHexColumn
        + bytesPerLine * 3       // - 2 digit for the hexadecimal value and 1 space
        + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
        + 2;                  // 2 spaces 

    int lineLength = firstCharColumn
        + bytesPerLine           // - characters to show the ascii value
        + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

    char[] line = (new String(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
    int expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
    StringBuilder result = new(expectedLines * lineLength);

    for (int i = 0; i < bytesLength; i += bytesPerLine)
    {
        line[0] = HexChars[(i >> 28) & 0xF];
        line[1] = HexChars[(i >> 24) & 0xF];
        line[2] = HexChars[(i >> 20) & 0xF];
        line[3] = HexChars[(i >> 16) & 0xF];
        line[4] = HexChars[(i >> 12) & 0xF];
        line[5] = HexChars[(i >> 8) & 0xF];
        line[6] = HexChars[(i >> 4) & 0xF];
        line[7] = HexChars[(i >> 0) & 0xF];

        int hexColumn = firstHexColumn;
        int charColumn = firstCharColumn;

        for (int j = 0; j < bytesPerLine; j++)
        {
            if (j > 0 && (j & 7) == 0) hexColumn++;
            if (i + j >= bytesLength)
            {
                line[hexColumn] = ' ';
                line[hexColumn + 1] = ' ';
                line[charColumn] = ' ';
            }
            else
            {
                byte b = bytes[i + j];
                line[hexColumn] = HexChars[(b >> 4) & 0xF];
                line[hexColumn + 1] = HexChars[b & 0xF];
                line[charColumn] = (b < 32 ? '·' : (char)b);
            }
            hexColumn += 3;
            charColumn++;
        }
        result.Append(line);
    }
    return result.ToString();
}

static string ToCode(byte[] data)
{
    StringBuilder builder = new();
    for (int i = 0; i < data.Length; i++)
    {
        builder.Append("0x").Append(data[i].ToString("X")).Append(", ");
    }

    return builder.ToString();
}