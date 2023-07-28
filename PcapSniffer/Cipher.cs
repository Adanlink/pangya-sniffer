//Obtained from PangCrypt -> https://github.com/pangyatools/PangCrypt
namespace PcapSniffer;

public static class Cipher
{
    /// <summary>
    ///     Decrypts data from client-side packets (sent from clients to servers.)
    /// </summary>
    /// <param name="source">The encrypted packet data.</param>
    /// <param name="key">Key to decrypt with.</param>
    /// <returns>The decrypted packet data.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the key is equal or superior to 0x10</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if the source's length is inferior to 5</exception>
    public static byte[] DecryptClient(byte[] source, byte key)
    {
        if (key >= 0x10)
        {
            throw new ArgumentOutOfRangeException(nameof(key),
                $"[{nameof(Cipher)}][{nameof(DecryptClient)}] The cryptography key is too big, the key generation should be changed.");
        }

        if (source.Length < 5)
        {
            throw new ArgumentOutOfRangeException(nameof(key),
                $"[{nameof(Cipher)}][{nameof(DecryptClient)}] The packet is too small to get decrypted ({source.Length.ToString()} < 5)");
        }

        byte[] buffer = (byte[]) source.Clone();

        buffer[4] = CryptoOracle.CryptTable2[(key << 8) + source[0]];

        for (int i = 8; i < buffer.Length; i++)
        {
            buffer[i] ^= buffer[i - 4];
        }

        byte[] output = new byte[buffer.Length - 5];

        Array.Copy(buffer, 5, output, 0, buffer.Length - 5);

        return output;
    }
        
    /// <summary>
    ///     Decrypts data from server-side packets (sent from servers to clients.)
    /// </summary>
    /// <param name="source">The encrypted packet data.</param>
    /// <param name="serverCryptKey">Key to decrypt with.</param>
    /// <returns>The decrypted packet data.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    ///     Thrown if the key is invalid or the packet data is too short.
    /// </exception>
    public static byte[] DecryptServer(byte[] source, byte serverCryptKey)
    {
        if (serverCryptKey >= 0x10) throw new ArgumentOutOfRangeException(nameof(serverCryptKey), $"Key too large ({serverCryptKey} >= 0x10)");

        if (source.Length < 8)
            throw new ArgumentOutOfRangeException(nameof(source), $"Packet too small ({source.Length} < 8)");

        byte oracleByte = CryptoOracle.CryptTable2[(serverCryptKey << 8) + source[0]];
        byte[] buffer = (byte[]) source.Clone();

        buffer[7] ^= oracleByte;

        for (int i = 10; i < source.Length; i++) buffer[i] ^= buffer[i - 4];

        byte[] compressedData = new byte[source.Length - 8];
        Array.Copy(buffer, 8, compressedData, 0, source.Length - 8);
        return MiniLzo.Decompress(compressedData);
    }
}