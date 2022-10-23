using System;
using System.IO;
using System.IO.Compression;
using System.Web.Security;

internal static class FormsAuthenticationTicketSerializer
{
    private sealed class SerializingBinaryReader : BinaryReader
    {
        public SerializingBinaryReader(Stream input)
            : base(input)
        {
        }

        public string ReadBinaryString()
        {
            int num = Read7BitEncodedInt();
            byte[] array = ReadBytes(num * 2);
            char[] array2 = new char[num];
            for (int i = 0; i < array2.Length; i++)
            {
                array2[i] = (char)(array[2 * i] | (array[2 * i + 1] << 8));
            }
            return new string(array2);
        }

        public override string ReadString()
        {
            throw new NotImplementedException();
        }
    }

    private sealed class SerializingBinaryWriter : BinaryWriter
    {
        public SerializingBinaryWriter(Stream output)
            : base(output)
        {
        }

        public override void Write(string value)
        {
            throw new NotImplementedException();
        }

        public void WriteBinaryString(string value)
        {
            byte[] array = new byte[value.Length * 2];
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                array[2 * i] = (byte)c;
                array[2 * i + 1] = (byte)((int)c >> 8);
            }
            Write7BitEncodedInt(value.Length);
            Write(array);
        }
    }

    private const byte CURRENT_TICKET_SERIALIZED_VERSION = 1;

    public static FormsAuthenticationTicket Deserialize(byte[] serializedTicket, int serializedTicketLength)
    {
        try
        {
            using (var memoryStream = new MemoryStream(serializedTicket))
            {
                using (var serializingBinaryReader = new SerializingBinaryReader(memoryStream))
                {
                    byte b = serializingBinaryReader.ReadByte();
                    if (b != 1)
                    {
                        return null;
                    }
                    int version = serializingBinaryReader.ReadByte();
                    long ticks = serializingBinaryReader.ReadInt64();
                    DateTime issueDateUtc = new DateTime(ticks, DateTimeKind.Utc);
                    DateTime dateTime = issueDateUtc.ToLocalTime();
                    byte b2 = serializingBinaryReader.ReadByte();
                    if (b2 != 254)
                    {
                        return null;
                    }
                    long ticks2 = serializingBinaryReader.ReadInt64();
                    DateTime expirationUtc = new DateTime(ticks2, DateTimeKind.Utc);
                    DateTime dateTime2 = expirationUtc.ToLocalTime();
                    bool isPersistent;
                    switch (serializingBinaryReader.ReadByte())
                    {
                        case 0:
                            isPersistent = false;
                            break;
                        case 1:
                            isPersistent = true;
                            break;
                        default:
                            return null;
                    }
                    string name = serializingBinaryReader.ReadBinaryString();
                    string userData = serializingBinaryReader.ReadBinaryString();
                    string cookiePath = serializingBinaryReader.ReadBinaryString();
                    byte b3 = serializingBinaryReader.ReadByte();
                    if (b3 != byte.MaxValue)
                    {
                        return null;
                    }
                    if (memoryStream.Position != serializedTicketLength)
                    {
                        return null;
                    }
                    return FormsAuthenticationTicket.FromUtc(version, name, issueDateUtc, expirationUtc, isPersistent, userData, cookiePath);
                }
            }
        }
        catch
        {
            return null;
        }
    }

    public static byte[] Serialize(FormsAuthenticationTicket ticket)
    {
        using (var memoryStream = new MemoryStream())
        {
            using (SerializingBinaryWriter serializingBinaryWriter = new SerializingBinaryWriter(memoryStream))
            {
                serializingBinaryWriter.Write((byte)1);
                serializingBinaryWriter.Write((byte)ticket.Version);
                serializingBinaryWriter.Write(ticket.IssueDateUtc.Ticks);
                serializingBinaryWriter.Write((byte)254);
                serializingBinaryWriter.Write(ticket.ExpirationUtc.Ticks);
                serializingBinaryWriter.Write(ticket.IsPersistent);
                serializingBinaryWriter.WriteBinaryString(ticket.Name);
                serializingBinaryWriter.WriteBinaryString(ticket.UserData);
                serializingBinaryWriter.WriteBinaryString(ticket.CookiePath);
                serializingBinaryWriter.Write(byte.MaxValue);
                return memoryStream.ToArray();
            }
        }
    }
}
