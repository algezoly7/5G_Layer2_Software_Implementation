#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstdlib>
#include <string>

// ===================== IP PACKET =====================

class IPPacket
{
private:
    std::string srcIP;
    std::string dstIP;
    std::vector<uint8_t> payload;

public:
    IPPacket(std::string src, std::string dst, int payloadSize)
    {
        srcIP = src;
        dstIP = dst;

        payload.resize(payloadSize);
        for (int i = 0; i < payloadSize; i++)
            payload[i] = rand() % 256;
    }

    std::string getSrcIP() { return srcIP; }
    std::string getDstIP() { return dstIP; }
    int getSize() { return payload.size(); }
    std::vector<uint8_t> getPayload() { return payload; }

    void print()
    {
        std::cout << "Src: " << srcIP
                  << " | Dst: " << dstIP
                  << " | Protocol: UDP"
                  << " | Size: " << getSize() << " bytes\n";
    }
};

// ===================== IP PACKET GENERATOR =====================

class IPPacketGenerator
{
private:
    std::string srcIP;
    std::string dstIP;
    int packetSize;
    std::vector<IPPacket> packets;

public:
    IPPacketGenerator(std::string src, std::string dst, int size)
    {
        srcIP = src;
        dstIP = dst;
        packetSize = size;
    }

    void generate(int count)
    {
        packets.clear();
        for (int i = 0; i < count; i++)
            packets.push_back(IPPacket(srcIP, dstIP, packetSize));
        std::cout << "Generated " << count << " packets of " << packetSize << " bytes.\n\n";
    }

    void printAll()
    {
        for (int i = 0; i < (int)packets.size(); i++)
        {
            std::cout << "Packet " << i + 1 << ": ";
            packets[i].print();
        }
    }

    std::vector<IPPacket> getPackets() { return packets; }
};
