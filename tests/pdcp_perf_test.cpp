#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include "../ip_generator.h"
#include "../pdcp.h"

// ===================== PDCP PERFORMANCE TESTS =====================
// Measures execution time of the PDCP sublayer under different conditions:
//   Test 1 — Varying payload sizes    (fixed packet count, changing size)
//   Test 2 — Varying packet counts    (fixed payload size, changing count)
//   Test 3 — Uplink vs Downlink time  (how long each direction takes)
//   Test 4 — Per-stage breakdown      (compression vs checksum vs encryption)

using Clock = std::chrono::high_resolution_clock;
using Ms = std::chrono::duration<double, std::milli>;
using Us = std::chrono::duration<double, std::micro>;

// Helper: returns elapsed milliseconds since `start`
static double elapsedMs(Clock::time_point start)
{
    return Ms(Clock::now() - start).count();
}

// Helper: returns elapsed microseconds since `start`
static double elapsedUs(Clock::time_point start)
{
    return Us(Clock::now() - start).count();
}

// Suppress all PDCP console output during timing runs by redirecting cout
#include <sstream>
static std::ostringstream devNull;

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1 — Varying Payload Sizes
// Fixed packet count (100 packets), payload grows from 10B to 2000B.
// Measures total uplink + downlink time for each size.
// ─────────────────────────────────────────────────────────────────────────────
void test_varying_payload_size()
{
    std::cout << "\n+======================================================+\n";
    std::cout << "|  TEST 1 — Varying Payload Size (100 packets each)   |\n";
    std::cout << "+======================================================+\n";
    std::cout << std::left
              << std::setw(14) << "Payload (B)"
              << std::setw(18) << "Uplink (ms)"
              << std::setw(18) << "Downlink (ms)"
              << std::setw(18) << "Total (ms)"
              << std::setw(18) << "Throughput (MB/s)"
              << "\n";
    std::cout << std::string(86, '-') << "\n";

    std::vector<int> sizes = {10, 50, 100, 200, 500, 1000, 2000};
    const int PACKET_COUNT = 100;

    for (int size : sizes)
    {
        // --- Generate packets ---
        IPPacketGenerator gen("192.168.1.1", "10.0.0.1", size);
        // Suppress output
        std::streambuf *orig = std::cout.rdbuf(devNull.rdbuf());
        gen.generate(PACKET_COUNT);
        std::cout.rdbuf(orig);

        std::vector<IPPacket> packets = gen.getPackets();

        // --- Uplink timing ---
        PDCPLayer pdcp(0xAB);
        std::cout.rdbuf(devNull.rdbuf());
        auto ulStart = Clock::now();
        for (auto &p : packets)
            pdcp.process(p);
        double ulTime = elapsedMs(ulStart);
        std::cout.rdbuf(orig);

        // --- Downlink timing ---
        std::vector<PDCPpdu> pdus = pdcp.getPDUs();
        std::vector<std::vector<uint8_t>> streams;
        for (auto &pdu : pdus)
            streams.push_back(pdu.getEncryptedPayload());

        std::cout.rdbuf(devNull.rdbuf());
        auto dlStart = Clock::now();
        for (auto &s : streams)
            pdcp.deprocess(s);
        double dlTime = elapsedMs(dlStart);
        std::cout.rdbuf(orig);

        double totalTime = ulTime + dlTime;
        double totalBytes = (double)PACKET_COUNT * size * 2;        // uplink + downlink
        double throughput = (totalBytes / 1e6) / (totalTime / 1e3); // MB/s

        std::cout << std::left
                  << std::setw(14) << size
                  << std::setw(18) << std::fixed << std::setprecision(4) << ulTime
                  << std::setw(18) << dlTime
                  << std::setw(18) << totalTime
                  << std::setw(18) << throughput
                  << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2 — Varying Packet Count
// Fixed payload size (100B), packet count grows from 10 to 10000.
// Measures how processing time scales with the number of packets.
// ─────────────────────────────────────────────────────────────────────────────
void test_varying_packet_count()
{
    std::cout << "\n+======================================================+\n";
    std::cout << "|  TEST 2 — Varying Packet Count (100B payload each)  |\n";
    std::cout << "+======================================================+\n";
    std::cout << std::left
              << std::setw(14) << "Packets"
              << std::setw(18) << "Uplink (ms)"
              << std::setw(18) << "Downlink (ms)"
              << std::setw(18) << "Total (ms)"
              << std::setw(22) << "Avg per packet (us)"
              << "\n";
    std::cout << std::string(90, '-') << "\n";

    std::vector<int> counts = {10, 50, 100, 500, 1000, 5000, 10000};
    const int PAYLOAD_SIZE = 100;

    for (int count : counts)
    {
        IPPacketGenerator gen("192.168.1.1", "10.0.0.1", PAYLOAD_SIZE);
        std::streambuf *orig = std::cout.rdbuf(devNull.rdbuf());
        gen.generate(count);
        std::cout.rdbuf(orig);

        std::vector<IPPacket> packets = gen.getPackets();

        // Uplink
        PDCPLayer pdcp(0xAB);
        std::cout.rdbuf(devNull.rdbuf());
        auto ulStart = Clock::now();
        for (auto &p : packets)
            pdcp.process(p);
        double ulTime = elapsedMs(ulStart);
        std::cout.rdbuf(orig);

        // Downlink
        std::vector<PDCPpdu> pdus = pdcp.getPDUs();
        std::vector<std::vector<uint8_t>> streams;
        for (auto &pdu : pdus)
            streams.push_back(pdu.getEncryptedPayload());

        std::cout.rdbuf(devNull.rdbuf());
        auto dlStart = Clock::now();
        for (auto &s : streams)
            pdcp.deprocess(s);
        double dlTime = elapsedMs(dlStart);
        std::cout.rdbuf(orig);

        double totalTime = ulTime + dlTime;
        double avgPerPkt = (totalTime * 1000.0) / (count * 2); // us per packet

        std::cout << std::left
                  << std::setw(14) << count
                  << std::setw(18) << std::fixed << std::setprecision(4) << ulTime
                  << std::setw(18) << dlTime
                  << std::setw(18) << totalTime
                  << std::setw(22) << std::setprecision(3) << avgPerPkt
                  << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3 — Uplink vs Downlink Time Comparison
// Runs both directions separately and compares how long each takes.
// Useful to see if one direction is heavier than the other.
// ─────────────────────────────────────────────────────────────────────────────
void test_uplink_vs_downlink()
{
    std::cout << "\n+======================================================+\n";
    std::cout << "|  TEST 3 — Uplink vs Downlink Time (1000 packets)    |\n";
    std::cout << "+======================================================+\n";
    std::cout << std::left
              << std::setw(14) << "Payload (B)"
              << std::setw(18) << "Uplink (ms)"
              << std::setw(18) << "Downlink (ms)"
              << std::setw(20) << "UL/DL ratio"
              << "\n";
    std::cout << std::string(70, '-') << "\n";

    std::vector<int> sizes = {50, 100, 500, 1000};
    const int COUNT = 1000;

    for (int size : sizes)
    {
        IPPacketGenerator gen("192.168.1.1", "10.0.0.1", size);
        std::streambuf *orig = std::cout.rdbuf(devNull.rdbuf());
        gen.generate(COUNT);
        std::cout.rdbuf(orig);

        std::vector<IPPacket> packets = gen.getPackets();

        // Uplink
        PDCPLayer pdcp(0xAB);
        std::cout.rdbuf(devNull.rdbuf());
        auto ulStart = Clock::now();
        for (auto &p : packets)
            pdcp.process(p);
        double ulTime = elapsedMs(ulStart);
        std::cout.rdbuf(orig);

        // Downlink
        std::vector<PDCPpdu> pdus = pdcp.getPDUs();
        std::vector<std::vector<uint8_t>> streams;
        for (auto &pdu : pdus)
            streams.push_back(pdu.getEncryptedPayload());

        std::cout.rdbuf(devNull.rdbuf());
        auto dlStart = Clock::now();
        for (auto &s : streams)
            pdcp.deprocess(s);
        double dlTime = elapsedMs(dlStart);
        std::cout.rdbuf(orig);

        double ratio = (dlTime > 0) ? ulTime / dlTime : 0;

        std::cout << std::left
                  << std::setw(14) << size
                  << std::setw(18) << std::fixed << std::setprecision(4) << ulTime
                  << std::setw(18) << dlTime
                  << std::setw(20) << std::setprecision(3) << ratio
                  << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 4 — Per-Stage Breakdown (Uplink)
// Times each PDCP stage independently to show which one is the bottleneck.
// Stages: header compression / checksum computation / XOR encryption
// ─────────────────────────────────────────────────────────────────────────────
void test_per_stage_breakdown()
{
    std::cout << "\n+======================================================+\n";
    std::cout << "|  TEST 4 — Per-Stage Breakdown (1000 packets, 100B)  |\n";
    std::cout << "+======================================================+\n";

    const int COUNT = 1000;
    const int SIZE = 100;

    IPPacketGenerator gen("192.168.1.1", "10.0.0.1", SIZE);
    std::streambuf *orig = std::cout.rdbuf(devNull.rdbuf());
    gen.generate(COUNT);
    std::cout.rdbuf(orig);

    std::vector<IPPacket> packets = gen.getPackets();

    // --- Stage 1: Header compression only ---
    // Simulate by doing compression separately COUNT times
    double compressionTime = 0;
    {
        std::map<uint16_t, std::pair<std::string, std::string>> table;
        uint16_t nextID = 0;
        auto start = Clock::now();
        for (auto &p : packets)
        {
            // Check if pair exists (same logic as compressHeader)
            bool found = false;
            for (auto &kv : table)
                if (kv.second.first == p.getSrcIP() &&
                    kv.second.second == p.getDstIP())
                {
                    found = true;
                    break;
                }
            if (!found)
                table[nextID++] = {p.getSrcIP(), p.getDstIP()};
        }
        compressionTime = elapsedMs(start);
    }

    // --- Stage 2: Checksum computation only ---
    double checksumTime = 0;
    {
        auto start = Clock::now();
        for (auto &p : packets)
        {
            uint8_t sum = 0;
            for (auto b : p.getPayload())
                sum += b;
            (void)sum;
        }
        checksumTime = elapsedMs(start);
    }

    // --- Stage 3: XOR encryption only ---
    double encryptionTime = 0;
    {
        uint8_t key = 0xAB;
        auto start = Clock::now();
        for (auto &p : packets)
        {
            auto payload = p.getPayload();
            for (auto &b : payload)
                b ^= key;
        }
        encryptionTime = elapsedMs(start);
    }

    double total = compressionTime + checksumTime + encryptionTime;

    std::cout << std::left
              << std::setw(30) << "Stage"
              << std::setw(16) << "Time (ms)"
              << std::setw(16) << "% of total"
              << "\n";
    std::cout << std::string(62, '-') << "\n";

    auto printRow = [&](const std::string &name, double t)
    {
        std::cout << std::left
                  << std::setw(30) << name
                  << std::setw(16) << std::fixed << std::setprecision(4) << t
                  << std::setw(16) << std::setprecision(1) << (t / total * 100) << "%"
                  << "\n";
    };

    printRow("Header Compression", compressionTime);
    printRow("Checksum Computation", checksumTime);
    printRow("XOR Encryption", encryptionTime);
    std::cout << std::string(62, '-') << "\n";
    printRow("TOTAL", total);
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    srand(time(0));

    std::cout << "+======================================================+\n";
    std::cout << "|          PDCP SUBLAYER — PERFORMANCE TESTS           |\n";
    std::cout << "+======================================================+\n";

    test_varying_payload_size();
    test_varying_packet_count();
    test_uplink_vs_downlink();
    test_per_stage_breakdown();

    std::cout << "\n==== All tests complete ====\n";
    return 0;
}
