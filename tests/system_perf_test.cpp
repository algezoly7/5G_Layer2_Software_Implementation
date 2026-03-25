#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <ctime>

#include "../ip_generator.h"
#include "../pdcp.h"
#include "../channel.h"
#include "../rlc.h"
#include "../mac.h"

// ===================== FULL SYSTEM PERFORMANCE TESTS =====================
// Measures end-to-end execution time of the full protocol stack:
//   IP Generator -> PDCP -> RLC -> MAC -> Air -> MAC -> RLC -> PDCP -> IP
//
//   Test 1 — Varying payload size   (fixed packet count, changing payload)
//   Test 2 — Varying packet count   (fixed payload size, changing count)
//   Test 3 — Per-layer breakdown    (how much time each layer takes)

using Clock = std::chrono::high_resolution_clock;
using Ms    = std::chrono::duration<double, std::milli>;

static double elapsedMs(Clock::time_point start)
{
    return Ms(Clock::now() - start).count();
}

const int MAX_ARQ_ROUNDS = 10;

// Silence all console output during timing runs
static std::ostringstream devNull;

// ─────────────────────────────────────────────────────────────────────────────
// runFullStack()
// Runs the complete uplink + downlink stack on a batch of packets.
// Returns per-layer times in milliseconds via output parameters.
// All console output is suppressed during the run.
// ─────────────────────────────────────────────────────────────────────────────
void runFullStack(int payloadSize, int packetCount,
                  double& tIP,
                  double& tPdcpUL, double& tRlcMacUL,
                  double& tRlcMacDL, double& tPdcpDL,
                  double& tVerify,
                  bool&   allMatch)
{
    std::streambuf* orig = std::cout.rdbuf(devNull.rdbuf());

    // ── STEP 1: IP Generation ──────────────────────────────────────────────
    auto t0 = Clock::now();
    IPPacketGenerator gen("192.168.1.1", "10.0.0.1", payloadSize);
    gen.generate(packetCount);
    std::vector<std::vector<uint8_t>> originalPayloads;
    for (auto& p : gen.getPackets())
        originalPayloads.push_back(p.getPayload());
    tIP = elapsedMs(t0);

    // ── STEP 2: PDCP Uplink ────────────────────────────────────────────────
    auto t1 = Clock::now();
    PDCPLayer pdcp(0xAB);
    for (auto& p : gen.getPackets()) pdcp.process(p);
    auto pdus = pdcp.getPDUs();
    tPdcpUL = elapsedMs(t1);

    // ── STEP 3+4: RLC + MAC Uplink + Air + RLC + MAC Downlink ─────────────
    auto t2 = Clock::now();

    RLCSender   rlcTx;
    RLCReceiver rlcRx;
    MACSender   macTx(Direction::UPLINK);
    MACReceiver macRx;

    for (auto& p : pdus) rlcTx.loadPDU(p);

    uint16_t totalSNs = 0;
    int      tbCounter = 0;

    // Phase A: Initial transmission
    while (rlcTx.hasPendingData())
    {
        int grant = pickTBGrant();
        std::vector<RLCpdu> rlcPDUs = rlcTx.getDataForMAC(grant);
        if (rlcPDUs.empty()) break;

        for (auto& p : rlcPDUs)
            if (p.header.sn + 1 > totalSNs) totalSNs = p.header.sn + 1;

        TransportBlock tb = macTx.buildTransportBlock(tbCounter++, grant, rlcPDUs);
        HARQResult harq = macTx.transmitWithHARQ(tb);

        if (harq.receiverDelivered)
            rlcRx.receive(macRx.extractRLCPDUs(tb));
    }

    // Phase B: ARQ recovery
    int arqRound = 0;
    while (!rlcRx.isComplete(totalSNs) && arqRound < MAX_ARQ_ROUNDS)
    {
        arqRound++;
        RLCStatusPDU status = rlcRx.generateStatusPDU(totalSNs);
        if (!status.hasNACKs()) break;

        if (!airTransmit("STATUS-PDU")) continue;

        std::vector<RLCpdu> retxPDUs = rlcTx.handleStatusPDU(status);
        if (retxPDUs.empty()) break;

        TransportBlock retxTB = macTx.buildTransportBlock(
            tbCounter++, 150, retxPDUs, true);
        HARQResult harq = macTx.transmitWithHARQ(retxTB);

        if (harq.receiverDelivered)
            rlcRx.receive(macRx.extractRLCPDUs(retxTB));
    }

    tRlcMacUL = elapsedMs(t2) / 2.0; // approximate UL portion
    tRlcMacDL = elapsedMs(t2) / 2.0; // approximate DL portion

    // ── STEP 5: PDCP Downlink ──────────────────────────────────────────────
    auto t3 = Clock::now();
    auto reassembled = rlcRx.getReassembledPDCPData();
    for (auto& pair : reassembled)
    {
        auto& data = pair.second;
        std::vector<uint8_t> pdcpStream(data.begin() + 2, data.end());
        pdcp.deprocess(pdcpStream);
    }
    tPdcpDL = elapsedMs(t3);

    // ── STEP 6: IP Verification ────────────────────────────────────────────
    auto t4 = Clock::now();
    allMatch = true;
    for (auto& pair : reassembled)
    {
        int pdcpSN = (int)pair.first;
        auto& data = pair.second;
        std::vector<uint8_t> pdcpStream(data.begin() + 2, data.end());
        std::vector<uint8_t> recovered = pdcp.deprocess(pdcpStream);
        if (pdcpSN < (int)originalPayloads.size())
            if (recovered != originalPayloads[pdcpSN]) allMatch = false;
    }
    tVerify = elapsedMs(t4);

    std::cout.rdbuf(orig);
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 1 — Varying Payload Size
// Fixed packet count (20), payload grows from 10B to 2000B.
// Measures total end-to-end time and throughput for each size.
// ─────────────────────────────────────────────────────────────────────────────
void test_varying_payload_size()
{
    std::cout << "\n+======================================================+\n";
    std::cout <<   "|  TEST 1 - Varying Payload Size (100 packets each)   |\n";
    std::cout <<   "+======================================================+\n";
    std::cout << std::left
              << std::setw(14) << "Payload (B)"
              << std::setw(18) << "PDCP UL (ms)"
              << std::setw(18) << "RLC+MAC (ms)"
              << std::setw(18) << "PDCP DL (ms)"
              << std::setw(18) << "Total (ms)"
              << std::setw(18) << "Throughput (MB/s)"
              << "\n";
    std::cout << std::string(104, '-') << "\n";

    std::vector<int> sizes = {10, 50, 100, 200, 500, 1000, 2000};
    const int COUNT = 100;

    for (int size : sizes)
    {
        double tIP, tPdcpUL, tRlcMacUL, tRlcMacDL, tPdcpDL, tVerify;
        bool allMatch;

        runFullStack(size, COUNT,
                     tIP, tPdcpUL, tRlcMacUL, tRlcMacDL, tPdcpDL, tVerify,
                     allMatch);

        double tRlcMac = tRlcMacUL + tRlcMacDL;
        double total   = tIP + tPdcpUL + tRlcMac + tPdcpDL + tVerify;
        double totalBytes  = (double)COUNT * size * 2;
        double throughput  = (totalBytes / 1e6) / (total / 1e3);

        std::cout << std::left
                  << std::setw(14) << size
                  << std::setw(18) << std::fixed << std::setprecision(4) << tPdcpUL
                  << std::setw(18) << tRlcMac
                  << std::setw(18) << tPdcpDL
                  << std::setw(18) << total
                  << std::setw(18) << throughput
                  << (allMatch ? "" : "  [MISMATCH]")
                  << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 2 — Varying Packet Count
// Fixed payload (100B), packet count grows from 5 to 100.
// Measures how end-to-end time scales with the number of packets.
// Note: kept small because RLC+MAC ARQ makes large counts very slow.
// ─────────────────────────────────────────────────────────────────────────────
void test_varying_packet_count()
{
    std::cout << "\n+======================================================+\n";
    std::cout <<   "|  TEST 2 - Varying Packet Count (100B payload each)  |\n";
    std::cout <<   "+======================================================+\n";
    std::cout << std::left
              << std::setw(12) << "Packets"
              << std::setw(18) << "PDCP UL (ms)"
              << std::setw(18) << "RLC+MAC (ms)"
              << std::setw(18) << "PDCP DL (ms)"
              << std::setw(18) << "Total (ms)"
              << std::setw(22) << "Avg per packet (ms)"
              << "\n";
    std::cout << std::string(106, '-') << "\n";

    std::vector<int> counts = {10, 50, 100, 500, 1000, 5000, 10000};
    const int SIZE = 100;

    for (int count : counts)
    {
        double tIP, tPdcpUL, tRlcMacUL, tRlcMacDL, tPdcpDL, tVerify;
        bool allMatch;

        runFullStack(SIZE, count,
                     tIP, tPdcpUL, tRlcMacUL, tRlcMacDL, tPdcpDL, tVerify,
                     allMatch);

        double tRlcMac = tRlcMacUL + tRlcMacDL;
        double total   = tIP + tPdcpUL + tRlcMac + tPdcpDL + tVerify;
        double avgPerPkt = total / count;

        std::cout << std::left
                  << std::setw(12) << count
                  << std::setw(18) << std::fixed << std::setprecision(4) << tPdcpUL
                  << std::setw(18) << tRlcMac
                  << std::setw(18) << tPdcpDL
                  << std::setw(18) << total
                  << std::setw(22) << avgPerPkt
                  << (allMatch ? "" : "  [MISMATCH]")
                  << "\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TEST 3 — Per-Layer Time Breakdown
// Runs the full stack once with 20 packets of 100B and shows what
// percentage of the total time each individual layer consumes.
// ─────────────────────────────────────────────────────────────────────────────
void test_per_layer_breakdown()
{
    std::cout << "\n+======================================================+\n";
    std::cout <<   "|  TEST 3 - Per-Layer Breakdown (20 packets, 100B)    |\n";
    std::cout <<   "+======================================================+\n";

    double tIP, tPdcpUL, tRlcMacUL, tRlcMacDL, tPdcpDL, tVerify;
    bool allMatch;

    runFullStack(100, 20,
                 tIP, tPdcpUL, tRlcMacUL, tRlcMacDL, tPdcpDL, tVerify,
                 allMatch);

    double total = tIP + tPdcpUL + tRlcMacUL + tRlcMacDL + tPdcpDL + tVerify;

    std::cout << std::left
              << std::setw(30) << "Layer"
              << std::setw(16) << "Time (ms)"
              << std::setw(16) << "% of total"
              << "\n";
    std::cout << std::string(62, '-') << "\n";

    auto row = [&](const std::string& name, double t) {
        std::cout << std::left
                  << std::setw(30) << name
                  << std::setw(16) << std::fixed << std::setprecision(4) << t
                  << std::setw(12) << std::setprecision(1) << (t / total * 100) << "%"
                  << "\n";
    };

    row("IP Generation",          tIP);
    row("PDCP Uplink",            tPdcpUL);
    row("RLC + MAC (Uplink)",     tRlcMacUL);
    row("RLC + MAC (Downlink)",   tRlcMacDL);
    row("PDCP Downlink",          tPdcpDL);
    row("IP Verification",        tVerify);
    std::cout << std::string(62, '-') << "\n";
    row("TOTAL",                  total);

    std::cout << "\nAll payloads match: " << (allMatch ? "YES" : "NO") << "\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    srand(time(0));

    std::cout << "+======================================================+\n";
    std::cout << "|       FULL SYSTEM - PERFORMANCE TESTS                |\n";
    std::cout << "|  IP -> PDCP -> RLC -> MAC -> Air -> MAC -> RLC ->    |\n";
    std::cout << "|                            PDCP -> IP                |\n";
    std::cout << "+======================================================+\n";

    test_varying_payload_size();
    test_varying_packet_count();
    test_per_layer_breakdown();

    std::cout << "\n==== All tests complete ====\n";
    return 0;
}
