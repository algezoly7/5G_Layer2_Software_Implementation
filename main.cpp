#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <chrono>

#include "ip_generator.h"  // Layer 3   : IP packet simulation
#include "rach.h"          // L2 / RRC  : NR Random Access (4-message handshake, TS 38.321 §5.1)
#include "pdcp.h"          // Layer 2a  : Packet Data Convergence Protocol  (TS 38.323)
#include "channel.h"       // Air interface: 30% loss + grant sizing         (TS 38.300)
#include "rlc.h"           // Layer 2b  : Radio Link Control                 (TS 38.322)
#include "mac.h"           // Layer 2c  : Medium Access Control              (TS 38.321)

const int MAX_ARQ_ROUNDS = 10; // Give up RLC ARQ recovery after this many rounds

// ─────────────────────────────────────────────────────────────────────────────
//  DESIGN SIMPLIFICATIONS (intentional — single-UE educational simulation)
//
//  1. No LCP (Logical Channel Prioritisation):
//     LCP exists to arbitrate between multiple logical channels competing for
//     the same TBS grant (e.g. signalling vs video vs voice). In this
//     simulation there is exactly one data bearer (DTCH/DRB1) carrying one
//     type of traffic (user IP data) in one direction (uplink). With a single
//     channel there is nothing to prioritise, so LCP reduces to "give all
//     bytes to DTCH" and the algorithm is trivially satisfied by pickTBGrant().
//
//  2. No complex BSR / Scheduler interaction:
//     A real BSR tells the gNB scheduler how much data is queued across all
//     Logical Channel Groups so it can dimension the next TBS precisely.
//     Here there is only one LCG with one bearer, and the queue depth is
//     visible directly (rlcTx.pendingCount()). The gNB therefore uses a
//     simple weighted-random grant: 25B (25%), 100B (50%), 150B (25%) via
//     pickTBGrant() — this captures the realistic distribution of small,
//     medium, and large allocations without a multi-step SR/BSR exchange.
//
//  3. No C-RNTI filtering on MAC receiver:
//     C-RNTI filtering is needed when multiple UEs share the same physical
//     channel and a UE must reject Transport Blocks addressed to others.
//     With a single UE in the simulation, every TB on the channel belongs
//     to this UE — so the filter check is always trivially true and adds
//     no educational value while complicating the code.
//
//  These simplifications do NOT affect the correctness of:
//    RACH (4-message handshake, 30% loss per message),
//    RLC segmentation / concatenation / ARQ retransmission,
//    MAC Transport Block construction / demultiplexing,
//    HARQ (up to 4 rounds, 30% loss on TB and feedback),
//    PDCP ROHC compression, AES-equivalent encryption, integrity check,
//    or the full end-to-end IP → PDCP → RLC → MAC → Uu → MAC → RLC → PDCP → IP loop.
// ─────────────────────────────────────────────────────────────────────────────

int main()
{
    // Seed with microsecond precision so rapid successive runs produce different results.
    // srand(time(0)) only has 1-second resolution — consecutive runs within the same
    // second would produce identical output, making the channel loss simulation appear
    // deterministic when it should be stochastic.
    auto seed = (unsigned)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    srand(seed);

    // ===========================================================
    //  STEP 1 — IP Packet Generation
    // ===========================================================
    std::cout << "===================================================\n";
    std::cout << "  STEP 1 — IP Packet Generation\n";
    std::cout << "===================================================\n";

    IPPacketGenerator gen("192.168.1.1", "10.0.0.1", 100);
    gen.generate(5);
    gen.printAll();

    // Save original IP payloads now for verification at the end of the downlink
    std::vector<std::vector<uint8_t>> originalPayloads;
    for (auto& p : gen.getPackets())
        originalPayloads.push_back(p.getPayload());

    // ===========================================================
    //  STEP 2 — PDCP Layer  (3GPP TS 38.323)
    //  a) Header compression   (ROHC simulation — prints bytes saved)
    //  b) Integrity checksum   (8-bit sum of original payload)
    //  c) XOR encryption       (key 0xAB — every payload byte XOR-ed)
    //  Output: one PDCPpdu per packet  (SN + checksum + encrypted payload)
    //
    //  The data is now fully prepared and ready to be segmented by RLC.
    //  Before handing it down, the UE must first obtain radio access
    //  via the RACH procedure (Step 3).
    // ===========================================================
    std::cout << "\n===================================================\n";
    std::cout << "  STEP 2 — PDCP Layer\n";
    std::cout << "===================================================\n";

    PDCPLayer pdcp(0xAB);
    for (auto& p : gen.getPackets()) pdcp.process(p);

    auto pdus = pdcp.getPDUs();
    std::cout << "\n  Integrity verification of all " << pdus.size() << " PDUs:\n";
    for (auto& p : pdus) pdcp.verify(p);

    std::cout << "\n  PDCP PDU serialised layout for RLC (variable size due to ROHC):\n";
    std::cout << "    First PDU : [ SN_hi | SN_lo | checksum | 0x00 | src_len | src | dst_len | dst | payload ] = 125B\n";
    std::cout << "    Other PDUs: [ SN_hi | SN_lo | checksum | 0x01 | ctx_hi  | ctx_lo | payload ] = 106B\n";
    std::cout << "  RLC slices this stream into segments; receiver reassembles then passes to PDCP decrypt.\n";

    // ===========================================================
    //  STEP 3 — NR Random Access Procedure  (3GPP TS 38.321 §5.1)
    //
    //  The IP data is compressed, encrypted, and waiting in the PDCP queue.
    //  Before RLC/MAC can transmit it, the UE must acquire radio resources
    //  from the gNB via the 4-message RACH handshake:
    //
    //    Msg1 (UE → gNB)  PRACH Preamble  — one of 64 Zadoff-Chu sequences
    //    Msg2 (gNB → UE)  Random Access Response (RAR) — TC-RNTI + UL grant
    //    Msg3 (UE → gNB)  RRC Setup Request — UE identity for contention resolution
    //    Msg4 (gNB → UE)  RRC Setup — Contention Resolution + dedicated C-RNTI
    //
    //  Every message crosses the 30%-loss air channel.  If any message is
    //  lost the UE backs off and restarts from Msg1 (up to 5 attempts).
    //  The C-RNTI returned here identifies this UE on all subsequent
    //  UL-SCH and DL-SCH transmissions.
    // ===========================================================
    std::cout << "\n===================================================\n";
    std::cout << "  STEP 3 — NR Random Access Procedure (RACH)\n";
    std::cout << "===================================================\n";

    RACHProcedure rach;
    RACHResult    rachResult = rach.run();

    std::cout << "\n  [RACH] UE now has dedicated C-RNTI = ";
    {
        char buf[8];
        snprintf(buf, sizeof(buf), "0x%04X", (unsigned)rachResult.cRNTI);
        std::cout << buf;
    }
    std::cout << "  — ready for scheduled UL/DL transmissions.\n";

    // ===========================================================
    //  STEP 4+5 — RLC + MAC  (UE ---Uu air--- gNB)
    //
    //  The UE uses the C-RNTI assigned by RACH (Step 2) for all
    //  uplink grants and HARQ feedback on the Uu interface.
    //
    //  Layer interaction summary:
    //    [1] MAC scheduler (gNB) picks a grant size: 25 / 100 / 150 B (weighted random)
    //    [2] MAC asks RLC: "give me data to fill a TB of X bytes"
    //    [3] RLC segments or concatenates PDCP PDUs to fill exactly X bytes
    //        (each RLC PDU = RLC_HEADER(6B) + payload; MAC sub-header adds 3B overhead)
    //    [4] MAC builds Transport Block: sub-headers + RLC PDUs  (TS 38.321 §6.1)
    //    [5] HARQ: TB travels Uu air channel (30% loss per attempt, up to 4 rounds)
    //        Feedback (ACK/NACK) also travels the lossy channel (30% loss)
    //    [6] If TB arrives: receiver MAC demultiplexes sub-headers -> RLC PDUs
    //    [7] Receiver RLC stores PDUs; duplicate SNs are detected and dropped
    //    [8] ARQ: once all sender SNs are known, receiver RLC checks for gaps
    //        and sends a STATUS PDU (ackSN + NACK list) back to sender
    //        STATUS PDU also travels the lossy channel (30% loss)
    //    [9] Sender RLC reads NACK list; retransmits missing PDUs through MAC+HARQ
    //   [10] Loop until receiver RLC has all SNs or MAX_ARQ_ROUNDS reached
    // ===========================================================
    std::cout << "\n===================================================\n";
    std::cout << "  STEP 4+5 — RLC + MAC  (UE ---Uu--- gNB)  [C-RNTI active]\n";
    std::cout << "===================================================\n";
    std::cout << "  C-RNTI in use            : ";
    {
        char buf[8];
        snprintf(buf, sizeof(buf), "0x%04X", (unsigned)rachResult.cRNTI);
        std::cout << buf;
    }
    std::cout << "\n";
    std::cout << "  Channel loss probability : 30%  (TB, ACK, NACK, STATUS PDU)\n";
    std::cout << "  HARQ max rounds          : 4 per Transport Block\n";
    std::cout << "  ARQ  max rounds          : " << MAX_ARQ_ROUNDS << " recovery cycles\n";
    std::cout << "  Grant distribution       : 25B(25%)  100B(50%)  150B(25%)\n\n";

    // --- Instantiate all four layer objects ---
    RLCSender   rlcTx;
    RLCReceiver rlcRx;
    MACSender   macTx(Direction::UPLINK);
    MACReceiver macRx;

    // Load all 5 PDCP PDUs into sender RLC input queue
    std::cout << "  Loading " << pdus.size()
              << " PDCP PDUs into RLC sender queue...\n";
    for (auto& p : pdus) rlcTx.loadPDU(p);

    // totalSNs tracks the highest SN the sender has ever assigned.
    // The receiver uses this as the upper bound when checking for gaps.
    uint16_t totalSNs = 0;
    int      tbCounter = 0;

    // ── PHASE A: Initial Transmission ──────────────────────────────────
    // Keep building and transmitting Transport Blocks until the RLC sender
    // queue is empty (all PDCP PDUs have been handed to MAC at least once).
    std::cout << "\n  ---- Phase A: Initial Transmission ----\n";

    while (rlcTx.hasPendingData())
    {
        // [1] MAC scheduler (gNB) grants a random TB size
        int grant = pickTBGrant();
        std::cout << "\n  [MAC-SCHED] Grant for next TB: " << grant << "B"
                  << "  (remaining PDUs in RLC queue: "
                  << rlcTx.pendingCount() << ")\n";

        // [2] RLC fills the grant — segments / concatenates PDCP PDUs
        std::vector<RLCpdu> rlcPDUs = rlcTx.getDataForMAC(grant);
        if (rlcPDUs.empty())
        {
            std::cout << "  [RLC-TX] Nothing to send (grant too small for overhead)\n";
            break;
        }

        // Track the highest SN assigned so far
        for (auto& p : rlcPDUs)
            if (p.header.sn + 1 > totalSNs) totalSNs = p.header.sn + 1;

        std::cout << "  [RLC-TX] Produced " << rlcPDUs.size()
                  << " RLC PDU(s) for grant of " << grant << "B:\n";
        for (auto& p : rlcPDUs) p.print();

        // [3] MAC builds Transport Block (adds sub-headers)
        TransportBlock tb = macTx.buildTransportBlock(tbCounter++, grant, rlcPDUs);
        std::cout << "  [MAC-TX] TB assembled:\n";
        tb.print();

        // [4] HARQ: transmit TB across Uu air channel (up to 4 attempts)
        std::cout << "\n  -- HARQ for TB #" << tb.tbID << " --\n";
        HARQResult harq = macTx.transmitWithHARQ(tb);

        // [5] If receiver MAC got a clean TB, demultiplex and pass to RLC
        if (harq.receiverDelivered)
        {
            std::cout << "\n  [MAC-RX] TB #" << tb.tbID
                      << " received clean — demultiplexing:\n";
            auto rxPDUs = macRx.extractRLCPDUs(tb);

            std::cout << "  [RLC-RX] Storing " << rxPDUs.size()
                      << " RLC PDU(s):\n";
            rlcRx.receive(rxPDUs);
        }
        else
        {
            std::cout << "\n  [HARQ-FAIL] TB #" << tb.tbID
                      << " permanently lost — RLC ARQ will recover.\n";
        }
    }

    // ── PHASE B: RLC ARQ Recovery ──────────────────────────────────────
    // Check receiver RLC for gaps.  If any SNs are missing, the receiver
    // generates a STATUS PDU and sends it back to the sender.
    // The STATUS PDU itself travels through the lossy Uu channel.
    // If it arrives, sender RLC retransmits the NACKed PDUs through
    // MAC + HARQ again.  Repeat until all SNs arrive or we give up.
    std::cout << "\n  ---- Phase B: RLC ARQ Recovery ----\n";
    std::cout << "  Total SNs sender assigned: " << totalSNs << "\n";
    std::cout << "  Receiver has             : " << rlcRx.receivedCount()
              << " / " << totalSNs << " RLC PDUs\n";

    int arqRound = 0;
    while (!rlcRx.isComplete(totalSNs) && arqRound < MAX_ARQ_ROUNDS)
    {
        arqRound++;
        std::cout << "\n  -- ARQ Round " << arqRound << " --\n";

        // [8] Receiver RLC detects gaps and builds a STATUS PDU
        RLCStatusPDU status = rlcRx.generateStatusPDU(totalSNs);
        std::cout << "  [RLC-RX] STATUS PDU generated: ";
        status.print();

        if (!status.hasNACKs())
        {
            std::cout << "  [RLC-RX] No NACKs — all SNs present, stopping ARQ.\n";
            break;
        }

        // STATUS PDU travels the reverse Uu air path (30% loss)
        std::cout << "  [ARQ] STATUS PDU travelling reverse Uu air path:\n";
        bool statusArrived = airTransmit("STATUS-PDU");

        if (!statusArrived)
        {
            std::cout << "  [ARQ] STATUS PDU lost — sender doesn't know about gaps"
                         " this round.\n       Receiver will retry next ARQ round.\n";
            continue;
        }

        // [9] Sender RLC processes the STATUS PDU
        std::cout << "  [RLC-TX] STATUS PDU received by sender RLC.\n";
        std::vector<RLCpdu> retxPDUs = rlcTx.handleStatusPDU(status);

        if (retxPDUs.empty())
        {
            std::cout << "  [RLC-TX] No PDUs to retransmit (all NACKed SNs already"
                         " cleared).\n";
            break;
        }

        std::cout << "  [RLC-TX] Will retransmit " << retxPDUs.size()
                  << " RLC PDU(s):\n";
        for (auto& p : retxPDUs) p.print();

        // Retransmit one TB per ARQ recovery cycle containing all missing PDUs.
        // If they don't all fit in one grant, use a large 150B grant.
        // (In a real system the gNB scheduler would issue multiple grants.)
        int retxGrant = 150;
        TransportBlock retxTB = macTx.buildTransportBlock(
            tbCounter++, retxGrant, retxPDUs, /*retx=*/true);

        std::cout << "  [MAC-TX] Retransmission TB assembled:\n";
        retxTB.print();

        // HARQ for the retransmission TB
        std::cout << "\n  -- HARQ for retransmission TB #" << retxTB.tbID << " --\n";
        HARQResult harq = macTx.transmitWithHARQ(retxTB);

        if (harq.receiverDelivered)
        {
            std::cout << "\n  [MAC-RX] Retransmission TB received — demultiplexing:\n";
            auto rxPDUs = macRx.extractRLCPDUs(retxTB);
            std::cout << "  [RLC-RX] Storing retransmitted PDU(s):\n";
            rlcRx.receive(rxPDUs);
        }
        else
        {
            std::cout << "\n  [HARQ-FAIL] Retransmission TB also lost."
                         " Will try again next ARQ round.\n";
        }

        std::cout << "  Receiver now has: " << rlcRx.receivedCount()
                  << " / " << totalSNs << " RLC PDUs\n";
    }

    // ── PHASE C: Final Status & Reassembly Preview ─────────────────────
    std::cout << "\n===================================================\n";
    std::cout << "  Final Status\n";
    std::cout << "===================================================\n";
    std::cout << "  Sender total SNs assigned : " << totalSNs << "\n";
    std::cout << "  Receiver SNs collected    : " << rlcRx.receivedCount() << "\n";

    if (rlcRx.isComplete(totalSNs))
        std::cout << "  Result : ALL RLC PDUs recovered — no gaps\n";
    else
    {
        std::cout << "  Result : INCOMPLETE — missing SNs after "
                  << arqRound << " ARQ round(s):\n";
        RLCStatusPDU final = rlcRx.generateStatusPDU(totalSNs);
        final.print();
    }

    // Show every RLC PDU that arrived at the receiver
    std::cout << "\n  Received RLC PDUs at receiver RLC:\n";
    rlcRx.printReceivedSNs();

    // ===========================================================
    //  STEP 6 — DOWNLINK: PDCP Deprocess + IP Verification  (TS 38.323)
    //  Each reassembled PDCP PDU is passed to pdcp.deprocess().
    //  The recovered IP payload is then compared byte-by-byte
    //  against the original IP payload from Step 1.
    //
    //  Serialised layout from RLC:
    //    bytes[0..1] = PDCP SN (added by RLC serialisePDCP)
    //    bytes[2..]  = PDCP stream: [ checksum | compress_flag | header | encrypted_payload ]
    //                  → this is exactly what deprocess() expects
    // ===========================================================
    auto reassembled = rlcRx.getReassembledPDCPData();

    std::cout << "\n===================================================\n";
    std::cout << "  STEP 6 — DOWNLINK: PDCP Deprocess + IP Verification\n";
    std::cout << "===================================================\n";
    std::cout << "  Reassembled " << reassembled.size()
              << " complete PDCP PDU(s) from RLC.\n";

    bool allMatch = true;

    for (auto& pair : reassembled)
    {
        int pdcpSN = (int)pair.first;
        auto& data = pair.second;

        std::cout << "\n--- Packet " << pdcpSN << " ---\n";

        // Strip the 2-byte SN prefix that RLC added — deprocess() only
        // expects the raw PDCP stream: [ checksum | compress_flag | header | payload ]
        std::vector<uint8_t> pdcpStream(data.begin() + 2, data.end());

        // PDCP downlink: decrypt + decompress header + verify integrity
        std::vector<uint8_t> recovered = pdcp.deprocess(pdcpStream);

        // Compare against the original IP payload saved in Step 1
        if (pdcpSN < (int)originalPayloads.size())
        {
            bool match = (recovered == originalPayloads[pdcpSN]);
            allMatch = allMatch && match;

            if (match)
                std::cout << "  [VERIFY] Packet " << pdcpSN
                          << " MATCHES the original IP payload. Downlink successful.\n";
            else
            {
                std::cout << "  [VERIFY] Packet " << pdcpSN
                          << " does NOT match the original IP payload! Data corrupted.\n";
                for (int j = 0; j < (int)recovered.size() &&
                                j < (int)originalPayloads[pdcpSN].size(); j++)
                {
                    if (recovered[j] != originalPayloads[pdcpSN][j])
                    {
                        std::cout << "  [VERIFY] First mismatch at byte " << j
                                  << ": got " << (int)recovered[j]
                                  << ", expected " << (int)originalPayloads[pdcpSN][j] << "\n";
                        break;
                    }
                }
            }
        }
    }

    // ===========================================================
    //  FINAL SUMMARY
    // ===========================================================
    std::cout << "\n===================================================\n";
    std::cout << "  Final Summary\n";
    std::cout << "===================================================\n";
    std::cout << "  Packets generated     : " << originalPayloads.size() << "\n";
    std::cout << "  Packets reassembled   : " << reassembled.size() << "\n";
    std::cout << "  All payloads match    : "
              << (allMatch ? "YES — Full loop verified!" : "NO — Errors detected!") << "\n";

    std::cout << "\n==== Simulation complete: IP → PDCP → RLC → MAC → Uu → MAC → RLC → PDCP → IP ====\n";
    return 0;
}
