#pragma once
#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include "rlc.h"
#include "channel.h"

// ===================== CHANNEL TYPE ENUMS =====================
// 5G NR logical and transport channel names per 3GPP TS 38.300 
enum class LogicalChannelType   { BCCH, PCCH, CCCH, DCCH, DTCH };
enum class TransportChannelType { DL_SCH, UL_SCH, BCH, PCH, RACH };
enum class Direction            { UPLINK, DOWNLINK };

static std::string logicalChName(LogicalChannelType lc)
{
    switch (lc) {
        case LogicalChannelType::BCCH: return "BCCH";
        case LogicalChannelType::PCCH: return "PCCH";
        case LogicalChannelType::CCCH: return "CCCH";
        case LogicalChannelType::DCCH: return "DCCH";
        case LogicalChannelType::DTCH: return "DTCH";
    }
    return "?";
}
static std::string transportChName(TransportChannelType tc)
{
    switch (tc) {
        case TransportChannelType::DL_SCH: return "DL-SCH";
        case TransportChannelType::UL_SCH: return "UL-SCH";
        case TransportChannelType::BCH:    return "BCH";
        case TransportChannelType::PCH:    return "PCH";
        case TransportChannelType::RACH:   return "RACH";
    }
    return "?";
}

// ===================== MAC SUB-HEADER =====================
// One sub-header entry per RLC PDU inside a Transport Block.
// The MAC receiver reads the full set of sub-headers first to know
// exactly where each RLC PDU starts and how long it is — this is
// what makes demultiplexing deterministic without any guessing.
//
// Wire layout (3GPP TS 38.321 §6.1.2):
//   [SubHdr0][SubHdr1]...[SubHdrN-1][RLC-PDU-0][RLC-PDU-1]...[RLC-PDU-N-1]
struct MACSubHeader
{
    uint8_t  lcid;    // Logical channel this RLC PDU belongs to
    uint16_t length;  // Total wire size of the RLC PDU that follows (bytes)
    static const int WIRE_SIZE = 3;

    void print() const
    {
        std::cout << "lcid=" << (int)lcid << " len=" << length << "B";
    }
};

// ===================== TRANSPORT BLOCK =====================
// The unit MAC hands to the Physical Layer (NR Uu air interface).
// A TB is the complete package: MAC header (sub-headers) + all RLC PDUs.
//
// Reference: 3GPP TS 38.321  (MAC PDU structure)
//
// Two important flags:
//   corrupted         — set by the air channel (30% probability); if true
//                       the receiver MAC must NACK it via HARQ.
//   receiverDelivered — set once the receiver actually gets a clean copy;
//                       stays true even if the ACK feedback is later lost.
//                       Determines whether receiver RLC gets the RLC PDUs.
struct TransportBlock
{
    int                       tbID;
    int                       grantSize;           // MAC scheduler grant in bytes
    std::vector<MACSubHeader> subHeaders;          // One per RLC PDU
    std::vector<RLCpdu>       rlcPDUs;
    bool                      corrupted         = false;
    int                       harqRound         = 0;
    bool                      receiverDelivered = false;
    bool                      isRetransmission  = false;

    int usedBytes() const
    {
        int t = 0;
        for (size_t i = 0; i < subHeaders.size(); ++i) t += MACSubHeader::WIRE_SIZE;
        for (auto& p  : rlcPDUs)   t += p.wireSize();
        return t;
    }

    void print() const
    {
        std::cout << "  [TB #" << tbID
                  << "]  grant=" << grantSize << "B"
                  << "  used="   << usedBytes() << "B"
                  << "  rlcPDUs=" << rlcPDUs.size()
                  << (isRetransmission ? "  [RETX]" : "") << "\n";
        std::cout << "    MAC sub-headers:\n";
        for (int i = 0; i < (int)subHeaders.size(); ++i)
        {
            std::cout << "      [" << i << "] ";
            subHeaders[i].print();
            std::cout << "\n";
        }
        std::cout << "    RLC PDUs inside this TB:\n";
        for (auto& p : rlcPDUs) p.print();
    }
};

// ===================== HARQ RESULT =====================
// Returned by transmitWithHARQ() to the caller (main.cpp).
//
//   receiverDelivered — receiver (gNB) got a clean copy of the TB
//                       → caller should pass RLC PDUs up to receiver RLC.
//   senderConfirmed   — sender (UE) received an explicit ACK
//                       → from sender's perspective HARQ succeeded.
//
// These two can differ:
//   • receiverDelivered=true + senderConfirmed=false means the TB arrived
//     but every ACK was lost.  Receiver already has the data; RLC ARQ
//     STATUS PDU will NOT list those SNs as missing, so no wasted retransmission.
//   • receiverDelivered=false + senderConfirmed=false means the TB truly
//     never reached the receiver → RLC ARQ MUST retransmit.
//
// Reference: 3GPP TS 38.321 §5.4 (HARQ procedure)
struct HARQResult
{
    bool receiverDelivered;
    bool senderConfirmed;
    int  attempts;
};

//  MAC SENDER
// Handles the sender side of MAC.
//
// buildTransportBlock() — creates a properly-structured TB from RLC PDUs,
//   adding one MAC sub-header per PDU so the receiver can demultiplex.
//
// transmitWithHARQ()    — runs the full HARQ state machine:
//   Forward path  (TB):        UE → gNB through air channel (30% loss)
//   Feedback path (ACK/NACK):  gNB → UE through air channel (30% loss)
//   Up to 4 attempts per TB.
//
// HARQ model detail:
//   Once the receiver physically obtains the TB (receiverHasTB=true),
//   it never loses it again — it just keeps resending the ACK each round.
//   This means we never send duplicate payload data to receiver RLC even
//   if the ACK keeps getting lost.  Compare with RLC ARQ which retransmits
//   entirely new RLC PDUs if HARQ gives up without an ACK.
//
// Reference: 3GPP TS 38.321 §5.4.2.1 (HARQ operation for UL-SCH)

class MACSender
{
private:
    Direction direction;
    int       maxHARQ = 4;

    static TransportChannelType mapChannel(LogicalChannelType lc, Direction dir)
    {
        switch (lc)
        {
            case LogicalChannelType::DTCH:
            case LogicalChannelType::DCCH:
            case LogicalChannelType::CCCH:
                return (dir == Direction::UPLINK)
                    ? TransportChannelType::UL_SCH
                    : TransportChannelType::DL_SCH;
            case LogicalChannelType::BCCH: return TransportChannelType::BCH;
            case LogicalChannelType::PCCH: return TransportChannelType::PCH;
        }
        return TransportChannelType::DL_SCH;
    }

public:
    explicit MACSender(Direction d) : direction(d) {}

    // ── buildTransportBlock ──────────────────────────────────────────────
    // Assembles the TB structure: computes sub-headers (lcid + wireSize for
    // each RLC PDU) and stores everything together in the TB.
    // The sub-headers are what allow the receiver to demultiplex the TB
    // back into individual RLC PDUs without ambiguity.
    //
    // Reference: 3GPP TS 38.321 §6.1.2 (MAC PDU for UL-SCH/DL-SCH)
    TransportBlock buildTransportBlock(int tbID, int grant,
                                       const std::vector<RLCpdu>& pdus,
                                       bool retx = false)
    {
        TransportBlock tb;
        tb.tbID             = tbID;
        tb.grantSize        = grant;
        tb.rlcPDUs          = pdus;
        tb.isRetransmission = retx;

        for (auto& pdu : pdus)
        {
            MACSubHeader sh;
            sh.lcid   = pdu.header.lcid;
            sh.length = (uint16_t)pdu.wireSize(); // Receiver uses this to extract PDU
            tb.subHeaders.push_back(sh);
        }

        // Show channel mapping for first PDU (all PDUs are DTCH/DRB here)
        if (!pdus.empty())
        {
            std::cout << "  [MAC-TX] Channel map: "
                      << logicalChName(LogicalChannelType::DTCH)
                      << " (logical) → "
                      << transportChName(mapChannel(LogicalChannelType::DTCH, direction))
                      << " (transport)\n";
        }
        return tb;
    }

    // ── transmitWithHARQ ─────────────────────────────────────────────────
    // HARQ state machine for one Transport Block.
    //
    // Each round:
    //   1. If receiver doesn't have TB yet: send TB through air (30% loss).
    //   2. If receiver now has TB: send ACK through air (30% loss).
    //        → ACK arrives at sender: HARQ success, done.
    //        → ACK lost: sender has no ACK, will retry (receiver keeps TB,
    //                    will just resend ACK next round — no duplicate data).
    //   3. If receiver still doesn't have TB: send NACK (30% loss, but
    //      sender retransmits regardless — synchronous HARQ behaviour).
    //
    // Reference: 3GPP TS 38.321 §5.4.2.1 / 3GPP TS 38.213 §9 (HARQ feedback)
    HARQResult transmitWithHARQ(TransportBlock& tb)
    {
        HARQResult res{ false, false, 0 };
        bool       receiverHasTB = false;
        std::string tag = "TB#" + std::to_string(tb.tbID);

        std::cout << "    [HARQ] Transmitting " << tag
                  << " (" << tb.usedBytes() << "B"
                  << ", " << tb.rlcPDUs.size() << " RLC PDU"
                  << (tb.rlcPDUs.size() == 1 ? "" : "s") << ")\n";

        for (int attempt = 1; attempt <= maxHARQ; ++attempt)
        {
            tb.harqRound = attempt;
            res.attempts = attempt;
            std::cout << "    [HARQ] Round " << attempt << "/" << maxHARQ << ":\n";

            // ── Forward path: TB travelling sender → receiver ──────────
            if (!receiverHasTB)
            {
                bool arrived = airTransmit(tag + " (attempt " +
                                           std::to_string(attempt) + ")");
                receiverHasTB = arrived;
                if (!arrived) tb.corrupted = true;
                else          tb.corrupted = false;
            }
            else
            {
                // Receiver already has TB — no need to re-send data.
                // This happens when TB arrived but ACK got lost on a previous round.
                std::cout << "        [AIR] " << tag
                          << " already at receiver — resending ACK only\n";
            }

            // ── Feedback path: ACK or NACK travelling receiver → sender ──
            if (receiverHasTB)
            {
                // Receiver sends ACK — also travels through lossy Uu channel
                bool ackArrived = airTransmit(tag + " HARQ-ACK");
                if (ackArrived)
                {
                    res.senderConfirmed   = true;
                    res.receiverDelivered = true;
                    tb.receiverDelivered  = true;
                    std::cout << "    [HARQ] ACK confirmed on attempt " << attempt
                              << " — TB delivered\n";
                    return res;
                }
                std::cout << "    [HARQ] ACK lost — sender will retry"
                             " (receiver already has the data)\n";
            }
            else
            {
                // Receiver sends NACK — NACK itself may be lost (30%)
                bool nackArrived = airTransmit(tag + " HARQ-NACK");
                if (nackArrived)
                    std::cout << "    [HARQ] NACK received — retransmitting TB\n";
                else
                    std::cout << "    [HARQ] NACK also lost — retransmitting anyway"
                                 " (synchronous HARQ: silence = NACK)\n";
            }
        }

        // All HARQ rounds exhausted
        res.receiverDelivered = receiverHasTB;
        tb.receiverDelivered  = receiverHasTB;

        if (receiverHasTB)
            std::cout << "    [HARQ] " << maxHARQ << " rounds done — receiver HAS "
                      << tag << " but ACK never confirmed.\n"
                         "             Receiver RLC will NOT NACK those SNs.\n";
        else
            std::cout << "    [HARQ] FAILED — " << tag << " never reached receiver"
                         " after " << maxHARQ << " rounds.\n"
                         "             RLC ARQ REQUIRED to recover lost SNs.\n";

        return res;
    }
};

//  MAC RECEIVER
// Receiver-side MAC.  One job: demultiplex a received Transport Block
// back into the individual RLC PDUs it was carrying.
//
// Uses the MAC sub-headers to read LCID and length for each PDU, then
// validates the sizes match before handing the PDUs up to receiver RLC.
//
// Reference: 3GPP TS 38.321 §6.1.2 / §5.2 (MAC PDU assembly/disassembly)
class MACReceiver
{
public:
    // Parse the Transport Block using its sub-headers and return the RLC PDUs.
    std::vector<RLCpdu> extractRLCPDUs(const TransportBlock& tb) const
    {
        std::cout << "    [MAC-RX] Demultiplexing TB#" << tb.tbID
                  << " — " << tb.subHeaders.size() << " sub-header(s):\n";

        std::vector<RLCpdu> out;
        for (int i = 0; i < (int)tb.rlcPDUs.size(); ++i)
        {
            // Sub-header length must match the actual RLC PDU wire size
            uint16_t expected = (uint16_t)tb.rlcPDUs[i].wireSize();
            if (tb.subHeaders[i].length != expected)
                std::cout << "    [MAC-RX] WARNING: sub-header length mismatch"
                          << " at [" << i << "]\n";

            std::cout << "      sub-header[" << i << "]: ";
            tb.subHeaders[i].print();
            std::cout << " → valid\n";
            out.push_back(tb.rlcPDUs[i]);
        }
        std::cout << "    [MAC-RX] Passed " << out.size()
                  << " RLC PDU(s) up to RLC receiver\n";
        return out;
    }
};
