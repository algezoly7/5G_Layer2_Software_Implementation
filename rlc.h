#pragma once
#include <iostream>
#include <vector>
#include <deque>
#include <map>
#include <cstdint>
#include <algorithm>
#include "pdcp.h"

// ===================== WIRE-SIZE CONSTANTS =====================
// These mirror simplified 3GPP TS 38.322 overhead values.
// Every RLC data PDU on the wire  = RLC_HEADER_BYTES + payload bytes.
// Every MAC sub-header entry      = MAC_SUBHEADER_BYTES per RLC PDU.
//
// PDCP serialised size is now VARIABLE due to header compression (ROHC):
//   First PDU  (full IP header):  2(SN) + 1(checksum) + 22(full header) + 100(payload) = 125B
//   Other PDUs (compressed hdr):  2(SN) + 1(checksum) +  3(context ID)  + 100(payload) = 106B
//   PDCP_SERIAL_BYTES reflects the compressed (typical) case for reference only.
//   Actual sizes come from the real data — RLC uses sdu.data.size() not this constant.
const int RLC_HEADER_BYTES    = 6;   // sn(2) + pdcpSN(1) + segOffset(2) + flags(1)
const int MAC_SUBHEADER_BYTES = 3;   // lcid(1) + length(2)
const int PDCP_SERIAL_BYTES   = 106; // 2(SN) + 104(compressed PDCP stream) — typical case

// ===================== RLC HEADER =====================
// Prepended to every RLC data PDU — the "envelope" the receiver reads.
//
// Fields needed for two distinct jobs:
//   1. ARQ gap detection  →  sn (monotonic global counter)
//   2. PDCP reassembly    →  pdcpSN + segOffset + isFirstSeg + isLastSeg
//      When the receiver collects all segments of one PDCP PDU it sorts
//      them by segOffset and concatenates payloads to recover the original
//      serialised PDCP PDU intact.
//
// Reference: 3GPP TS 38.322 §6.2.2  (RLC Data PDU header format, AM mode)
struct RLCHeader
{
    uint16_t sn;          // Monotonically increasing; unique per RLC PDU sent
    uint8_t  pdcpSN;      // Which PDCP PDU (0-255) this segment came from
    uint16_t segOffset;   // Byte offset within that PDCP PDU's serialised data
    bool     isFirstSeg;  // True iff this is the first (or only) slice
    bool     isLastSeg;   // True iff this is the last  (or only) slice
    uint8_t  lcid;        // Logical Channel ID: 3 = DTCH (dedicated user traffic)

    void print() const
    {
        std::cout << "SN="      << sn
                  << " pSN="    << (int)pdcpSN
                  << " off="    << segOffset
                  << " F="      << isFirstSeg
                  << " L="      << isLastSeg
                  << " lcid="   << (int)lcid;
    }
};

// ===================== RLC DATA PDU =====================
// The unit handed between RLC and MAC (in both directions).
// wire size = RLC_HEADER_BYTES + payload.size()
struct RLCpdu
{
    RLCHeader            header;
    std::vector<uint8_t> payload; // Slice of a serialised PDCP PDU

    int wireSize() const { return RLC_HEADER_BYTES + (int)payload.size(); }

    void print() const
    {
        std::cout << "      [RLC-PDU] ";
        header.print();
        std::cout << "  payload=" << payload.size()
                  << "B  wire="   << wireSize() << "B\n";
    }
};

// ===================== RLC STATUS PDU =====================
// Sent by RECEIVER RLC → SENDER RLC as ARQ feedback when gaps are found.
// Travels the full reverse path:
//   Receiver-RLC → Receiver-MAC → air channel (Uu) → Sender-MAC → Sender-RLC
//
// ackSN   : cumulative ACK — all SNs strictly below this value are confirmed.
// nackSNs : selective NACKs — individual missing SNs at or above ackSN.
//
// Reference: 3GPP TS 38.322 §6.2.2.5 (AM STATUS PDU format)
struct RLCStatusPDU
{
    uint16_t              ackSN;
    std::vector<uint16_t> nackSNs;

    bool hasNACKs() const { return !nackSNs.empty(); }

    void print() const
    {
        std::cout << "      [STATUS] ackSN=" << ackSN;
        if (!nackSNs.empty())
        {
            std::cout << "  NACK=[";
            for (size_t i = 0; i < nackSNs.size(); ++i)
            {
                if (i) std::cout << ',';
                std::cout << nackSNs[i];
            }
            std::cout << "]";
        }
        else
        {
            std::cout << "  (no NACKs — all SNs below " << ackSN << " confirmed)";
        }
        std::cout << "\n";
    }
};

// ████████████████████████████████████████████████████████████████████████
//  RLC SENDER
// ████████████████████████████████████████████████████████████████████████
// Sender-side RLC.  Holds PDCP PDUs in an input queue, provides data to
// MAC on demand (segmenting or concatenating to fit the MAC grant exactly),
// and maintains a retransmission buffer so ARQ can recover lost PDUs.
//
// Key design: RLC never decides when to send — MAC calls getDataForMAC()
// with a grant size and RLC fills it.  This mirrors the real 3GPP 38-series spec.
//
// Reference: 3GPP TS 38.322 §5  (RLC AM entity procedures)

class RLCSender
{
private:
    // ── Input queue ──────────────────────────────────────────────────────
    // Each entry is a serialised PDCP PDU still waiting to be segmented.
    // `offset` tracks how many bytes of the PDU have already been given
    // to MAC so we can resume mid-PDU on the next call.
    struct PendingSDU
    {
        uint8_t              pdcpSN;
        std::vector<uint8_t> data;   // variable bytes: 2B SN + PDCP stream (checksum+header+payload)
        int                  offset; // Bytes already handed to MAC
    };
    std::deque<PendingSDU>     pdcpQueue;

    // ── Retransmission buffer ─────────────────────────────────────────────
    // Every RLC PDU ever handed to MAC is stored here indexed by SN.
    // An entry is removed only when receiver ACKs it via STATUS PDU.
    // This lets ARQ re-send any PDU that got permanently lost.
    std::map<uint16_t, RLCpdu> retxBuf;

    uint16_t nextSN = 0;  // Monotonically increasing global SN
    uint8_t  lcid   = 3;  // DTCH: dedicated traffic (DRB — user data)
                          // LCID=3 per 3GPP TS 38.321 Table 6.2.1-1

    // Serialise one PDCP PDU to a flat byte vector for RLC to slice.
    //
    // Our PDCP now embeds the checksum AND the compressed header inside
    // getEncryptedPayload(), so the layout is:
    //   [ SN_hi | SN_lo | checksum | compress_flag | header_bytes | encrypted_payload ]
    //
    // We only prepend the 2-byte SN here — everything else is already in
    // getEncryptedPayload(). DO NOT push getChecksum() separately; it is
    // already the first byte of getEncryptedPayload() and would be duplicated.
    static std::vector<uint8_t> serialisePDCP(PDCPpdu pdu)
    {
        std::vector<uint8_t> out;
        int sn = pdu.getSequenceNumber();
        out.push_back((sn >> 8) & 0xFF);   // SN high byte
        out.push_back( sn       & 0xFF);   // SN low  byte
        // getEncryptedPayload() already contains:
        //   [ checksum | compress_flag | header | encrypted_payload ]
        auto ep = pdu.getEncryptedPayload();
        out.insert(out.end(), ep.begin(), ep.end());
        return out;
    }

public:
    // Add a PDCP PDU to the sender's input queue.
    void loadPDU(PDCPpdu pdu)
    {
        pdcpQueue.push_back({ (uint8_t)pdu.getSequenceNumber(),
                               serialisePDCP(pdu), 0 });
    }

    bool hasPendingData() const { return !pdcpQueue.empty(); }
    int  pendingCount()   const { return (int)pdcpQueue.size(); }
    int  nextSNValue()    const { return (int)nextSN; }
    int  retxBufSize()    const { return (int)retxBuf.size(); }

    // ── getDataForMAC ─────────────────────────────────────────────────────
    // Called by MAC with a byte grant for the next Transport Block.
    // Returns a list of RLC PDUs whose total wire bytes (including RLC
    // headers and the MAC sub-header overhead per PDU) fit within `grant`.
    //
    // Segmentation:  if a PDCP PDU is larger than the available space,
    //                only a slice is taken; the remainder stays in the queue.
    // Concatenation: if space remains after one PDCP PDU is fully consumed,
    //                the loop continues to pack the next PDU into the same TB.
    //
    // All returned PDUs are also stored in retxBuf for ARQ retransmission.
    //
    // Reference: 3GPP TS 38.322 §5.2.2.1 (Segmentation) / §5.2.2.2 (Concatenation)
    std::vector<RLCpdu> getDataForMAC(int grant)
    {
        std::vector<RLCpdu> result;
        int remaining = grant;
        const int minOverhead = MAC_SUBHEADER_BYTES + RLC_HEADER_BYTES; // 9 bytes

        while (remaining > minOverhead && !pdcpQueue.empty())
        {
            PendingSDU& sdu = pdcpQueue.front();
            int available   = remaining - minOverhead; // bytes left for payload
            int leftInSDU   = (int)sdu.data.size() - sdu.offset;
            int take        = std::min(available, leftInSDU);
            if (take <= 0) break;

            // Slice the correct bytes from the serialised PDCP PDU
            std::vector<uint8_t> piece(
                sdu.data.begin() + sdu.offset,
                sdu.data.begin() + sdu.offset + take);

            RLCHeader hdr;
            hdr.sn         = nextSN;
            hdr.pdcpSN     = sdu.pdcpSN;
            hdr.segOffset  = (uint16_t)sdu.offset;
            hdr.isFirstSeg = (sdu.offset == 0);
            hdr.isLastSeg  = (sdu.offset + take >= (int)sdu.data.size());
            hdr.lcid       = lcid;

            RLCpdu pdu;
            pdu.header  = hdr;
            pdu.payload = piece;

            retxBuf[nextSN] = pdu;   // Keep for possible ARQ retransmission
            ++nextSN;

            result.push_back(pdu);

            sdu.offset += take;
            remaining  -= (minOverhead + take);

            if (hdr.isLastSeg) pdcpQueue.pop_front(); // SDU fully consumed
        }
        return result;
    }

    // ── handleStatusPDU ───────────────────────────────────────────────────
    // Called when a STATUS PDU from the receiver arrives.
    //   • Removes all SNs below ackSN from retxBuf (cumulative ACK).
    //   • Returns a copy of every NACKed PDU for immediate retransmission.
    //     (NACKed PDUs stay in retxBuf — they may need yet another retx.)
    //
    // Reference: 3GPP TS 38.322 §5.3.3 (ARQ retransmission procedure)
    std::vector<RLCpdu> handleStatusPDU(const RLCStatusPDU& status)
    {
        // Purge cumulatively acknowledged PDUs
        for (auto it = retxBuf.begin();
             it != retxBuf.end() && it->first < status.ackSN; )
            it = retxBuf.erase(it);

        // Collect NACKed PDUs for retransmission
        std::vector<RLCpdu> retx;
        for (uint16_t sn : status.nackSNs)
        {
            auto it = retxBuf.find(sn);
            if (it != retxBuf.end())
                retx.push_back(it->second);
            else
                std::cout << "      [RLC-TX] WARN: NACK for SN=" << sn
                          << " not in retxBuf (already ACKed?)\n";
        }
        return retx;
    }
};

// ████████████████████████████████████████████████████████████████████████
//  RLC RECEIVER
// ████████████████████████████████████████████████████████████████████████
// Receiver-side RLC.  Accepts RLC PDUs from receiver MAC, tracks gaps,
// and generates STATUS PDUs for ARQ feedback.
//
// Also provides PDCP reassembly for the receiver PDCP layer:
// once all segments of a PDCP PDU are collected, they can be sorted by
// segOffset and concatenated to recover the original serialised PDU.
//
// Reference: 3GPP TS 38.322 §5.2.3 (Reassembly) / §5.3.4 (STATUS triggering)

class RLCReceiver
{
private:
    std::map<uint16_t, RLCpdu> rxBuf; // SN → received PDU

public:
    // Accept a batch of RLC PDUs from receiver MAC.
    // Duplicates (same SN arriving twice, e.g. after HARQ retransmission
    // that was already delivered) are detected and silently dropped.
    void receive(const std::vector<RLCpdu>& pdus)
    {
        for (const auto& pdu : pdus)
        {
            uint16_t sn = pdu.header.sn;
            if (rxBuf.count(sn))
                std::cout << "      [RLC-RX] Duplicate SN=" << sn << " — discarded\n";
            else
            {
                rxBuf[sn] = pdu;
                std::cout << "      [RLC-RX] Stored: ";
                pdu.print();
            }
        }
    }

    int  receivedCount() const { return (int)rxBuf.size(); }

    // True if any SN in [0, totalSNs) has not yet arrived.
    bool hasGaps(uint16_t totalSNs) const
    {
        for (uint16_t sn = 0; sn < totalSNs; ++sn)
            if (!rxBuf.count(sn)) return true;
        return false;
    }

    bool isComplete(uint16_t totalSNs) const { return !hasGaps(totalSNs); }

    // Build a STATUS PDU describing exactly what is missing in [0, totalSNs).
    //   ackSN   = first gap (all SNs below this are contiguously received)
    //   nackSNs = every individual missing SN from ackSN up to totalSNs-1
    RLCStatusPDU generateStatusPDU(uint16_t totalSNs) const
    {
        RLCStatusPDU s;
        s.ackSN = 0;
        for (uint16_t sn = 0; sn < totalSNs; ++sn)
        {
            if (!rxBuf.count(sn)) break;
            s.ackSN = sn + 1;
        }
        for (uint16_t sn = s.ackSN; sn < totalSNs; ++sn)
            if (!rxBuf.count(sn)) s.nackSNs.push_back(sn);
        return s;
    }

    void printReceivedSNs() const
    {
        if (rxBuf.empty()) { std::cout << "      (none)\n"; return; }
        // FIXED: Using standard map iterator pair.second instead of structured binding
        for (auto& pair : rxBuf) pair.second.print();
    }

    // ── PDCP reassembly ───────────────────────────────────────────────────
    // Groups RLC PDUs by pdcpSN.  For each group, verifies that segments
    // are contiguous (correct offsets, first+last flags present), then
    // concatenates payloads to recover the original serialised PDCP PDU.
    // Returns only complete, contiguous PDCP PDUs.
    // The caller (receiver PDCP) will parse:
    //   bytes[0..1] = original PDCP SN
    //   bytes[2]    = original integrity checksum
    //   bytes[3..]  = encrypted payload to decrypt and verify
    //
    // Reference: 3GPP TS 38.322 §5.2.3 (RLC SDU reassembly)
    std::map<uint8_t, std::vector<uint8_t>> getReassembledPDCPData() const
    {
        // Group by pdcpSN
        std::map<uint8_t, std::vector<const RLCpdu*>> groups;
        // FIXED: Removed structured binding for C++11/C++14 compatibility
        for (auto& pair : rxBuf)
            groups[pair.second.header.pdcpSN].push_back(&pair.second);

        std::map<uint8_t, std::vector<uint8_t>> result;
        // FIXED: Removed structured binding
        for (auto& pair : groups)
        {
            uint8_t pdcpSN = pair.first;
            auto& segs = pair.second;

            // Sort segments by their byte offset within the original PDCP PDU
            auto sorted = segs;
            std::sort(sorted.begin(), sorted.end(),
                [](const RLCpdu* a, const RLCpdu* b){
                    return a->header.segOffset < b->header.segOffset;
                });

            // Must start at offset 0
            if (!sorted.front()->header.isFirstSeg)   continue;
            // Must have a last-segment marker
            if (!sorted.back()->header.isLastSeg)     continue;

            // Every segment must begin exactly where the previous one ended
            bool contiguous = true;
            int  expected   = 0;
            for (auto* seg : sorted)
            {
                if ((int)seg->header.segOffset != expected)
                { contiguous = false; break; }
                expected += (int)seg->payload.size();
            }
            if (!contiguous) continue;

            // Assemble the full PDCP SDU
            std::vector<uint8_t> assembled;
            for (auto* seg : sorted)
                assembled.insert(assembled.end(),
                                 seg->payload.begin(), seg->payload.end());
            result[pdcpSN] = assembled;
        }
        return result;
    }
};
