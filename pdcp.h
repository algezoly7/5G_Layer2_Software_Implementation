#pragma once
#include <iostream>
#include <vector>
#include <map>
#include <cstdint>
#include <cstdio>
#include <string>
#include "ip_generator.h"

// ===================== PDCP PDU =====================
// The output unit of the PDCP layer — one per IP packet processed.
// Handed downward to RLC for segmentation into RLC PDUs.
//
// Internal layout of encryptedPayload (what RLC sees):
//   [ checksum(1) | compressed_header | encrypted_IP_payload ]
//
// Reference: 3GPP TS 38.323 §6.2.2 (PDCP Data PDU format)

class PDCPpdu
{
private:
    int sequenceNumber;
    std::vector<uint8_t> encryptedPayload;
    uint8_t checksum;

public:
    PDCPpdu(int sn, std::vector<uint8_t> payload, uint8_t cs)
    {
        sequenceNumber = sn;
        encryptedPayload = payload;
        checksum = cs;
    }

    int getSequenceNumber() const { return sequenceNumber; }
    std::vector<uint8_t> getEncryptedPayload() const { return encryptedPayload; }
    uint8_t getChecksum() const { return checksum; }

    void print()
    {
        std::cout << "  SN: " << sequenceNumber
                  << " | Checksum: " << (int)checksum
                  << " | Encrypted payload (first 4 bytes): ";
        for (int i = 0; i < 4 && i < (int)encryptedPayload.size(); i++)
            printf("%02X ", encryptedPayload[i]);
        std::cout << "\n";
    }
};

// ===================== PDCP LAYER =====================
// Implements the three core PDCP functions for a single DRB (Data Radio Bearer):
//
//   1. Header Compression  — ROHC (Robust Header Compression) simulation
//      First packet of each IP flow carries the full IP header; subsequent
//      packets carry only a 2-byte context ID, saving ~20 bytes per packet.
//      Reference: 3GPP TS 38.323 §5.7.4 / RFC 3095 (ROHC RTP/UDP/IP)
//
//   2. Integrity Protection — 8-bit checksum over the original IP payload.
//      Simulates the MAC-I field computed by PDCP before ciphering.
//      Reference: 3GPP TS 38.323 §5.9 (Integrity protection)
//
//   3. Ciphering — XOR with key 0xAB applied to every payload byte.
//      Models the AES-128-EEA2 (or NEA2) stream cipher used in 5G NR.
//      Reference: 3GPP TS 38.323 §5.8 (Ciphering) / TS 33.501 §5.3.1.3

class PDCPLayer
{
private:
    uint8_t xorKey;
    int sequenceNumber;
    std::vector<PDCPpdu> pdus;

    // --- Compressor context table (uplink / transmitter side) ---
    // Built by the transmitter as it sends packets.
    // Maps context ID → { srcIP, dstIP }
    // Reference: 3GPP TS 38.323 §5.7.4 — ROHC compressor state machine
    std::map<uint16_t, std::pair<std::string, std::string>> compressorTable;
    uint16_t nextCompressorID = 0;

    // --- Decompressor context table (downlink / receiver side) ---
    // Built independently by the receiver as full headers arrive.
    // Maps context ID → { srcIP, dstIP }
    // Starts empty — populated only when a full header (flag=0x00) is received.
    // Reference: 3GPP TS 38.323 §5.7.4 — ROHC decompressor state machine
    std::map<uint16_t, std::pair<std::string, std::string>> decompressorTable;
    uint16_t nextDecompressorID = 0;

    // --- Ciphering / Deciphering ---
    // Models NEA2 (AES-128-CTR equivalent) via XOR with a fixed key.
    // In real NR, inputs include COUNT, BEARER, DIRECTION, LENGTH.
    // Reference: 3GPP TS 38.323 §5.8 / TS 33.501 Annex D
    std::vector<uint8_t> encrypt(std::vector<uint8_t> payload)
    {
        std::vector<uint8_t> encrypted(payload.size());
        for (int i = 0; i < (int)payload.size(); i++)
            encrypted[i] = payload[i] ^ xorKey;
        return encrypted;
    }

    std::vector<uint8_t> decrypt(std::vector<uint8_t> payload)
    {
        return encrypt(payload); // XOR is its own inverse
    }

    // --- Integrity Protection ---
    // Simulates NIA2 (AES-128-CMAC equivalent) as an 8-bit sum.
    // Applied over the plaintext payload before ciphering (uplink).
    // Verified after deciphering (downlink).
    // Reference: 3GPP TS 38.323 §5.9 / TS 33.501 §5.3.1.4
    uint8_t computeChecksum(std::vector<uint8_t> payload)
    {
        uint8_t sum = 0;
        for (int i = 0; i < (int)payload.size(); i++)
            sum += payload[i];
        return sum;
    }

    // --- Search the compressor table for a known IP flow ---
    // Returns the context ID if found, -1 if not.
    int findCompressorID(const std::string &src, const std::string &dst)
    {
        for (const auto &kv : compressorTable)
            if (kv.second.first == src && kv.second.second == dst)
                return kv.first;
        return -1;
    }

    // --- Header Compression (uplink / transmitter) ---
    // Uses compressorTable only — decompressorTable is never touched here.
    //
    // Output when IP flow is new (Initialisation and Refresh — IR state):
    //   [ 0x00 | src_len | src_bytes | dst_len | dst_bytes ]
    //
    // Output when IP flow is known (Compressed — CO state):
    //   [ 0x01 | context_id_high | context_id_low ]
    //
    // Reference: 3GPP TS 38.323 §5.7.4 / RFC 3095 §5.3 (ROHC IR / CO packets)
    std::vector<uint8_t> compressHeader(const std::string &src, const std::string &dst)
    {
        std::vector<uint8_t> header;
        int ctxID = findCompressorID(src, dst);

        if (ctxID == -1)
        {
            // New IP flow — register in compressor table and send full header (IR packet)
            uint16_t newID = nextCompressorID++;
            compressorTable[newID] = {src, dst};

            header.push_back(0x00); // flag: full header (IR state) follows
            header.push_back((uint8_t)src.size());
            for (char c : src)
                header.push_back((uint8_t)c);
            header.push_back((uint8_t)dst.size());
            for (char c : dst)
                header.push_back((uint8_t)c);

            std::cout << "  [ROHC TX] New IP flow — full IR header sent."
                      << " Compressor context ID=" << newID << "\n";
            std::cout << "  [ROHC TX] Header size: " << header.size() << " bytes\n";
        }
        else
        {
            // Known IP flow — send context ID instead of full IPs (CO packet)
            header.push_back(0x01); // flag: context ID (CO state) follows
            header.push_back((uint8_t)(ctxID >> 8));
            header.push_back((uint8_t)(ctxID & 0xFF));

            int originalSize = src.size() + dst.size() + 2;
            int compressedSize = 3;
            std::cout << "  [ROHC TX] Known IP flow — CO packet, compressor context ID=" << ctxID
                      << ". Saved " << (originalSize - compressedSize) << " bytes.\n";
        }

        return header;
    }

    // --- Header Decompression (downlink / receiver) ---
    // Uses decompressorTable only — compressorTable is never touched here.
    // The decompressor table is built independently from scratch, populated
    // only when full IR headers (flag=0x00) arrive through the data stream.
    //
    // Returns the updated byte offset after consuming the header fields.
    // Reference: 3GPP TS 38.323 §5.7.4 / RFC 3095 §5.3 (ROHC decompressor)
    int decompressHeader(const std::vector<uint8_t> &stream, int offset,
                         std::string &srcOut, std::string &dstOut)
    {
        uint8_t flag = stream[offset++];

        if (flag == 0x00)
        {
            // Full IR header — read IPs and register in decompressor table
            uint8_t srcLen = stream[offset++];
            srcOut = std::string(stream.begin() + offset, stream.begin() + offset + srcLen);
            offset += srcLen;

            uint8_t dstLen = stream[offset++];
            dstOut = std::string(stream.begin() + offset, stream.begin() + offset + dstLen);
            offset += dstLen;

            // Register independently in the decompressor table
            uint16_t newID = nextDecompressorID++;
            decompressorTable[newID] = {srcOut, dstOut};

            std::cout << "  [ROHC RX] Full IR header received."
                      << " Decompressor context ID=" << newID
                      << " (" << srcOut << " -> " << dstOut << ")\n";
        }
        else // flag == 0x01 — CO (Compressed) packet
        {
            // Compressed — read context ID and look up in decompressor table
            uint16_t ctxID = ((uint16_t)stream[offset] << 8) | stream[offset + 1];
            offset += 2;

            if (decompressorTable.count(ctxID))
            {
                srcOut = decompressorTable[ctxID].first;
                dstOut = decompressorTable[ctxID].second;
                std::cout << "  [ROHC RX] CO packet."
                          << " Decompressor context ID=" << ctxID
                          << " resolved to (" << srcOut << " -> " << dstOut << ")\n";
            }
            else
            {
                std::cout << "  [ROHC RX] ERROR: Decompressor context ID=" << ctxID
                          << " not found! Cannot decompress.\n";
            }
        }

        return offset;
    }

public:
    PDCPLayer(uint8_t key) : xorKey(key), sequenceNumber(0) {}

    // ===================== UPLINK (Transmitter) =====================
    // Processing order per 3GPP TS 38.323 §5.1.1:
    //   1. Header compression  (ROHC — compressor side)
    //   2. Integrity protection (compute MAC-I / checksum over plaintext)
    //   3. Ciphering            (encrypt payload)
    //
    // Full byte stream handed down to RLC:
    //   [ checksum(1) | compressed_header | encrypted_payload ]
    //
    PDCPpdu process(IPPacket packet)
    {
        std::cout << "Processing packet SN " << sequenceNumber << ":\n";

        // Step 1: Header compression — uses compressorTable only
        std::vector<uint8_t> header = compressHeader(packet.getSrcIP(), packet.getDstIP());

        // Step 2: Compute integrity checksum on original plaintext payload
        uint8_t checksum = computeChecksum(packet.getPayload());
        std::cout << "  Integrity checksum (NIA2-sim): " << (int)checksum << "\n";

        // Step 3: Cipher the payload (NEA2-sim: XOR with key 0xAB)
        std::vector<uint8_t> encrypted = encrypt(packet.getPayload());
        std::cout << "  Ciphering done (NEA2-sim, XOR key: 0x" << std::hex << (int)xorKey << std::dec << ")\n";

        // Step 4: Assemble stream: [ checksum | compressed_header | encrypted_payload ]
        std::vector<uint8_t> rlcPayload;
        rlcPayload.push_back(checksum);
        rlcPayload.insert(rlcPayload.end(), header.begin(), header.end());
        rlcPayload.insert(rlcPayload.end(), encrypted.begin(), encrypted.end());

        std::cout << "  Total bytes to RLC: " << rlcPayload.size()
                  << " (1 checksum + " << header.size() << " header + "
                  << encrypted.size() << " payload)\n";

        PDCPpdu pdu(sequenceNumber, rlcPayload, checksum);
        pdus.push_back(pdu);
        sequenceNumber++;

        return pdu;
    }

    // ===================== DOWNLINK (Receiver) =====================
    // Processing order per 3GPP TS 38.323 §5.1.2 (reverse of uplink):
    //   1. Deciphering          (decrypt payload)
    //   2. Header decompression (ROHC — decompressor side)
    //   3. Integrity verification (verify MAC-I / checksum over plaintext)
    //
    // Takes only the raw bytes reassembled by RLC — self-contained,
    // no uplink PDU object needed.
    // Uses decompressorTable only — built independently from the stream.
    //
    std::vector<uint8_t> deprocess(const std::vector<uint8_t> &incomingBytes)
    {
        int offset = 0;

        // Step 1: Extract checksum (MAC-I) from byte 0
        uint8_t receivedChecksum = incomingBytes[offset++];
        std::cout << "  [PDCP DL] Extracted MAC-I (checksum): " << (int)receivedChecksum << "\n";

        // Step 2: Decompress header — uses decompressorTable only
        std::string srcIP, dstIP;
        offset = decompressHeader(incomingBytes, offset, srcIP, dstIP);

        // Step 3: Decipher the remaining bytes (NEA2-sim: XOR)
        std::vector<uint8_t> encryptedPayload(incomingBytes.begin() + offset, incomingBytes.end());
        std::vector<uint8_t> decrypted = decrypt(encryptedPayload);
        std::cout << "  [PDCP DL] Deciphering done (NEA2-sim).\n";

        // Step 4: Verify integrity (NIA2-sim)
        uint8_t recalculated = computeChecksum(decrypted);
        if (recalculated == receivedChecksum)
            std::cout << "  [PDCP DL] Integrity check PASSED (NIA2-sim, checksum=" << (int)recalculated << ")\n";
        else
            std::cout << "  [PDCP DL] Integrity check FAILED — data may be corrupted!\n";

        return decrypted;
    }

    // ===================== HELPERS =====================

    bool verify(PDCPpdu pdu)
    {
        // blob layout: [ checksum(1) | compress_flag(1) | header... | encrypted_payload ]
        // We must skip the checksum byte AND the compressed header before decrypting,
        // otherwise we'd be computing a checksum over garbage (header + cipher bytes).
        const auto& blob = pdu.getEncryptedPayload();
        int offset = 0;

        // Skip byte 0 — that's the checksum field itself, not payload data
        offset += 1;

        // Parse and skip the ROHC header so we land exactly on the encrypted payload
        uint8_t flag = blob[offset++];
        if (flag == 0x00)
        {
            // Full IR header: src_len + src_bytes + dst_len + dst_bytes
            uint8_t srcLen = blob[offset++];
            offset += srcLen;
            uint8_t dstLen = blob[offset++];
            offset += dstLen;
        }
        else
        {
            // CO (compressed) header: 2-byte context ID
            offset += 2;
        }

        // Now decrypt only the payload portion and verify the checksum
        std::vector<uint8_t> encPayload(blob.begin() + offset, blob.end());
        std::vector<uint8_t> decrypted = decrypt(encPayload);
        uint8_t recalculated = computeChecksum(decrypted);

        if (recalculated == pdu.getChecksum())
        {
            std::cout << "  SN " << pdu.getSequenceNumber() << ": Integrity check PASSED\n";
            return true;
        }
        else
        {
            std::cout << "  SN " << pdu.getSequenceNumber() << ": Integrity check FAILED\n";
            return false;
        }
    }

    void printAll()
    {
        std::cout << "\n--- All PDCP PDUs ---\n";
        for (int i = 0; i < (int)pdus.size(); i++)
            pdus[i].print();
    }

    // --- Print both ROHC context tables for inspection ---
    void printContextTables()
    {
        std::cout << "\n--- ROHC Compressor Context Table ---\n";
        if (compressorTable.empty())
            std::cout << "  (empty)\n";
        for (const auto &kv : compressorTable)
            std::cout << "  ID=" << kv.first << " -> ("
                      << kv.second.first << ", " << kv.second.second << ")\n";

        std::cout << "--- ROHC Decompressor Context Table ---\n";
        if (decompressorTable.empty())
            std::cout << "  (empty)\n";
        for (const auto &kv : decompressorTable)
            std::cout << "  ID=" << kv.first << " -> ("
                      << kv.second.first << ", " << kv.second.second << ")\n";
    }

    std::vector<PDCPpdu> getPDUs() { return pdus; }
};
