#pragma once
#include <cstdlib>
#include <iostream>
#include <string>

// ===================== AIR INTERFACE SIMULATION =====================
// Every packet that crosses the air interface — Transport Blocks (data),
// HARQ ACK/NACK feedback, and RLC STATUS PDUs — has a 30% probability
// of being lost due to radio fading, interference or collision.
// This applies symmetrically in both directions (UE ↔ gNB).
// Physical channel: 5G NR Uu interface  (3GPP TS 38.300)

const float CHANNEL_LOSS_PROB = 0.30f;

// Transmit one packet over the air.
// Returns true  → packet arrived intact
// Returns false → packet was lost
inline bool airTransmit(const std::string& label)
{
    bool ok = ((float)rand() / RAND_MAX) > CHANNEL_LOSS_PROB;
    std::cout << "        [AIR] " << label
              << (ok ? "  → ARRIVED\n" : "  → LOST (30%)\n");
    return ok;
}

// ===================== MAC SCHEDULER GRANT =====================
// The MAC scheduler (gNB side) decides how large the next Transport Block
// will be based on radio conditions, queue depth, and QoS requirements.
// We model three typical allocation sizes with a weighted distribution
// that peaks at 100B — resembling a normal distribution over a small set.
//
//   25B  (25%) — poor conditions, small grant
//  100B  (50%) — typical everyday allocation
//  150B  (25%) — good conditions, large grant
inline int pickTBGrant()
{
    float r = (float)rand() / RAND_MAX;
    if (r < 0.25f) return 25;
    if (r < 0.75f) return 100;
    return 150;
}
