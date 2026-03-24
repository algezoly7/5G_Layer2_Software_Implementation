#pragma once
#include <iostream>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <string>
#include "channel.h"

// =====================================================================
//  RANDOM ACCESS PROCEDURE  —  3GPP TS 38.321  / TS 38.300 
// A UE without dedicated resources must perform contention-based Random
// Access before it can send user data on the 5G NR Uu interface.
// The procedure is a four-message handshake; every message crosses the
// 30%-loss air channel.
//
//  Msg1 (UE → gNB)  PRACH Preamble
//       UE selects one of 64 Zadoff-Chu preamble sequences at random
//       and transmits it on the Physical RACH (PRACH) resource.
//       If two UEs pick the same preamble they collide — Msg4 resolves
//       contention by echoing Msg3's UE identity.
//
//  Msg2 (gNB → UE)  Random Access Response (RAR)  — DL-SCH, RA-RNTI
//       gNB responds with: Timing Advance (TA) correction, a temporary
//       cell-radio-network identifier (TC-RNTI), and a small 56-byte
//       UL grant so the UE can send Msg3.
//
//  Msg3 (UE → gNB)  RRC Setup Request  — UL-SCH, TC-RNTI
//       UE sends its identity (ng-5G-S-TMSI or random 39-bit value) for
//       gNB contention resolution.
//
//  Msg4 (gNB → UE)  RRC Setup  — DL-SCH, TC-RNTI
//       gNB echoes the Msg3 UE identity (Contention Resolution IE),
//       confirming which UE won, and assigns the permanent dedicated
//       C-RNTI the UE will use for all future UL/DL transmissions.
//       Only the UE whose identity matches the echo accepts Msg4.
//
// If any message is lost the UE backs off and restarts from Msg1.
// MAX_RACH_ATTEMPTS controls how many complete attempts are allowed.
// =====================================================================

struct RACHResult
{
    bool     success;     // True when all four messages completed cleanly
    uint16_t cRNTI;       // Dedicated C-RNTI (valid on success or fallback)
    uint16_t tempCRNTI;   // TC-RNTI from Msg2 — kept for display only
    int      attempts;    // How many full Msg1→Msg4 cycles were needed
};

class RACHProcedure
{
private:
    static const int MAX_RACH_ATTEMPTS = 5;

    // Format a 16-bit identifier as 0xXXXX for display.
    static std::string hex16(uint16_t v)
    {
        char buf[8];
        snprintf(buf, sizeof(buf), "0x%04X", (unsigned)v);
        return std::string(buf);
    }

    // Valid C-RNTI range: 0x0001 – 0xFFF3  (3GPP TS 38.321 Table 7.1-1)
    static uint16_t randomCRNTI()
    {
        return (uint16_t)(1 + rand() % 0xFFF3);
    }

public:
    // ── run ──────────────────────────────────────────────────────────────
    // Execute the full RACH procedure, retrying on any per-message loss.
    // Returns when the procedure succeeds or all attempts are exhausted.
    RACHResult run()
    {
        RACHResult result{ false, 0, 0, 0 };

        std::cout << "\n  [RACH] UE has no dedicated resources — initiating NR RACH.\n"
                     "  [RACH] 64 Zadoff-Chu preamble sequences available on PRACH.\n\n";

        for (int attempt = 1; attempt <= MAX_RACH_ATTEMPTS; ++attempt)
        {
            result.attempts = attempt;
            std::cout << "  ---- RACH Attempt " << attempt
                      << " / " << MAX_RACH_ATTEMPTS << " ----\n";

            // ── Msg1: PRACH Preamble ──────────────────────────────────────
            // UE picks a random preamble index (0–63) and transmits on PRACH.
            uint8_t preamble = (uint8_t)(rand() % 64);
            std::cout << "  [RACH] Msg1 — UE selects preamble #" << (int)preamble
                      << " and transmits on PRACH resource.\n";
            if (!airTransmit("PRACH-preamble#" + std::to_string((int)preamble)))
            {
                std::cout << "  [RACH] Msg1 lost — backing off, retrying.\n\n";
                continue;
            }
            std::cout << "  [RACH] gNB detected preamble #" << (int)preamble
                      << " on PRACH.\n";

            // ── Msg2: Random Access Response ─────────────────────────────
            // gNB assigns a TC-RNTI and grants 56B for Msg3.
            uint16_t tcRNTI = randomCRNTI();
            std::cout << "  [RACH] Msg2 — gNB sends RAR on DL-SCH (RA-RNTI):\n"
                      << "         echo-preamble=#" << (int)preamble
                      << "  TC-RNTI=" << hex16(tcRNTI)
                      << "  TA=0  UL-grant=56B\n";
            if (!airTransmit("RAR(TC-RNTI=" + hex16(tcRNTI) + ")"))
            {
                std::cout << "  [RACH] Msg2 (RAR) lost — UE never received TC-RNTI,"
                             " retrying.\n\n";
                continue;
            }
            std::cout << "  [RACH] UE received RAR — TC-RNTI=" << hex16(tcRNTI)
                      << ", UL grant=56B available.\n";
            result.tempCRNTI = tcRNTI;

            // ── Msg3: RRC Setup Request ───────────────────────────────────
            // UE sends its identity (random 39-bit NR value) for contention resolution.
            uint32_t ueIdentity = (uint32_t)rand();
            char uid[12];
            snprintf(uid, sizeof(uid), "0x%08X", ueIdentity);
            std::cout << "  [RACH] Msg3 — UE sends RRC Setup Request"
                         " (UL-SCH, TC-RNTI=" << hex16(tcRNTI) << "):\n"
                      << "         UE-identity=" << uid
                      << "  (random value, used for contention resolution)\n";
            if (!airTransmit("RRCSetupRequest(TC-RNTI=" + hex16(tcRNTI) + ")"))
            {
                std::cout << "  [RACH] Msg3 lost — gNB did not receive request,"
                             " retrying.\n\n";
                continue;
            }
            std::cout << "  [RACH] gNB received Msg3 from UE-identity=" << uid << ".\n";

            // ── Msg4: RRC Setup / Contention Resolution ───────────────────
            // gNB echoes ueIdentity and assigns the permanent C-RNTI.
            // Only the UE whose Msg3 identity matches accepts this message.
            uint16_t dedicatedCRNTI = randomCRNTI();
            std::cout << "  [RACH] Msg4 — gNB sends RRC Setup (DL-SCH):\n"
                      << "         Contention-Resolution-IE=" << uid
                      << "  (echoes Msg3 — winning UE matches)\n"
                      << "         Dedicated C-RNTI=" << hex16(dedicatedCRNTI) << "\n";
            if (!airTransmit("RRCSetup(C-RNTI=" + hex16(dedicatedCRNTI) + ")"))
            {
                std::cout << "  [RACH] Msg4 lost — UE did not receive C-RNTI,"
                             " retrying.\n\n";
                continue;
            }

            // ── RACH Complete ─────────────────────────────────────────────
            std::cout << "  [RACH] UE accepted Msg4 (UE-identity matches Msg3).\n"
                      << "  [RACH] [OK] NR Random Access complete in " << attempt
                      << " attempt(s).\n"
                      << "  [RACH]     Dedicated C-RNTI = " << hex16(dedicatedCRNTI)
                      << "  (used for all future UL/DL transmissions)\n";

            result.success = true;
            result.cRNTI   = dedicatedCRNTI;
            return result;
        }

        // Exhausted all attempts — fallback to keep simulation running.
        std::cout << "\n  [RACH] [FAIL] RACH failed after " << MAX_RACH_ATTEMPTS
                  << " attempts.\n"
                     "  [RACH]        Using fallback C-RNTI=0x0001 to continue.\n";
        result.cRNTI = 0x0001;
        return result;
    }
};
