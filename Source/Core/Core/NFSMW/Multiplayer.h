// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// Open-world multiplayer for Need for Speed: Most Wanted (GameCube, GOWE69).
//
// Every player's game sends its car (position, rotation, velocity, model) over UDP, usually through
// a small relay ("hub"), and shows every other player as a driverless "ghost" car of their real
// model. Three built-in Gecko patches let us spawn and keep those ghosts and switch traffic off.
// Wire-compatible with the PC tools (netplay.py / hub.py), so phones and PCs can play together.
//
// Settings live in <User>/Config/NFSMWMultiplayer.ini (created on first boot of the game).

#pragma once

#include <string>
#include <vector>

namespace Core
{
class CPUThreadGuard;
}
namespace Gecko
{
class GeckoCode;
}

namespace NFSMW
{
// Called when patches load at game boot. Reads the settings and returns the Gecko patches the
// multiplayer needs - empty unless the game is GOWE69 and multiplayer is enabled.
std::vector<Gecko::GeckoCode> GetBuiltinCodes(const std::string& game_id);

// Called once per frame on the CPU thread, after the Gecko code handler.
void OnFrame(const Core::CPUThreadGuard& guard);

// Called when emulation stops.
void Shutdown();
}  // namespace NFSMW
