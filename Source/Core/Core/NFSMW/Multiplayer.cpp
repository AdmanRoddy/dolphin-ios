// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// C++ port of the PC multiplayer tools (mp-mod/src: nfsmw.py, ghost.py, spawn.py, netplay.py,
// clear_traffic.py, cheats.py). Addresses come from the game's own debug symbols; see
// mp-mod/NOTES.md for how each one was found and verified.

#include "Core/NFSMW/Multiplayer.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string_view>

#include <SFML/Network.hpp>
#include <fmt/format.h>

#include "Common/CommonTypes.h"
#include "Common/FileUtil.h"
#include "Common/IniFile.h"
#include "Common/Logging/Log.h"
#include "Common/Timer.h"
#include "Core/Core.h"
#include "Core/GeckoCode.h"
#include "Core/PowerPC/MMU.h"
#include "VideoCommon/OnScreenDisplay.h"

namespace NFSMW
{
namespace
{
// ---- Game addresses (GOWE69 only) -------------------------------------------------------------
constexpr u32 PLAYER_LISTS = 0x804812cc;  // ListableSet<IPlayer>::_mLists, list stride 0x30
constexpr u32 RB_TABLE = 0x80480b5c;      // Listable<IRigidBody,160>::_mTable
constexpr u32 VEH_LISTS = 0x8048092c;     // ListableSet<IVehicle>::_mLists, list stride 0x38
constexpr u32 FN_LOCALPLAYER_GETSIMABLE = 0x8028932c;
constexpr u32 FN_PHYSICSOBJECT_GETRIGIDBODY = 0x8022d8c0;
constexpr u32 FN_PHYSICSOBJECT_GETRIGIDBODY_C = 0x8022d8c8;
constexpr u32 FN_RIGIDBODY_GETPOSITION = 0x802670a8;
constexpr u32 VT_RBVEHICLE_IRIGIDBODY = 0x80400d48;
constexpr u32 SELECTOR_PTR = 0x804372a8;  // DebugVehicleSelection::mThis
constexpr u32 CHANGE_PLAYER_VEHICLE = 0x804372b0;
constexpr u32 FE_DATABASE = 0x8041c484;
constexpr u32 UNLOCK_ALL_THINGS = 0x8041eeb0;

// Selector fields our patches use (unused 0xaaaaaaaa fill in the original game).
constexpr u32 SEL_GHOST_FLAG = 0x08;    // 'GHST' while a ghost spawn is requested
constexpr u32 SEL_LAST_GHOST = 0x18;    // ISimable* of the last ghost spawned
constexpr u32 SEL_INDEX = 0x1c;         // name list index (pre-incremented by Service())
constexpr u32 SEL_NAMES_BEGIN = 0x20;   // std::vector<const char*> of 38 player-car names
constexpr u32 SEL_NAMES_END = 0x24;     // ghost keep table starts here (spare capacity)
constexpr u32 SEL_TRAFFIC_FLAG = 0x28;  // 'NOTR' while traffic should be off
constexpr u32 SEL_NAMES_CAP_END = 0x2c;
constexpr u32 GHOST_MAGIC = 0x47485354;
constexpr u32 NO_TRAFFIC_MAGIC = 0x4E4F5452;
constexpr int KEEP_SLOTS = 8;

constexpr u32 ISIMABLE_TO_PVEHICLE = static_cast<u32>(-44);
constexpr u32 IVEHICLE_TO_ISIMABLE = static_cast<u32>(-136);

constexpr float FAR_AWAY = 20000.0f;  // metres outside the map, where cleared cars are parked
constexpr u32 RICH_CASH = 9'999'999;

// ---- Built-in Gecko patches (identical to mp-mod/src/build_gecko.py output) -----------------------
struct BuiltinCode
{
  const char* name;
  std::vector<std::pair<u32, u32>> lines;
};

const std::array<BuiltinCode, 3>& Codes()
{
  static const std::array<BuiltinCode, 3> codes{{
      {"NFSMW multiplayer: ghost car spawn hook",
       {{0xC22C66E8, 0x0000000D}, {0x3D808043, 0x818C72A8}, {0x800C0008, 0x3D604748},
        {0x616B5354, 0x7C005800}, {0x40820044, 0x906C0018}, {0x38000000, 0x900C0008},
        {0x2C030000, 0x4182001C}, {0x3863FFD4, 0x38800004}, {0x3D808021, 0x618C03E4},
        {0x7D8903A6, 0x4E800421}, {0x38600001, 0x3D80802C}, {0x618C673C, 0x7D8903A6},
        {0x4E800420, 0x7C691B79}, {0x60000000, 0x00000000}}},
      {"NFSMW multiplayer: shared empty streets (no traffic toggle)",
       {{0xC20055A8, 0x00000006}, {0x3D808043, 0x818C72A8}, {0x800C0028, 0x3D604E4F},
        {0x616B5452, 0x7C005800}, {0x40820010, 0x3D80803D}, {0xC02C8FD4, 0x4E800020},
        {0x9421FFF0, 0x00000000}}},
      {"NFSMW multiplayer: keep ghost cars loaded",
       {{0xC22EBE28, 0x00000009}, {0x3D808043, 0x818C72A8}, {0x3804FF78, 0x38600001},
        {0x816C0018, 0x7C005800}, {0x41820028, 0x816C0024}, {0x396BFFFC, 0x39400008},
        {0x7D4903A6, 0x854B0004}, {0x7C005000, 0x4182000C}, {0x4200FFF4, 0x48000008},
        {0x38600000, 0x00000000}}},
  }};
  return codes;
}
constexpr u32 HOOK_SPAWN = 0x802c66e8;
constexpr u32 HOOK_SPAWN_ORIGINAL = 0x7c691b79;  // or. r9,r3,r3 - still there = patch not applied

// ---- Network ---------------------------------------------------------------------------------
// Packet "NFM2" (big-endian, 92 bytes): magic, player id, seq, sender time (f64), quat[4], pos[3],
// vel[3] (f32), car model[16], player name[16]. Same as netplay.py.
constexpr std::size_t PACKET_SIZE = 92;
constexpr double SEND_INTERVAL = 1.0 / 30.0;
constexpr double PEER_TIMEOUT = 5.0;
constexpr double RESPAWN_COOLDOWN = 3.0;
constexpr double HOUSEKEEPING_EVERY = 10.0;
constexpr double BODY_CHECK_EVERY = 0.25;
constexpr double SPAWN_TIMEOUT = 2.0;
constexpr double EXTRAPOLATE = 0.25;
constexpr u16 DEFAULT_HUB_PORT = 50100;

struct Settings
{
  bool enabled = false;
  std::string name = "player";
  std::string server;  // host or host:port of the hub (or another player)
  bool rich = false;
  bool keep_traffic = false;
  double buffer = 0.1;  // seconds of interpolation delay
};

struct CarState
{
  std::array<float, 4> orient{};
  std::array<float, 3> pos{};
  std::array<float, 3> vel{};
};

double Now()
{
  return static_cast<double>(Common::Timer::NowUs()) / 1e6;
}

void Message(std::string text, u32 color = OSD::Color::CYAN)
{
  NOTICE_LOG_FMT(CORE, "NFSMW multiplayer: {}", text);
  OSD::AddMessage("[MP] " + text, OSD::Duration::NORMAL, color);
}

// ---- Guest memory --------------------------------------------------------------------------------
// Quiet reads/writes: a bad pointer (cars being destroyed mid-frame, loading screens) must never
// pop up an error, it just makes this frame's work skip.
class Mem
{
public:
  explicit Mem(const Core::CPUThreadGuard& guard) : m_guard(guard) {}

  u32 U(u32 address)
  {
    const auto r = PowerPC::MMU::HostTryRead<u32>(m_guard, address);
    if (!r)
    {
      m_ok = false;
      return 0;
    }
    return r->value;
  }
  float F(u32 address) { return std::bit_cast<float>(U(address)); }
  void W(u32 address, u32 value) { PowerPC::MMU::HostTryWrite<u32>(m_guard, value, address); }
  void WF(u32 address, float value) { W(address, std::bit_cast<u32>(value)); }
  std::string Str(u32 address, std::size_t max = 32)
  {
    std::string s;
    for (std::size_t i = 0; i < max; ++i)
    {
      const auto r = PowerPC::MMU::HostTryRead<u8>(m_guard, address + static_cast<u32>(i));
      if (!r || r->value == 0)
        break;
      s.push_back(static_cast<char>(r->value));
    }
    return s;
  }
  bool Ok() const { return m_ok; }
  void ResetOk() { m_ok = true; }

private:
  const Core::CPUThreadGuard& m_guard;
  bool m_ok = true;
};

bool Valid(u32 p)
{
  return p >= 0x80000000 && p < 0x81800000;
}

// CodeWarrior vtables: vptr at object+4; each slot is s16 this-adjust then u32 function.
// Returns the adjusted `this` if the slot holds one of the expected functions, else 0.
u32 VCallThis(Mem& m, u32 obj, u32 slot, std::initializer_list<u32> expected)
{
  if (!Valid(obj))
    return 0;
  const u32 vt = m.U(obj + 4);
  if (!Valid(vt))
    return 0;
  const s16 adjust = static_cast<s16>(m.U(vt + slot) >> 16);
  const u32 fn = m.U(vt + slot + 4);
  if (std::ranges::find(expected, fn) == expected.end())
    return 0;
  return obj + static_cast<u32>(static_cast<s32>(adjust));
}

u32 RigidBodyOfSimable(Mem& m, u32 simable)
{
  const u32 self = VCallThis(m, simable, 0xa8,
                             {FN_PHYSICSOBJECT_GETRIGIDBODY, FN_PHYSICSOBJECT_GETRIGIDBODY_C});
  return self ? m.U(self + 0x78) : 0;
}

// RigidBody::GetPosition: **(this + 0x88) is the car's "Volatile" physics state:
// +0x00 orientation quaternion, +0x10 position, +0x1c status (untouched), +0x20 velocity,
// +0x30 angular velocity.
u32 StateOfRigidBody(Mem& m, u32 rb)
{
  const u32 self = VCallThis(m, rb, 0x48, {FN_RIGIDBODY_GETPOSITION});
  if (!self)
    return 0;
  const u32 slot = m.U(self + 0x88);
  return Valid(slot) ? m.U(slot) : 0;
}

u32 PlayerSimable(Mem& m)
{
  const u32 list = PLAYER_LISTS + 1 * 0x30;  // list 1 = local players
  if (m.U(list + 8) == 0)
    return 0;
  const u32 player = m.U(m.U(list));
  const u32 self = VCallThis(m, player, 0x10, {FN_LOCALPLAYER_GETSIMABLE});
  return self ? m.U(self + 0x48) : 0;
}

std::string ModelOfSimable(Mem& m, u32 simable)
{
  // PVehicle::GetVehicleName: *(*(pvehicle + 0xe0) + 0x24); the layout lives in VMEM (0x7E...).
  const u32 pv = simable + ISIMABLE_TO_PVEHICLE;
  return m.Str(m.U(m.U(pv + 0xe0) + 0x24), 16);
}

std::map<u32, u32> VehicleBodies(Mem& m)  // IRigidBody* -> physics state, for every RBVehicle
{
  std::map<u32, u32> out;
  const u32 begin = m.U(RB_TABLE);
  const u32 count = std::min<u32>(m.U(RB_TABLE + 8), 160);
  for (u32 i = 0; i < count; ++i)
  {
    const u32 rb = m.U(begin + 4 * i);
    if (!Valid(rb) || m.U(rb + 4) != VT_RBVEHICLE_IRIGIDBODY)
      continue;
    if (const u32 state = StateOfRigidBody(m, rb))
      out[rb] = state;
  }
  return out;
}

CarState ReadState(Mem& m, u32 state)
{
  CarState s;
  for (int i = 0; i < 4; ++i)
    s.orient[i] = m.F(state + 4 * i);
  for (int i = 0; i < 3; ++i)
  {
    s.pos[i] = m.F(state + 0x10 + 4 * i);
    s.vel[i] = m.F(state + 0x20 + 4 * i);
  }
  return s;
}

void WriteState(Mem& m, u32 state, const CarState& s)
{
  for (int i = 0; i < 4; ++i)
    m.WF(state + 4 * i, s.orient[i]);
  for (int i = 0; i < 3; ++i)
  {
    m.WF(state + 0x10 + 4 * i, s.pos[i]);
    m.WF(state + 0x20 + 4 * i, s.vel[i]);
    m.WF(state + 0x30 + 4 * i, 0.0f);
  }
}

// ---- Interpolation ---------------------------------------------------------------------------
class Track
{
public:
  void Add(double t, const CarState& s)
  {
    m_samples.emplace_back(t, s);
    while (m_samples.size() > 600)
      m_samples.pop_front();
  }
  bool Empty() const { return m_samples.empty(); }

  std::optional<CarState> At(double t) const
  {
    if (m_samples.empty() || t < m_samples.front().first)
      return std::nullopt;
    const auto it = std::ranges::upper_bound(m_samples, t, {}, &Sample::first);
    if (it == m_samples.end())
    {
      // Past the newest sample: coast on its velocity for a little while.
      CarState s = m_samples.back().second;
      const float dt = static_cast<float>(std::min(t - m_samples.back().first, EXTRAPOLATE));
      for (int i = 0; i < 3; ++i)
        s.pos[i] += s.vel[i] * dt;
      return s;
    }
    const auto& [t1, b] = *it;
    const auto& [t0, a] = *std::prev(it);
    const float f = t1 > t0 ? static_cast<float>((t - t0) / (t1 - t0)) : 0.0f;
    CarState s;
    float dot = 0;
    for (int i = 0; i < 4; ++i)
      dot += a.orient[i] * b.orient[i];
    const float sign = dot < 0 ? -1.0f : 1.0f;  // take the short way round
    float norm = 0;
    for (int i = 0; i < 4; ++i)
    {
      s.orient[i] = a.orient[i] + (sign * b.orient[i] - a.orient[i]) * f;
      norm += s.orient[i] * s.orient[i];
    }
    norm = norm > 0 ? std::sqrt(norm) : 1.0f;
    for (int i = 0; i < 4; ++i)
      s.orient[i] /= norm;
    for (int i = 0; i < 3; ++i)
    {
      s.pos[i] = a.pos[i] + (b.pos[i] - a.pos[i]) * f;
      s.vel[i] = a.vel[i] + (b.vel[i] - a.vel[i]) * f;
    }
    return s;
  }

private:
  using Sample = std::pair<double, CarState>;
  std::deque<Sample> m_samples;
};

struct Peer
{
  u32 id = 0;
  int slot = 0;
  std::string name, model, ghost_model;
  Track track;
  std::optional<double> clock_offset;
  s64 last_seq = -1;
  u64 got = 0, lost = 0;
  double last_heard = 0, last_spawn = -RESPAWN_COOLDOWN;
  u32 ghost_rb = 0, ghost_state = 0;
};

struct Parking
{
  u32 state;
  float x;
  int frames;
};

// ---- Packet encoding -------------------------------------------------------------------------
void PutU32(u8* p, u32 v)
{
  p[0] = static_cast<u8>(v >> 24);
  p[1] = static_cast<u8>(v >> 16);
  p[2] = static_cast<u8>(v >> 8);
  p[3] = static_cast<u8>(v);
}
u32 GetU32(const u8* p)
{
  return (u32(p[0]) << 24) | (u32(p[1]) << 16) | (u32(p[2]) << 8) | u32(p[3]);
}
void PutStr(u8* p, std::string_view s)
{
  std::memset(p, 0, 16);
  std::memcpy(p, s.data(), std::min<std::size_t>(s.size(), 16));
}
std::string GetStr(const u8* p)
{
  return std::string(reinterpret_cast<const char*>(p), strnlen(reinterpret_cast<const char*>(p), 16));
}

std::array<u8, PACKET_SIZE> Encode(u32 id, u32 seq, double t, const CarState& s,
                                   std::string_view model, std::string_view name)
{
  std::array<u8, PACKET_SIZE> b{};
  std::memcpy(b.data(), "NFM2", 4);
  PutU32(&b[4], id);
  PutU32(&b[8], seq);
  const u64 tb = std::bit_cast<u64>(t);
  PutU32(&b[12], static_cast<u32>(tb >> 32));
  PutU32(&b[16], static_cast<u32>(tb));
  u8* p = &b[20];
  for (float f : s.orient)
    PutU32(p, std::bit_cast<u32>(f)), p += 4;
  for (float f : s.pos)
    PutU32(p, std::bit_cast<u32>(f)), p += 4;
  for (float f : s.vel)
    PutU32(p, std::bit_cast<u32>(f)), p += 4;
  PutStr(&b[60], model);
  PutStr(&b[76], name);
  return b;
}

// ---- The session -------------------------------------------------------------------------------
class Session
{
public:
  explicit Session(Settings settings) : m_settings(std::move(settings))
  {
    std::random_device rd;
    m_my_id = (u32(rd()) << 16) ^ u32(rd());
    std::string host = m_settings.server;
    u16 port = DEFAULT_HUB_PORT;
    if (const auto colon = host.rfind(':'); colon != std::string::npos)
    {
      port = static_cast<u16>(std::stoi(host.substr(colon + 1)));
      host.resize(colon);
    }
    if (const auto ip = sf::IpAddress::resolve(host))
    {
      m_server = *ip;
      m_port = port;
    }
    else
    {
      Message(fmt::format("can't find server '{}' - check NFSMWMultiplayer.ini", m_settings.server),
              OSD::Color::RED);
    }
    m_socket.setBlocking(false);
    (void)m_socket.bind(sf::Socket::AnyPort);
    Message(fmt::format("multiplayer on as '{}' -> {}", m_settings.name, m_settings.server));
  }

  void Frame(const Core::CPUThreadGuard& guard)
  {
    Mem m(guard);
    const double now = Now();
    const u32 sel = m.U(SELECTOR_PTR);
    if (!Valid(sel))
      return;  // still booting
    if (!m_initialized)
    {
      m_hooks = m.U(HOOK_SPAWN) != HOOK_SPAWN_ORIGINAL;
      if (!m_hooks)
        Message("multiplayer patches not active yet", OSD::Color::YELLOW);
      ClearKeep(m, sel);
      m_initialized = true;
    }

    // Find our car and every car body (cheap enough every few frames).
    if (now - m_last_body_check >= BODY_CHECK_EVERY)
    {
      m_last_body_check = now;
      m_bodies = VehicleBodies(m);
      const u32 simable = PlayerSimable(m);
      m_player_simable = simable;
      m_player_state = 0;
      if (simable)
      {
        const u32 rb = RigidBodyOfSimable(m, simable);
        if (const auto it = m_bodies.find(rb); it != m_bodies.end())
          m_player_state = it->second;
      }
      for (auto& [id, p] : m_peers)
      {
        const auto it = m_bodies.find(p.ghost_rb);
        if (p.ghost_rb && (it == m_bodies.end() || it->second != p.ghost_state))
        {
          // Car destroyed (race end, cutscene) or its physics slot reused by another car.
          p.ghost_rb = p.ghost_state = 0;
          p.ghost_model.clear();
        }
      }
    }

    if (now - m_last_house >= HOUSEKEEPING_EVERY)
    {
      m_last_house = now;
      Housekeeping(m, sel);
    }
    Park(m);

    if (m_player_state && now - m_last_send >= SEND_INTERVAL)
    {
      m_last_send = now;
      Send(m, now);
    }
    Receive(now);
    UpdatePeers(m, sel, now);
  }

private:
  void ClearKeep(Mem& m, u32 sel)
  {
    const u32 table = m.U(sel + SEL_NAMES_END);
    if (m.U(sel + SEL_NAMES_CAP_END) - table < 4 * KEEP_SLOTS)
      return;
    for (int i = 0; i < KEEP_SLOTS; ++i)
      m.W(table + 4 * i, 0);
  }
  void SetKeep(Mem& m, u32 sel, int slot, u32 simable)
  {
    const u32 table = m.U(sel + SEL_NAMES_END);
    if (m.U(sel + SEL_NAMES_CAP_END) - table >= 4 * KEEP_SLOTS)
      m.W(table + 4 * slot, simable);
  }

  void Housekeeping(Mem& m, u32 sel)
  {
    if (m_hooks && !m_settings.keep_traffic)
    {
      // No traffic: the patched ComputeDensity returns 0 while this is set (savestate loads can
      // reset it, so keep re-applying), and cars already on the road get parked off the map.
      m.W(sel + SEL_TRAFFIC_FLAG, NO_TRAFFIC_MAGIC);
      const u32 count = std::min<u32>(m.U(VEH_LISTS + 8), 64);
      const u32 begin = m.U(VEH_LISTS);
      for (u32 k = 0; k < count; ++k)
      {
        const u32 simable = m.U(begin + 4 * k) + IVEHICLE_TO_ISIMABLE;
        if (!ModelOfSimable(m, simable).starts_with("traf"))
          continue;
        const auto it = m_bodies.find(RigidBodyOfSimable(m, simable));
        if (it != m_bodies.end() && m.F(it->second + 0x10) < FAR_AWAY / 2)
          m_parking.push_back({it->second, FAR_AWAY + 50.0f * float(m_parking.size()), 12});
      }
    }
    if (m_settings.rich)
    {
      m.ResetOk();
      const u32 career = m.U(m.U(FE_DATABASE) + 0x20) + 0xe4;
      if (m.Ok() && m.U(career + 0x0c) < RICH_CASH)
        m.W(career + 0x0c, RICH_CASH);
      m.W(UNLOCK_ALL_THINGS, 1);
    }
  }

  void Park(Mem& m)
  {
    // Hold parked cars in place for a few frames until the game accepts the move.
    for (auto& p : m_parking)
    {
      m.WF(p.state + 0x10, p.x);
      m.WF(p.state + 0x14, 500.0f);
      m.WF(p.state + 0x18, FAR_AWAY);
      for (int i = 0; i < 3; ++i)
        m.WF(p.state + 0x20 + 4 * i, 0.0f);
      --p.frames;
    }
    std::erase_if(m_parking, [](const Parking& p) { return p.frames <= 0; });
  }

  void Send(Mem& m, double now)
  {
    if (now - m_model_at >= 1.0)
    {
      m_model_at = now;
      m_my_model = ModelOfSimable(m, m_player_simable);
    }
    m.ResetOk();
    const CarState me = ReadState(m, m_player_state);
    if (!m.Ok() || !m_port)
      return;
    const auto pkt = Encode(m_my_id, m_seq++, now, me, m_my_model, m_settings.name);
    (void)m_socket.send(pkt.data(), pkt.size(), m_server, m_port);
  }

  void Receive(double now)
  {
    std::array<u8, 256> buf;
    for (;;)
    {
      std::size_t got = 0;
      std::optional<sf::IpAddress> from;
      unsigned short port = 0;
      if (m_socket.receive(buf.data(), buf.size(), got, from, port) != sf::Socket::Status::Done)
        break;
      if (got != PACKET_SIZE || std::memcmp(buf.data(), "NFM2", 4) != 0)
        continue;
      const u32 id = GetU32(&buf[4]);
      if (id == m_my_id)
        continue;
      auto it = m_peers.find(id);
      if (it == m_peers.end())
      {
        if (m_free_slots.empty())
          continue;  // more players than ghost slots
        Peer p;
        p.id = id;
        p.slot = m_free_slots.front();
        m_free_slots.erase(m_free_slots.begin());
        it = m_peers.emplace(id, std::move(p)).first;
        Message(fmt::format("{} joined", GetStr(&buf[76])), OSD::Color::GREEN);
      }
      Peer& p = it->second;
      p.name = GetStr(&buf[76]);
      p.model = GetStr(&buf[60]);
      p.last_heard = now;
      const u32 seq = GetU32(&buf[8]);
      if (static_cast<s64>(seq) <= p.last_seq)
        continue;  // stale or duplicate
      if (p.last_seq >= 0)
        p.lost += seq - p.last_seq - 1;
      p.last_seq = seq;
      ++p.got;
      const double t_sent =
          std::bit_cast<double>((u64(GetU32(&buf[12])) << 32) | u64(GetU32(&buf[16])));
      const double offset = now - t_sent;
      p.clock_offset = p.clock_offset ? std::min(*p.clock_offset, offset) : offset;
      CarState s;
      const u8* q = &buf[20];
      for (float& f : s.orient)
        f = std::bit_cast<float>(GetU32(q)), q += 4;
      for (float& f : s.pos)
        f = std::bit_cast<float>(GetU32(q)), q += 4;
      for (float& f : s.vel)
        f = std::bit_cast<float>(GetU32(q)), q += 4;
      p.track.Add(t_sent + *p.clock_offset, s);
    }
  }

  void UpdatePeers(Mem& m, u32 sel, double now)
  {
    for (auto it = m_peers.begin(); it != m_peers.end();)
    {
      Peer& p = it->second;
      if (now - p.last_heard > PEER_TIMEOUT)
      {
        Message(fmt::format("{} left", p.name), OSD::Color::YELLOW);
        if (p.ghost_state)
          m_parking.push_back({p.ghost_state, FAR_AWAY - 500.0f - 50.0f * float(p.slot), 12});
        SetKeep(m, sel, p.slot, 0);
        m_free_slots.push_back(p.slot);
        it = m_peers.erase(it);
        continue;
      }
      ++it;
    }

    // One spawn at a time: the game services the request during the next World_Service tick.
    if (m_spawn_for)
    {
      FinishSpawn(m, sel, now);
    }
    else if (m_hooks && m_player_state)
    {
      for (auto& [id, p] : m_peers)
      {
        if (!p.model.empty() && (p.model != p.ghost_model || !p.ghost_state) &&
            now - p.last_spawn >= RESPAWN_COOLDOWN)
        {
          p.last_spawn = now;
          StartSpawn(m, sel, p, now);
          break;
        }
      }
    }

    for (auto& [id, p] : m_peers)
    {
      if (!p.ghost_state || p.track.Empty())
        continue;
      if (const auto target = p.track.At(now - m_settings.buffer))
        WriteState(m, p.ghost_state, *target);
    }
  }

  void StartSpawn(Mem& m, u32 sel, Peer& p, double now)
  {
    const u32 begin = m.U(sel + SEL_NAMES_BEGIN);
    const u32 n = (m.U(sel + SEL_NAMES_END) - begin) / 4;
    for (u32 i = 0; i < n && i < 64; ++i)
    {
      if (m.Str(m.U(begin + 4 * i), 16) != p.model)
        continue;
      m.W(sel + SEL_LAST_GHOST, 0);
      m.W(sel + SEL_GHOST_FLAG, GHOST_MAGIC);
      m.W(sel + SEL_INDEX, (i + n - 1) % n);  // Service() pre-increments the index
      m.W(CHANGE_PLAYER_VEHICLE, 1);
      m_spawn_for = p.id;
      m_spawn_started = now;
      return;
    }
    Message(fmt::format("can't show {}: unknown car '{}'", p.name, p.model), OSD::Color::RED);
    p.ghost_model = p.model;  // don't retry an unknown model forever
  }

  void FinishSpawn(Mem& m, u32 sel, double now)
  {
    const auto it = m_peers.find(m_spawn_for);
    if (m.U(CHANGE_PLAYER_VEHICLE) != 0)
    {
      if (now - m_spawn_started > SPAWN_TIMEOUT)
      {
        m.W(CHANGE_PLAYER_VEHICLE, 0);  // paused or loading - try again later
        m.W(sel + SEL_GHOST_FLAG, 0);
        m_spawn_for = 0;
      }
      return;
    }
    m_spawn_for = 0;
    const u32 simable = m.U(sel + SEL_LAST_GHOST);
    if (m.U(sel + SEL_GHOST_FLAG) == GHOST_MAGIC || !Valid(simable) || it == m_peers.end())
      return;
    Peer& p = it->second;
    const u32 rb = RigidBodyOfSimable(m, simable);
    const u32 state = StateOfRigidBody(m, rb);
    if (!state)
      return;
    SetKeep(m, sel, p.slot, simable);
    p.ghost_rb = rb;
    p.ghost_state = state;
    p.ghost_model = p.model;
    m_bodies[rb] = state;
  }

  Settings m_settings;
  sf::UdpSocket m_socket;
  sf::IpAddress m_server = sf::IpAddress::Any;
  u16 m_port = 0;
  u32 m_my_id = 0, m_seq = 0;
  std::string m_my_model;
  double m_model_at = -1, m_last_send = 0, m_last_house = -HOUSEKEEPING_EVERY, m_last_body_check = 0;
  bool m_initialized = false, m_hooks = false;
  u32 m_player_simable = 0, m_player_state = 0;
  std::map<u32, u32> m_bodies;
  std::map<u32, Peer> m_peers;
  std::vector<int> m_free_slots{0, 1, 2, 3, 4, 5, 6, 7};
  std::vector<Parking> m_parking;
  u32 m_spawn_for = 0;
  double m_spawn_started = 0;
};

std::optional<Settings> s_settings;  // set at boot when GOWE69 + enabled
std::unique_ptr<Session> s_session;

Settings LoadSettings()
{
  const std::string path = File::GetUserPath(D_CONFIG_IDX) + "NFSMWMultiplayer.ini";
  Common::IniFile ini;
  const bool existed = ini.Load(path);
  auto* section = ini.GetOrCreateSection("Multiplayer");
  Settings s;
  section->Get("Enabled", &s.enabled, false);
  section->Get("Name", &s.name, "player");
  section->Get("Server", &s.server, "");
  section->Get("RichMode", &s.rich, false);
  section->Get("KeepTraffic", &s.keep_traffic, false);
  section->Get("Buffer", &s.buffer, 0.1);
  if (!existed)
  {
    section->Set("Enabled", false);
    section->Set("Name", s.name);
    section->Set("Server", std::string("100.x.y.z:50100"));
    section->Set("RichMode", false);
    section->Set("KeepTraffic", false);
    section->Set("Buffer", 0.1);
    ini.Save(path);
  }
  s.name.resize(std::min<std::size_t>(s.name.size(), 16));
  return s;
}
}  // namespace

std::vector<Gecko::GeckoCode> GetBuiltinCodes(const std::string& game_id)
{
  s_session.reset();
  s_settings.reset();
  if (game_id != "GOWE69")
    return {};
  Settings settings = LoadSettings();
  if (!settings.enabled || settings.server.empty())
    return {};
  s_settings = settings;

  std::vector<Gecko::GeckoCode> out;
  for (const auto& code : Codes())
  {
    Gecko::GeckoCode g;
    g.name = code.name;
    g.creator = "NFSMW multiplayer";
    g.enabled = true;
    g.default_enabled = true;
    for (const auto& [address, data] : code.lines)
    {
      Gecko::GeckoCode::Code c;
      c.address = address;
      c.data = data;
      c.original_line = fmt::format("{:08X} {:08X}", address, data);
      g.codes.push_back(std::move(c));
    }
    out.push_back(std::move(g));
  }
  return out;
}

void OnFrame(const Core::CPUThreadGuard& guard)
{
  if (!s_settings)
    return;
  if (!s_session)
    s_session = std::make_unique<Session>(*s_settings);
  s_session->Frame(guard);
}

void Shutdown()
{
  s_session.reset();
  s_settings.reset();
}
}  // namespace NFSMW
