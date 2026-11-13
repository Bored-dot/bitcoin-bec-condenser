// crypto.hpp — SHA-256, tagged hash (BIP-340), hex, bech32m (BIP-350)
// Dio projekta: bitcoin-bec-condenser (ispravljena implementacija)
#pragma once

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

namespace bec {

// ---------------------------------------------------------------- SHA-256
namespace detail {
struct Sha256Ctx { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t used; };

inline uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

inline const uint32_t* ktable() {
    static const uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
    return K;
}

inline void sha256_block(Sha256Ctx& c, const unsigned char* p) {
    const uint32_t* K = ktable();
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t(p[i * 4]) << 24) | (uint32_t(p[i * 4 + 1]) << 16) |
               (uint32_t(p[i * 4 + 2]) << 8) | uint32_t(p[i * 4 + 3]);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3];
    uint32_t e = c.h[4], f = c.h[5], g = c.h[6], h = c.h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d;
    c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += h;
}

inline void sha256_init(Sha256Ctx& c) {
    static const uint32_t iv[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                                   0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    std::memcpy(c.h, iv, sizeof(iv));
    c.len = 0; c.used = 0;
}

inline void sha256_update(Sha256Ctx& c, const unsigned char* p, size_t n) {
    c.len += n;
    while (n) {
        size_t take = 64 - c.used;
        if (take > n) take = n;
        std::memcpy(c.buf + c.used, p, take);
        c.used += take; p += take; n -= take;
        if (c.used == 64) { sha256_block(c, c.buf); c.used = 0; }
    }
}

inline void sha256_final(Sha256Ctx& c, unsigned char out[32]) {
    uint64_t bits = c.len * 8;
    unsigned char pad = 0x80;
    sha256_update(c, &pad, 1);
    unsigned char z = 0;
    while (c.used != 56) sha256_update(c, &z, 1);
    unsigned char lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (unsigned char)(c.h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c.h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c.h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(c.h[i]);
    }
}
} // namespace detail

inline void sha256(const unsigned char* data, size_t len, unsigned char out[32]) {
    detail::Sha256Ctx c;
    detail::sha256_init(c);
    detail::sha256_update(c, data, len);
    detail::sha256_final(c, out);
}

inline void tagged_hash(const std::string& tag, const unsigned char* data, size_t len, unsigned char out[32]) {
    unsigned char tag_hash[32];
    sha256(reinterpret_cast<const unsigned char*>(tag.data()), tag.size(), tag_hash);
    detail::Sha256Ctx c;
    detail::sha256_init(c);
    detail::sha256_update(c, tag_hash, 32);
    detail::sha256_update(c, tag_hash, 32);
    if (len) detail::sha256_update(c, data, len);
    detail::sha256_final(c, out);
}

// ---------------------------------------------------------------- sigurno nuliranje
inline void secure_zero(void* p, size_t n) {
    volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
}

// ---------------------------------------------------------------- hex
inline std::string to_hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 0x0f]); }
    return s;
}
inline std::string to_hex(const std::vector<unsigned char>& v) { return to_hex(v.data(), v.size()); }

inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// striktno parsiranje: vraća false na bilo koji neispravan znak ili neparnu dužinu
inline bool from_hex(const std::string& s, std::vector<unsigned char>& out) {
    if (s.size() % 2) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_nibble(s[i]), lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((unsigned char)((hi << 4) | lo));
    }
    return true;
}

inline bool from_hex32(const std::string& s, unsigned char out[32]) {
    std::vector<unsigned char> v;
    if (!from_hex(s, v) || v.size() != 32) return false;
    std::memcpy(out, v.data(), 32);
    return true;
}

// ---------------------------------------------------------------- little-endian helpers
inline void put_u32le(std::vector<unsigned char>& v, uint32_t x) {
    for (int i = 0; i < 4; i++) v.push_back((unsigned char)(x >> (8 * i)));
}
inline void put_u64le(std::vector<unsigned char>& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((unsigned char)(x >> (8 * i)));
}
inline void put_bytes(std::vector<unsigned char>& v, const void* p, size_t n) {
    const unsigned char* b = static_cast<const unsigned char*>(p);
    v.insert(v.end(), b, b + n);
}
// CompactSize / varint
inline void put_compactsize(std::vector<unsigned char>& v, uint64_t n) {
    if (n < 0xfd) { v.push_back((unsigned char)n); }
    else if (n <= 0xffff) { v.push_back(0xfd); v.push_back((unsigned char)n); v.push_back((unsigned char)(n >> 8)); }
    else if (n <= 0xffffffffULL) { v.push_back(0xfe); put_u32le(v, (uint32_t)n); }
    else { v.push_back(0xff); put_u64le(v, n); }
}

// ---------------------------------------------------------------- bech32 / bech32m (BIP-173/350)
namespace bech32 {
inline const char* charset() { return "qpzry9x8gf2tvdw0s3jn54khce6mua7l"; }

inline uint32_t polymod(const std::vector<unsigned char>& values) {
    static const uint32_t GEN[5] = {0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
    uint32_t chk = 1;
    for (unsigned char v : values) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffffu) << 5) ^ v;
        for (int i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk;
}

inline std::vector<unsigned char> hrp_expand(const std::string& hrp) {
    std::vector<unsigned char> out;
    for (char c : hrp) out.push_back((unsigned char)(c >> 5));
    out.push_back(0);
    for (char c : hrp) out.push_back((unsigned char)(c & 31));
    return out;
}

inline bool convert_bits(const std::vector<unsigned char>& in, int from, int to,
                         bool pad, std::vector<unsigned char>& out) {
    uint32_t acc = 0;
    int bits = 0;
    out.clear();
    uint32_t maxv = (1u << to) - 1;
    for (unsigned char b : in) {
        if (b >> from) return false;
        acc = (acc << from) | b;
        bits += from;
        while (bits >= to) { bits -= to; out.push_back((unsigned char)((acc >> bits) & maxv)); }
    }
    if (pad) {
        if (bits) out.push_back((unsigned char)((acc << (to - bits)) & maxv));
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
        return false;
    }
    return true;
}

inline bool encode(const std::string& hrp, int witver, const std::vector<unsigned char>& program,
                   std::string& out) {
    std::vector<unsigned char> data;
    data.push_back((unsigned char)witver);
    std::vector<unsigned char> conv;
    if (!convert_bits(program, 8, 5, true, conv)) return false;
    data.insert(data.end(), conv.begin(), conv.end());

    uint32_t constval = (witver == 0) ? 1u : 0x2bc830a3u; // bech32 vs bech32m

    std::vector<unsigned char> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    for (int i = 0; i < 6; i++) values.push_back(0);
    uint32_t mod = polymod(values) ^ constval;

    std::vector<unsigned char> chk;
    for (int i = 0; i < 6; i++) chk.push_back((unsigned char)((mod >> (5 * (5 - i))) & 31));

    out = hrp + "1";
    for (unsigned char v : data) out.push_back(charset()[v]);
    for (unsigned char v : chk) out.push_back(charset()[v]);
    return true;
}

inline bool decode(const std::string& addr, std::string& hrp, int& witver,
                   std::vector<unsigned char>& program) {
    size_t pos = addr.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > addr.size()) return false;
    hrp = addr.substr(0, pos);
    for (char& c : hrp) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');

    std::vector<unsigned char> data;
    for (size_t i = pos + 1; i < addr.size(); i++) {
        int idx = -1;
        for (int j = 0; j < 32; j++) if (charset()[j] == addr[i]) { idx = j; break; }
        if (idx < 0) return false;
        data.push_back((unsigned char)idx);
    }
    if (data.size() < 7) return false;

    std::vector<unsigned char> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    uint32_t mod = polymod(values);
    bool is_m = (mod == 0x2bc830a3u);
    bool is_b = (mod == 1u);
    if (!is_m && !is_b) return false;

    witver = data[0];
    if (witver > 16) return false;
    if (witver == 0 && !is_b) return false;   // v0 mora biti bech32
    if (witver > 0 && !is_m) return false;    // v1+ mora biti bech32m

    std::vector<unsigned char> payload(data.begin() + 1, data.end() - 6);
    if (!convert_bits(payload, 5, 8, false, program)) return false;
    return true;
}
} // namespace bech32

// segwit v1 (taproot) adresa
inline bool taproot_address(const std::string& hrp, const unsigned char output_key[32], std::string& out) {
    std::vector<unsigned char> prog(output_key, output_key + 32);
    return bech32::encode(hrp, 1, prog, out);
}

} // namespace bec
