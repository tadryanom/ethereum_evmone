// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <evmc/mocked_host.hpp>
#include <gtest/gtest.h>
#include <cstring>

using State = std::map<evmc::address, evmc::MockedAccount>;

using namespace evmc::literals;


inline bool operator==(const evmc::bytes32& a, const ethash::hash256& b) noexcept
{
    return std::memcmp(a.bytes, b.bytes, sizeof(a)) == 0;
}

namespace
{
constexpr auto emptyStorageTrieHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

constexpr auto emptyCodeHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;

evmc::bytes rlp_encode(const evmc::bytes32& b)
{
    size_t i = 0;
    for (; i < sizeof(b); ++i)
    {
        if (b.bytes[i] != 0)
            break;
    }
    size_t l = 32 - i;
    if (l == 0)
        return {uint8_t{0x80}};
    if (l == 1 && b.bytes[31] <= 0x7f)
        return {static_cast<uint8_t>(b.bytes[31])};
    evmc::bytes r{static_cast<uint8_t>(0x80 + l)};
    r.append(&b.bytes[i], l);
    return r;
}

evmc::bytes rlp_encode_len(size_t l)
{
    assert(l > 0x37);
    assert(l <= 0xff);
    return {static_cast<uint8_t>(l)};
}

evmc::bytes rlp_encode(const evmc::MockedAccount& a)
{
    const auto n = rlp_encode(evmc::bytes32{static_cast<uint64_t>(a.nonce)});
    const auto b = rlp_encode(a.balance);
    const auto s = rlp_encode(emptyStorageTrieHash);
    const auto c = rlp_encode(emptyCodeHash);
    const auto l = n.size() + b.size() + s.size() + c.size();
    const auto le = rlp_encode_len(l);
    evmc::bytes r{static_cast<uint8_t>(0xf7 + le.size())};
    r += le + n + b + s + c;
    return r;
}

ethash::hash256 compute_state_root(const State& state)
{
    (void)state;
    return {};
}
}  // namespace


TEST(state, empty_code_hash)
{
    const auto empty = ethash::keccak256(nullptr, 0);
    EXPECT_EQ(evmc::hex({empty.bytes, sizeof(empty)}),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    EXPECT_EQ(emptyCodeHash, empty);
}

TEST(state, rlp_v1)
{
    const auto expected = evmc::from_hex(
        "f8 44"
        "80"
        "01"
        "a0 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        "a0 c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    evmc::MockedAccount a;
    a.balance.bytes[31] = 1;
    EXPECT_EQ(evmc::hex(rlp_encode(a)), evmc::hex(expected));
}

TEST(state, v1)
{
    // Expected value computed in go-ethereum.

    State state;
    state[0x0000000000000000000000000000000000000002_address].balance.bytes[31] = 1;

    const auto r = compute_state_root(state);
    EXPECT_EQ(evmc::hex({r.bytes, sizeof(r)}),
        "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");
}
