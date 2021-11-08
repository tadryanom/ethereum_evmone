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

inline bool operator==(const ethash::hash256& a, const evmc::bytes32& b) noexcept
{
    return b == a;
}


namespace
{
constexpr auto emptyStorageTrieHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

constexpr auto emptyCodeHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;

evmc::bytes rlp_encode_str(evmc::bytes_view data)
{
    assert(data.size() >= 2);
    assert(data.size() > 55);
    assert(data.size() <= 0xff);
    return evmc::bytes{0xb7 + 1, static_cast<uint8_t>(data.size())} + evmc::bytes{data};
}

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

evmc::bytes rlp_encode_list(const evmc::bytes& a, const evmc::bytes& b)
{
    const auto l = static_cast<uint8_t>(a.size() + b.size());
    return evmc::bytes{0xf8, l} + a + b;
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

evmc::bytes build_leaf_node(const evmc::address& address, const evmc::MockedAccount& account)
{
    const auto path = ethash::keccak256(address.bytes, sizeof(address));
    const auto encoded_path = evmc::bytes{0x20} + evmc::bytes{path.bytes, sizeof(path)};
    const auto rlp_encoded_path =
        evmc::bytes{static_cast<uint8_t>(0x80 + encoded_path.length())} + encoded_path;
    const auto value = rlp_encode(account);
    const auto rlp_value = rlp_encode_str(value);  // Although value is RLP, treat it as bytes.
    auto node = rlp_encode_list(rlp_encoded_path, rlp_value);
    return node;
}

ethash::hash256 hash_leaf_node(const evmc::address& address, const evmc::MockedAccount& account)
{
    const auto node = build_leaf_node(address, account);
    return ethash::keccak256(node.data(), node.size());
}


[[maybe_unused]] ethash::hash256 compute_state_root(const State& state)
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
    EXPECT_EQ(rlp_encode(a).size(), 70);
}

TEST(state, empty_trie)
{
    const uint8_t rlp_null = 0x80;
    const auto empty_trie_hash = ethash::keccak256(&rlp_null, 1);
    EXPECT_EQ(empty_trie_hash, emptyStorageTrieHash);
}

TEST(state, hashed_address)
{
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    const auto hashed_addr = ethash::keccak256(addr.bytes, sizeof(addr));
    EXPECT_EQ(evmc::hex({hashed_addr.bytes, sizeof(hashed_addr)}),
        "d52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62");
}

TEST(state, build_leaf_node)
{
    State state;
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    state[addr].balance.bytes[31] = 1;
    const auto node = build_leaf_node(addr, state[addr]);
    EXPECT_EQ(evmc::hex(node),
        "f86aa120d52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62b846f8448001a056e8"
        "1f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc7"
        "03c0e500b653ca82273b7bfad8045d85a470");
}

TEST(state, single_account_v1)
{
    // Expected value computed in go-ethereum.

    State state;
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    state[addr].balance.bytes[31] = 1;

    const auto h = hash_leaf_node(addr, state[addr]);
    EXPECT_EQ(evmc::hex({h.bytes, sizeof(h)}),
        "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");
}
