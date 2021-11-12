// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <ethash/keccak.hpp>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <evmc/mocked_host.hpp>
#include <gtest/gtest.h>
#include <cstring>

// Better API and utils
// ====================

using evmc::bytes;
using evmc::bytes_view;
using namespace evmc::literals;

/// Better than ethash::hash256 because has some additional handy constructors.
using hash256 = evmc::bytes32;

inline bool operator==(const hash256& a, const ethash::hash256& b) noexcept
{
    return std::memcmp(a.bytes, b.bytes, sizeof(a)) == 0;
}

inline bool operator==(const ethash::hash256& a, const hash256& b) noexcept
{
    return b == a;
}

inline auto keccak256(bytes_view data) noexcept
{
    return ethash::keccak256(std::data(data), std::size(data));
}

inline auto keccak256(const evmc::address& addr) noexcept
{
    return ethash::keccak256(addr.bytes, std::size(addr.bytes));
}

using evmc::address;
using evmc::from_hex;
using evmc::hex;
using Account = evmc::MockedAccount;

inline auto hex(const ethash::hash256& h) noexcept
{
    return hex({h.bytes, std::size(h.bytes)});
}


// Temporary needed up here to hock RLP encoding of an Account.
constexpr auto emptyStorageTrieHash =
    0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32;

constexpr auto emptyCodeHash =
    0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32;


// RLP
// ===

namespace rlp
{
inline bytes string(bytes_view data)
{
    const auto l = std::size(data);
    if (l == 1 && data[0] <= 0x7f)
        return bytes{data[0]};
    if (l <= 55)
        return bytes{static_cast<uint8_t>(0x80 + l)} + bytes{data};

    // FIXME: Should it skip zero bytes?
    assert(data.size() <= 0xff);
    return bytes{0xb7 + 1, static_cast<uint8_t>(l)} + bytes{data};
}

inline bytes string(const hash256& b)
{
    size_t i = 0;
    for (; i < sizeof(b); ++i)
    {
        if (b.bytes[i] != 0)
            break;
    }
    const size_t l = sizeof(b) - i;
    return string({&b.bytes[i], l});
}

inline bytes string(int x)
{
    // TODO: Account::nonce should be uint64_t.
    uint8_t b[sizeof(x)];
    const auto be = __builtin_bswap32(static_cast<unsigned>(x));
    __builtin_memcpy(b, &be, sizeof(be));

    size_t i = 0;
    for (; i < sizeof(b); ++i)
    {
        if (b[i] != 0)
            break;
    }
    const size_t l = sizeof(b) - i;
    return string({&b[i], l});
}

template <typename... Items>
inline bytes list(const Items&... items)
{
    const bytes string_items[] = {string(items)...};
    size_t items_len = 0;
    for (const auto& s : string_items)
        items_len += std::size(s);
    assert(items_len > 55);
    assert(items_len <= 0xff);
    auto r = bytes{0xf7 + 1, static_cast<uint8_t>(items_len)};
    for (const auto& s : string_items)
        r += s;
    return r;
}

bytes encode(const Account& a)
{
    assert(a.storage.empty());
    assert(a.code.empty());
    return rlp::list(a.nonce, a.balance, emptyStorageTrieHash, emptyCodeHash);
}
}  // namespace rlp


// State Trie
// ==========

namespace
{
using State = std::map<address, Account>;
bytes build_leaf_node(const address& addr, const Account& account)
{
    const auto path = keccak256(addr);
    const auto encoded_path = bytes{0x20} + bytes{path.bytes, sizeof(path)};
    const auto value = rlp::encode(account);  // Double RLP encoding.
    return rlp::list(encoded_path, value);
}

ethash::hash256 hash_leaf_node(const address& addr, const Account& account)
{
    const auto node = build_leaf_node(addr, account);
    return keccak256(node);
}


[[maybe_unused]] ethash::hash256 compute_state_root(const State& state)
{
    (void)state;
    return {};
}
}  // namespace


TEST(state, empty_code_hash)
{
    const auto empty = keccak256(bytes_view{});
    EXPECT_EQ(hex(empty), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    EXPECT_EQ(emptyCodeHash, empty);
}

TEST(state, rlp_v1)
{
    const auto expected = from_hex(
        "f8 44"
        "80"
        "01"
        "a0 56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        "a0 c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

    evmc::MockedAccount a;
    a.balance.bytes[31] = 1;
    EXPECT_EQ(hex(rlp::encode(a)), hex(expected));
    EXPECT_EQ(rlp::encode(a).size(), 70);
}

TEST(state, empty_trie)
{
    const auto rlp_null = bytes{0x80};
    const auto empty_trie_hash = keccak256(rlp_null);
    EXPECT_EQ(empty_trie_hash, emptyStorageTrieHash);
}

TEST(state, hashed_address)
{
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    const auto hashed_addr = keccak256(addr);
    EXPECT_EQ(hex(hashed_addr), "d52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62");
}

TEST(state, build_leaf_node)
{
    State state;
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    state[addr].balance.bytes[31] = 1;
    const auto node = build_leaf_node(addr, state[addr]);
    EXPECT_EQ(hex(node),
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
    EXPECT_EQ(hex(h), "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");
}
