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

inline hash256 keccak256(bytes_view data) noexcept
{
    const auto eh = ethash::keccak256(std::data(data), std::size(data));
    hash256 h;
    std::memcpy(h.bytes, eh.bytes, sizeof(h));
    return h;
}

inline hash256 keccak256(const evmc::address& addr) noexcept
{
    return keccak256({addr.bytes, sizeof(addr)});
}

inline hash256 keccak256(const evmc::bytes32& h) noexcept
{
    return keccak256({h.bytes, sizeof(h)});
}

using evmc::address;
using evmc::from_hex;
using evmc::hex;
using Account = evmc::MockedAccount;

inline auto hex(const hash256& h) noexcept
{
    return hex({h.bytes, std::size(h.bytes)});
}

inline bytes to_bytes(std::string_view s)
{
    bytes b;
    b.reserve(std::size(s));
    for (const auto c : s)
        b.push_back(static_cast<uint8_t>(c));
    return b;
}


// Temporary needed up here to hock RLP encoding of an Account.
constexpr auto emptyTrieHash =
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

    assert(data.size() <= 0xff);
    return bytes{0xb7 + 1, static_cast<uint8_t>(l)} + bytes{data};
}

inline bytes_view trim(const evmc::uint256be& v)
{
    size_t i = 0;
    for (; i < sizeof(v); ++i)
    {
        if (v.bytes[i] != 0)
            break;
    }
    const size_t l = sizeof(v) - i;
    return {&v.bytes[i], l};
}

inline bytes string(const hash256& b)
{
    return string({b.bytes, sizeof(b)});
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
    assert(items_len <= 0xff);
    auto r = (items_len <= 55) ? bytes{static_cast<uint8_t>(0xc0 + items_len)} :
                                 bytes{0xf7 + 1, static_cast<uint8_t>(items_len)};
    for (const auto& s : string_items)
        r += s;
    return r;
}

bytes encode(const Account& a)
{
    assert(a.storage.empty());
    assert(a.code.empty());
    return rlp::list(a.nonce, rlp::trim(a.balance), emptyTrieHash, emptyCodeHash);
}
}  // namespace rlp


// State Trie
// ==========

namespace
{
/// Trie path (key)
struct Path
{
    size_t num_nibbles;  // TODO: Can be converted to uint8_t.
    uint8_t nibbles[64];

    explicit Path(bytes_view k) noexcept : num_nibbles(2 * std::size(k))
    {
        assert(num_nibbles <= 64);
        size_t i = 0;
        for (const auto b : k)
        {
            nibbles[i++] = b >> 4;
            nibbles[i++] = b & 0x0f;
        }
    }

    [[nodiscard]] uint8_t nibble(size_t index) const
    {
        assert(index < num_nibbles);
        return nibbles[index];
    }

    Path tail(size_t index) const
    {
        assert(index <= num_nibbles);
        Path p{{}};
        p.num_nibbles = num_nibbles - index;
        std::memcpy(p.nibbles, &nibbles[index], p.num_nibbles);
        return p;
    }

    Path head(size_t size) const
    {
        assert(size < num_nibbles);
        Path p{{}};
        p.num_nibbles = size;
        std::memcpy(p.nibbles, nibbles, size);
        return p;
    }

    [[nodiscard]] bytes encode(bool extended) const
    {
        bytes bs;
        const auto is_even = num_nibbles % 2 == 0;
        if (is_even)
            bs.push_back(0x00);
        else
            bs.push_back(0x10 | nibbles[0]);
        for (size_t i = is_even ? 0 : 1; i < num_nibbles; ++i)
        {
            const auto h = nibbles[i++];
            const auto l = nibbles[i];
            assert(h <= 0x0f);
            assert(l <= 0x0f);
            bs.push_back(uint8_t((h << 4) | l));
        }
        if (!extended)
            bs[0] |= 0x20;
        return bs;
    }
};

inline Path common_prefix(const Path& p, const Path& q)
{
    assert(p.num_nibbles == q.num_nibbles);
    Path r{{}};
    for (size_t i = 0; i < p.num_nibbles; ++i)
    {
        if (p.nibbles[i] != q.nibbles[i])
            break;
        ++r.num_nibbles;
        r.nibbles[i] = p.nibbles[i];
    }
    return r;
}

struct BranchNode
{
    hash256 items[16]{};
    void insert(uint8_t nibble, const hash256& value) { items[nibble] = value; }

    [[nodiscard]] bytes rlp() const
    {
        const auto f = [](const hash256& h) {
            return (h != hash256{}) ? bytes_view{h.bytes, sizeof(h)} : bytes_view{};
        };

        return rlp::list(f(items[0]), f(items[1]), f(items[2]), f(items[3]), f(items[4]),
            f(items[5]), f(items[6]), f(items[7]), f(items[8]), f(items[9]), f(items[10]),
            f(items[11]), f(items[12]), f(items[13]), f(items[14]), f(items[15]), bytes_view{});
    }

    [[nodiscard]] hash256 hash() const { return keccak256(rlp()); }
};

class Trie
{
    std::map<bytes, bytes> m_map;

public:
    static bytes build_leaf_node(bytes_view path, bytes_view value)
    {
        const auto encoded_path = bytes{0x20} + bytes{path};
        return rlp::list(encoded_path, value);
    }

    void insert(bytes k, bytes v) { m_map[std::move(k)] = std::move(v); }

    /// Helper
    void insert(hash256 k, bytes v) { insert(bytes{k.bytes, sizeof(k)}, std::move(v)); }

    [[nodiscard]] hash256 get_root_hash() const
    {
        const auto size = std::size(m_map);
        if (size == 0)
            return emptyTrieHash;
        else if (size == 1)
        {
            const auto& [k, v] = *m_map.begin();
            return keccak256(build_leaf_node(k, v));
        }

        return {};
    }
};

using State = std::map<address, Account>;
bytes build_leaf_node(const address& addr, const Account& account)
{
    const auto path = keccak256(addr);
    const auto encoded_path = bytes{0x20} + bytes{path.bytes, sizeof(path)};
    const auto value = rlp::encode(account);  // Double RLP encoding.
    return rlp::list(encoded_path, value);
}

bytes build_leaf_node(const hash256& key, bytes_view value)
{
    const auto encoded_path = bytes{0x20} + bytes{key.bytes, sizeof(key)};
    return rlp::list(encoded_path, value);
}

hash256 hash_leaf_node(const address& addr, const Account& account)
{
    const auto node = build_leaf_node(addr, account);
    return keccak256(node);
}

enum class NodeType
{
    null,
    leaf,
    ext,
    branch
};

struct StackTrie
{
    NodeType nodeType{NodeType::null};
    bytes val;
    Path key{{}};
    size_t keyOffset = 0;
    std::unique_ptr<StackTrie> children[16];

    /// Named constructor for a leaf node.
    static StackTrie leaf(size_t ko, const Path& k, bytes_view v)
    {
        return {NodeType::leaf, bytes{v}, k.tail(ko), ko, {}};
    }

    /// Named constructor for an extended node.
    static StackTrie ext(size_t ko, const Path& k, std::unique_ptr<StackTrie> child)
    {
        return {NodeType::ext, {}, k.tail(ko), ko, {std::move(child)}};
    }

    size_t getDiffIndex(const Path& k)
    {
        size_t diffindex = 0;
        for (; diffindex < key.num_nibbles &&
               key.nibbles[diffindex] == k.nibbles[keyOffset + diffindex];
             diffindex++)
        {}
        return diffindex;
    }

    void insert(const Path& k, bytes_view v)
    {
        switch (nodeType)
        {
        case NodeType::null:
            assert(keyOffset == 0);
            *this = leaf(keyOffset, k, v);
            break;

        case NodeType::branch:
        {
            const auto idx = k.nibbles[keyOffset];
            auto& child = children[idx];
            if (!child)
                child = std::make_unique<StackTrie>(leaf(keyOffset + 1, k, v));
            else
                child->insert(k, v);
            break;
        }

        case NodeType::ext:
        {
            const auto diffidx = getDiffIndex(k);

            if (diffidx == key.num_nibbles)
            {
                // Go into child.
                return children[0]->insert(k, v);
            }

            std::unique_ptr<StackTrie> n;
            if (diffidx < key.num_nibbles - 1)
                n = std::make_unique<StackTrie>(ext(diffidx + 1, key, std::move(children[0])));
            else
                n = std::move(children[0]);

            StackTrie* branch = nullptr;
            if (diffidx == 0)
            {
                branch = this;
                branch->nodeType = NodeType::branch;
            }
            else
            {
                branch = (children[0] = std::make_unique<StackTrie>()).get();
                branch->nodeType = NodeType::branch;
                branch->keyOffset = keyOffset + diffidx;
            }

            const auto origIdx = key.nibbles[diffidx];
            const auto newIdx = k.nibbles[diffidx + keyOffset];

            branch->children[origIdx] = std::move(n);
            branch->children[newIdx] =
                std::make_unique<StackTrie>(leaf(keyOffset + diffidx + 1, k, v));
            key = key.head(diffidx);
            break;
        }

        case NodeType::leaf:
        {
            // TODO: Add assert for k == key.
            const auto diffidx = getDiffIndex(k);

            StackTrie* branch = nullptr;
            if (diffidx == 0)  // Convert into a branch.
            {
                nodeType = NodeType::branch;
                branch = this;
            }
            else
            {
                nodeType = NodeType::ext;
                branch = (children[0] = std::make_unique<StackTrie>()).get();
                branch->nodeType = NodeType::branch;
                branch->keyOffset = keyOffset + diffidx;
            }

            const auto origIdx = key.nibbles[diffidx];
            branch->children[origIdx] = std::make_unique<StackTrie>(leaf(diffidx + 1, key, val));

            const auto newIdx = k.nibbles[diffidx + keyOffset];
            assert(origIdx != newIdx);
            branch->children[newIdx] =
                std::make_unique<StackTrie>(leaf(branch->keyOffset + 1, k, v));

            key = key.head(diffidx);
            val = {};
            break;
        }

        default:
            assert(false);
        }
    }

    [[nodiscard]] hash256 hash() const
    {
        hash256 r{};
        switch (nodeType)
        {
        case NodeType::null:
            return emptyTrieHash;
        case NodeType::leaf:
        {
            const auto node = rlp::list(key.encode(false), val);
            r = keccak256(node);
            break;
        }
        case NodeType::branch:
        {
            BranchNode node;
            for (uint8_t i = 0; i < std::size(children); ++i)
            {
                if (children[i])
                    node.insert(i, children[i]->hash());
            }
            r = node.hash();
            break;
        }
        case NodeType::ext:
        {
            const auto branch = children[0].get();
            assert(branch != nullptr);
            assert(branch->nodeType == NodeType::branch);
            r = keccak256(rlp::list(key.encode(true), branch->hash()));
            break;
        }
        default:
            assert(false);
        }

        // std::cout << hex(bytes_view{key.nibbles, key.num_nibbles}) << ": " << hex(r) << "\n";
        return r;
    }
};

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

    Account a;
    a.set_balance(1);
    EXPECT_EQ(hex(rlp::encode(a)), hex(expected));
    EXPECT_EQ(rlp::encode(a).size(), 70);

    EXPECT_EQ(hex(rlp::string(0x31)), "31");
}

TEST(state, empty_trie)
{
    const auto rlp_null = bytes{0x80};
    const auto empty_trie_hash = keccak256(rlp_null);
    EXPECT_EQ(empty_trie_hash, emptyTrieHash);

    StackTrie trie;
    EXPECT_EQ(trie.hash(), emptyTrieHash);
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
    state[addr].set_balance(1);
    const auto node = build_leaf_node(addr, state[addr]);
    EXPECT_EQ(hex(node),
        "f86aa120d52688a8f926c816ca1e079067caba944f158e764817b83fc43594370ca9cf62b846f8448001a056e8"
        "1f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc7"
        "03c0e500b653ca82273b7bfad8045d85a470");
}

TEST(state, single_account_v1)
{
    // Expected value computed in go-ethereum.

    Account a;
    const auto addr = 0x0000000000000000000000000000000000000002_address;
    a.set_balance(1);

    const auto h = hash_leaf_node(addr, a);
    EXPECT_EQ(hex(h), "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");

    Trie trie;
    trie.insert(keccak256(addr), rlp::encode(a));
    EXPECT_EQ(hex(trie.get_root_hash()),
        "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");

    StackTrie st;
    const auto xkey = keccak256(addr);
    const auto xval = rlp::encode(a);
    st.insert(Path{{xkey.bytes, sizeof(xkey)}}, xval);
    EXPECT_EQ(hex(st.hash()), "084f337237951e425716a04fb0aaa74111eda9d9c61767f2497697d0a201c92e");
}

TEST(state, storage_trie_v1)
{
    const auto key = 0_bytes32;
    const auto value = 0x00000000000000000000000000000000000000000000000000000000000001ff_bytes32;
    const auto xkey = keccak256(key);
    const auto xvalue = rlp::string(rlp::trim(value));
    const auto node = build_leaf_node(xkey, xvalue);
    EXPECT_EQ(hex(node),
        "e6a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563838201ff");
    const auto root = keccak256(node);
    EXPECT_EQ(hex(root), "d9aa83255221f68fdd4931f73f8fe6ea30c191a9619b5fc60ce2914eee1e7e54");

    StackTrie st;
    st.insert(Path{{xkey.bytes, sizeof(xkey)}}, xvalue);
    EXPECT_EQ(hex(st.hash()), "d9aa83255221f68fdd4931f73f8fe6ea30c191a9619b5fc60ce2914eee1e7e54");
}

TEST(state, trie_ex1)
{
    StackTrie trie;
    const auto k = to_bytes("\x01\x02\x03");
    const auto v = to_bytes("hello");
    EXPECT_EQ(hex(Trie::build_leaf_node(k, v)), "cb84200102038568656c6c6f");
    trie.insert(Path{k}, v);
    EXPECT_EQ(hex(trie.hash()), "82c8fd36022fbc91bd6b51580cfd941d3d9994017d59ab2e8293ae9c94c3ab6e");
}

TEST(state, trie_branch_node)
{
    Trie trie;
    const auto k1 = to_bytes("A");
    const auto k2 = to_bytes("z");
    const auto v1 = to_bytes("v___________________________1");
    const auto v2 = to_bytes("v___________________________2");

    const auto p1 = Path(k1);
    const auto p2 = Path(k2);
    EXPECT_EQ(common_prefix(p1, p2).num_nibbles, 0);
    const auto n1 = p1.nibble(0);
    const auto n2 = p2.nibble(0);
    EXPECT_EQ(n1, 4);
    EXPECT_EQ(n2, 7);

    const auto lp1 = p1.tail(1);
    EXPECT_EQ(hex(lp1.encode(false)), "31");
    const auto lp2 = p2.tail(1);
    EXPECT_EQ(hex(lp2.encode(false)), "3a");

    const auto node1 = rlp::list(lp1.encode(false), v1);
    EXPECT_EQ(hex(node1), "df319d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31");
    const auto node2 = rlp::list(lp2.encode(false), v2);


    BranchNode branch;
    branch.insert(n1, keccak256(node1));
    branch.insert(n2, keccak256(node2));
    EXPECT_EQ(hex(branch.rlp()),
        "f85180808080a05806d69cca87e01a0e7567781f037a6e86cdc72dff63366b000d7e00eedd36478080a0ddcda2"
        "25116d4479645995715b72cc33ab2ac7229345297556354ff6baa5a7e5808080808080808080");
    EXPECT_EQ(
        hex(branch.hash()), "56e911635579e0f86dce3c116af12b30448e01cc634aac127e037efbd29e7f9f");

    StackTrie st;
    st.insert(Path{k1}, v1);
    st.insert(Path{k2}, v2);
    EXPECT_EQ(hex(st.hash()), "56e911635579e0f86dce3c116af12b30448e01cc634aac127e037efbd29e7f9f");
}

TEST(state, trie_extension_node)
{
    Trie trie;
    const auto k1 = to_bytes("XXA");
    const auto k2 = to_bytes("XXZ");
    const auto v1 = to_bytes("v___________________________1");
    const auto v2 = to_bytes("v___________________________2");

    const auto p1 = Path(k1);
    const auto p2 = Path(k2);
    const auto common_p = common_prefix(p1, p2);
    EXPECT_EQ(common_p.num_nibbles, 4);
    const auto n1 = p1.nibble(common_p.num_nibbles);
    const auto n2 = p2.nibble(common_p.num_nibbles);
    EXPECT_EQ(n1, 4);
    EXPECT_EQ(n2, 5);

    const auto hp1 = p1.tail(common_p.num_nibbles + 1);
    EXPECT_EQ(hex(hp1.encode(false)), "31");
    const auto hp2 = p2.tail(common_p.num_nibbles + 1);

    const auto node1 = rlp::list(hp1.encode(false), v1);
    EXPECT_EQ(hex(node1), "df319d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31");
    const auto node2 = rlp::list(hp2.encode(false), v2);


    BranchNode branch;
    branch.insert(n1, keccak256(node1));
    branch.insert(n2, keccak256(node2));
    EXPECT_EQ(hex(branch.rlp()),
        "f85180808080a05806d69cca87e01a0e7567781f037a6e86cdc72dff63366b000d7e00eedd3647a0ddcda22511"
        "6d4479645995715b72cc33ab2ac7229345297556354ff6baa5a7e58080808080808080808080");
    EXPECT_EQ(
        hex(branch.hash()), "1aaa6f712413b9a115730852323deb5f5d796c29151a60a1f55f41a25354cd26");

    const auto ext = rlp::list(common_p.encode(true), branch.hash());
    EXPECT_EQ(
        hex(keccak256(ext)), "3eefc183db443d44810b7d925684eb07256e691d5c9cb13215660107121454f9");

    StackTrie st;
    st.insert(p1, v1);
    st.insert(p2, v2);
    EXPECT_EQ(hex(st.hash()), "3eefc183db443d44810b7d925684eb07256e691d5c9cb13215660107121454f9");
}


TEST(state, trie_extension_node2)
{
    Trie trie;
    const auto k1 = to_bytes("XXA");
    const auto k2 = to_bytes("XYZ");
    const auto v1 = to_bytes("v___________________________1");
    const auto v2 = to_bytes("v___________________________2");

    const auto p1 = Path(k1);
    const auto p2 = Path(k2);
    const auto prefix = common_prefix(p1, p2);

    const auto n1 = p1.nibble(prefix.num_nibbles);
    const auto n2 = p2.nibble(prefix.num_nibbles);
    EXPECT_EQ(n1, 8);
    EXPECT_EQ(n2, 9);

    const auto hp1 = p1.tail(prefix.num_nibbles + 1);
    EXPECT_EQ(hex(hp1.encode(false)), "2041");
    const auto hp2 = p2.tail(prefix.num_nibbles + 1);

    const auto node1 = rlp::list(hp1.encode(false), v1);
    EXPECT_EQ(hex(node1), "e18220419d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f31");
    const auto node2 = rlp::list(hp2.encode(false), v2);
    EXPECT_EQ(hex(node2), "e182205a9d765f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f32");

    BranchNode branch;
    branch.insert(n1, keccak256(node1));
    branch.insert(n2, keccak256(node2));
    EXPECT_EQ(hex(branch.rlp()),
        "f8518080808080808080a030afaabf307606fe3b9afa75de1e2b3ff5a735ec7c4d78c48dfefbcb88b4553da075"
        "a7752e1452fb347efd915ff49f693793d396f9b205fb989f7f2a927da7baf780808080808080");
    EXPECT_EQ(
        hex(branch.hash()), "01746f8ab5a4cc5d6175cbd9ea9603357634ec06b2059f90710243f098e0ee82");

    const auto ext = rlp::list(prefix.encode(true), branch.hash());
    EXPECT_EQ(
        hex(keccak256(ext)), "ac28c08fa3ff1d0d2cc9a6423abb7af3f4dcc37aa2210727e7d3009a9b4a34e8");

    StackTrie st;
    st.insert(p1, v1);
    st.insert(p2, v2);
    EXPECT_EQ(hex(st.hash()), "ac28c08fa3ff1d0d2cc9a6423abb7af3f4dcc37aa2210727e7d3009a9b4a34e8");
}

TEST(state, trie_3keys_topologies)
{
    struct KVH
    {
        const char* key_hex;
        const char* value;
        const char* hash_hex;
    };

    // clang-format off
    KVH tests[][3] = {
        { // {0:0, 7:0, f:0}
            {"00", "v_______________________0___0", "5cb26357b95bb9af08475be00243ceb68ade0b66b5cd816b0c18a18c612d2d21"},
            {"70", "v_______________________0___1", "8ff64309574f7a437a7ad1628e690eb7663cfde10676f8a904a8c8291dbc1603"},
            {"f0", "v_______________________0___2", "9e3a01bd8d43efb8e9d4b5506648150b8e3ed1caea596f84ee28e01a72635470"},
        },
        { // {1:0cc, e:{1:fc, e:fc}}
            {"10cc", "v_______________________1___0", "233e9b257843f3dfdb1cce6676cdaf9e595ac96ee1b55031434d852bc7ac9185"},
            {"e1fc", "v_______________________1___1", "39c5e908ae83d0c78520c7c7bda0b3782daf594700e44546e93def8f049cca95"},
            {"eefc", "v_______________________1___2", "d789567559fd76fe5b7d9cc42f3750f942502ac1c7f2a466e2f690ec4b6c2a7c"},
        },
        { // {1:0cc, e:{1:fc, e:fc}}
            {"10cc", "v_______________________1___0", "233e9b257843f3dfdb1cce6676cdaf9e595ac96ee1b55031434d852bc7ac9185"},
            {"e1fc", "v_______________________1___1", "39c5e908ae83d0c78520c7c7bda0b3782daf594700e44546e93def8f049cca95"},
            {"eefc", "v_______________________1___2", "d789567559fd76fe5b7d9cc42f3750f942502ac1c7f2a466e2f690ec4b6c2a7c"},
        },
        { // {b:{a:ac, b:ac}, d:acc}
            {"baac", "v_______________________2___0", "8be1c86ba7ec4c61e14c1a9b75055e0464c2633ae66a055a24e75450156a5d42"},
            {"bbac", "v_______________________2___1", "8495159b9895a7d88d973171d737c0aace6fe6ac02a4769fff1bc43bcccce4cc"},
            {"dacc", "v_______________________2___2", "9bcfc5b220a27328deb9dc6ee2e3d46c9ebc9c69e78acda1fa2c7040602c63ca"},
        },
        { // {0:0cccc, 2:456{0:0, 2:2}
            {"00cccc", "v_______________________3___0", "e57dc2785b99ce9205080cb41b32ebea7ac3e158952b44c87d186e6d190a6530"},
            {"245600", "v_______________________3___1", "0335354adbd360a45c1871a842452287721b64b4234dfe08760b243523c998db"},
            {"245622", "v_______________________3___2", "9e6832db0dca2b5cf81c0e0727bfde6afc39d5de33e5720bccacc183c162104e"},
        },
        { // {1:4567{1:1c, 3:3c}, 3:0cccccc}
            {"1456711c", "v_______________________4___0", "f2389e78d98fed99f3e63d6d1623c1d4d9e8c91cb1d585de81fbc7c0e60d3529"},
            {"1456733c", "v_______________________4___1", "101189b3fab852be97a0120c03d95eefcf984d3ed639f2328527de6def55a9c0"},
            {"30cccccc", "v_______________________4___2", "3780ce111f98d15751dfde1eb21080efc7d3914b429e5c84c64db637c55405b3"},
        },
        { // 8800{1:f, 2:e, 3:d}
            {"88001f", "v_______________________5___0", "e817db50d84f341d443c6f6593cafda093fc85e773a762421d47daa6ac993bd5"},
            {"88002e", "v_______________________5___1", "d6e3e6047bdc110edd296a4d63c030aec451bee9d8075bc5a198eee8cda34f68"},
            {"88003d", "v_______________________5___2", "b6bdf8298c703342188e5f7f84921a402042d0e5fb059969dd53a6b6b1fb989e"},
        },
        { // 0{1:fc, 2:ec, 4:dc}
            {"01fc", "v_______________________6___0", "693268f2ca80d32b015f61cd2c4dba5a47a6b52a14c34f8e6945fad684e7a0d5"},
            {"02ec", "v_______________________6___1", "e24ddd44469310c2b785a2044618874bf486d2f7822603a9b8dce58d6524d5de"},
            {"04dc", "v_______________________6___2", "33fc259629187bbe54b92f82f0cd8083b91a12e41a9456b84fc155321e334db7"},
        },
        { // f{0:fccc, f:ff{0:f, f:f}}
            {"f0fccc", "v_______________________7___0", "b0966b5aa469a3e292bc5fcfa6c396ae7a657255eef552ea7e12f996de795b90"},
            {"ffff0f", "v_______________________7___1", "3b1ca154ec2a3d96d8d77bddef0abfe40a53a64eb03cecf78da9ec43799fa3d0"},
            {"ffffff", "v_______________________7___2", "e75463041f1be8252781be0ace579a44ea4387bf5b2739f4607af676f7719678"},
        },
        { // ff{0:f{0:f, f:f}, f:fcc}
            {"ff0f0f", "v_______________________8___0", "0928af9b14718ec8262ab89df430f1e5fbf66fac0fed037aff2b6767ae8c8684"},
            {"ff0fff", "v_______________________8___1", "d870f4d3ce26b0bf86912810a1960693630c20a48ba56be0ad04bc3e9ddb01e6"},
            {"ffffcc", "v_______________________8___2", "4239f10dd9d9915ecf2e047d6a576bdc1733ed77a30830f1bf29deaf7d8e966f"},
        },
        {
            {"123d", "x___________________________0", "fc453d88b6f128a77c448669710497380fa4588abbea9f78f4c20c80daa797d0"},
            {"123e", "x___________________________1", "5af48f2d8a9a015c1ff7fa8b8c7f6b676233bd320e8fb57fd7933622badd2cec"},
            {"123f", "x___________________________2", "1164d7299964e74ac40d761f9189b2a3987fae959800d0f7e29d3aaf3eae9e15"},
        },
        {
            {"123d", "x___________________________0", "fc453d88b6f128a77c448669710497380fa4588abbea9f78f4c20c80daa797d0"},
            {"123e", "x___________________________1", "5af48f2d8a9a015c1ff7fa8b8c7f6b676233bd320e8fb57fd7933622badd2cec"},
            {"124a", "x___________________________2", "661a96a669869d76b7231380da0649d013301425fbea9d5c5fae6405aa31cfce"},
        },
        {
            {"123d", "x___________________________0", "fc453d88b6f128a77c448669710497380fa4588abbea9f78f4c20c80daa797d0"},
            {"123e", "x___________________________1", "5af48f2d8a9a015c1ff7fa8b8c7f6b676233bd320e8fb57fd7933622badd2cec"},
            {"13aa", "x___________________________2", "6590120e1fd3ffd1a90e8de5bb10750b61079bb0776cca4414dd79a24e4d4356"},
        },
        {
            {"123d", "x___________________________0", "fc453d88b6f128a77c448669710497380fa4588abbea9f78f4c20c80daa797d0"},
            {"123e", "x___________________________1", "5af48f2d8a9a015c1ff7fa8b8c7f6b676233bd320e8fb57fd7933622badd2cec"},
            {"2aaa", "x___________________________2", "f869b40e0c55eace1918332ef91563616fbf0755e2b946119679f7ef8e44b514"},
        },
        {
            {"1234da", "x___________________________0", "1c4b4462e9f56a80ca0f5d77c0d632c41b0102290930343cf1791e971a045a79"},
            {"1234ea", "x___________________________1", "2f502917f3ba7d328c21c8b45ee0f160652e68450332c166d4ad02d1afe31862"},
            {"1234fa", "x___________________________2", "4f4e368ab367090d5bc3dbf25f7729f8bd60df84de309b4633a6b69ab66142c0"},
        },
        {
            {"1234da", "x___________________________0", "1c4b4462e9f56a80ca0f5d77c0d632c41b0102290930343cf1791e971a045a79"},
            {"1234ea", "x___________________________1", "2f502917f3ba7d328c21c8b45ee0f160652e68450332c166d4ad02d1afe31862"},
            {"1235aa", "x___________________________2", "21840121d11a91ac8bbad9a5d06af902a5c8d56a47b85600ba813814b7bfcb9b"},
        },
        {
            {"1234da", "x___________________________0", "1c4b4462e9f56a80ca0f5d77c0d632c41b0102290930343cf1791e971a045a79"},
            {"1234ea", "x___________________________1", "2f502917f3ba7d328c21c8b45ee0f160652e68450332c166d4ad02d1afe31862"},
            {"124aaa", "x___________________________2", "ea4040ddf6ae3fbd1524bdec19c0ab1581015996262006632027fa5cf21e441e"},
        },
        {
            {"1234da", "x___________________________0", "1c4b4462e9f56a80ca0f5d77c0d632c41b0102290930343cf1791e971a045a79"},
            {"1234ea", "x___________________________1", "2f502917f3ba7d328c21c8b45ee0f160652e68450332c166d4ad02d1afe31862"},
            {"13aaaa", "x___________________________2", "e4beb66c67e44f2dd8ba36036e45a44ff68f8d52942472b1911a45f886a34507"},
        },
        {
            {"1234da", "x___________________________0", "1c4b4462e9f56a80ca0f5d77c0d632c41b0102290930343cf1791e971a045a79"},
            {"1234ea", "x___________________________1", "2f502917f3ba7d328c21c8b45ee0f160652e68450332c166d4ad02d1afe31862"},
            {"2aaaaa", "x___________________________2", "5f5989b820ff5d76b7d49e77bb64f26602294f6c42a1a3becc669cd9e0dc8ec9"},
        },
    };
    // clang-format on

    for (const auto& test : tests)
    {
        StackTrie st;
        for (const auto& kv : test)
        {
            const auto k = from_hex(kv.key_hex);
            const auto v = to_bytes(kv.value);
            st.insert(Path{k}, v);
            EXPECT_EQ(hex(st.hash()), kv.hash_hex);
        }
    }
}

TEST(state, trie_4keys_extended_node_split)
{
    struct KVH
    {
        const char* key_hex;
        const char* value;
        const char* hash_hex;
    };

    // clang-format off
    KVH tests[][4] = {
        {
            {"000000", "x___________________________0", "3b32b7af0bddc7940e7364ee18b5a59702c1825e469452c8483b9c4e0218b55a"},
            {"1234da", "x___________________________1", "3ab152a1285dca31945566f872c1cc2f17a770440eda32aeee46a5e91033dde2"},
            {"1234ea", "x___________________________2", "0cccc87f96ddef55563c1b3be3c64fff6a644333c3d9cd99852cb53b6412b9b8"},
            {"1234fa", "x___________________________3", "65bb3aafea8121111d693ffe34881c14d27b128fd113fa120961f251fe28428d"},
        },
        {
            {"000000", "x___________________________0", "3b32b7af0bddc7940e7364ee18b5a59702c1825e469452c8483b9c4e0218b55a"},
            {"1234da", "x___________________________1", "3ab152a1285dca31945566f872c1cc2f17a770440eda32aeee46a5e91033dde2"},
            {"1234ea", "x___________________________2", "0cccc87f96ddef55563c1b3be3c64fff6a644333c3d9cd99852cb53b6412b9b8"},
            {"1235aa", "x___________________________3", "f670e4d2547c533c5f21e0045442e2ecb733f347ad6d29ef36e0f5ba31bb11a8"},
        },
        {
            {"000000", "x___________________________0", "3b32b7af0bddc7940e7364ee18b5a59702c1825e469452c8483b9c4e0218b55a"},
            {"1234da", "x___________________________1", "3ab152a1285dca31945566f872c1cc2f17a770440eda32aeee46a5e91033dde2"},
            {"1234ea", "x___________________________2", "0cccc87f96ddef55563c1b3be3c64fff6a644333c3d9cd99852cb53b6412b9b8"},
            {"124aaa", "x___________________________3", "c17464123050a9a6f29b5574bb2f92f6d305c1794976b475b7fb0316b6335598"},
        },
        {
            {"000000", "x___________________________0", "3b32b7af0bddc7940e7364ee18b5a59702c1825e469452c8483b9c4e0218b55a"},
            {"1234da", "x___________________________1", "3ab152a1285dca31945566f872c1cc2f17a770440eda32aeee46a5e91033dde2"},
            {"1234ea", "x___________________________2", "0cccc87f96ddef55563c1b3be3c64fff6a644333c3d9cd99852cb53b6412b9b8"},
            {"13aaaa", "x___________________________3", "aa8301be8cb52ea5cd249f5feb79fb4315ee8de2140c604033f4b3fff78f0105"},
        },
        {
            {"0000", "x___________________________0", "cb8c09ad07ae882136f602b3f21f8733a9f5a78f1d2525a8d24d1c13258000b2"},
            {"123d", "x___________________________1", "8f09663deb02f08958136410dc48565e077f76bb6c9d8c84d35fc8913a657d31"},
            {"123e", "x___________________________2", "0d230561e398c579e09a9f7b69ceaf7d3970f5a436fdb28b68b7a37c5bdd6b80"},
            {"123f", "x___________________________3", "80f7bad1893ca57e3443bb3305a517723a74d3ba831bcaca22a170645eb7aafb"},
        },
        {
            {"0000", "x___________________________0", "cb8c09ad07ae882136f602b3f21f8733a9f5a78f1d2525a8d24d1c13258000b2"},
            {"123d", "x___________________________1", "8f09663deb02f08958136410dc48565e077f76bb6c9d8c84d35fc8913a657d31"},
            {"123e", "x___________________________2", "0d230561e398c579e09a9f7b69ceaf7d3970f5a436fdb28b68b7a37c5bdd6b80"},
            {"124a", "x___________________________3", "383bc1bb4f019e6bc4da3751509ea709b58dd1ac46081670834bae072f3e9557"},
        },
        {
            {"0000", "x___________________________0", "cb8c09ad07ae882136f602b3f21f8733a9f5a78f1d2525a8d24d1c13258000b2"},
            {"123d", "x___________________________1", "8f09663deb02f08958136410dc48565e077f76bb6c9d8c84d35fc8913a657d31"},
            {"123e", "x___________________________2", "0d230561e398c579e09a9f7b69ceaf7d3970f5a436fdb28b68b7a37c5bdd6b80"},
            {"13aa", "x___________________________3", "ff0dc70ce2e5db90ee42a4c2ad12139596b890e90eb4e16526ab38fa465b35cf"},
        },
    };
    //clang-format on

    for (const auto& test : tests)
    {
        StackTrie st;
        for (const auto& kv : test)
        {
            const auto k = from_hex(kv.key_hex);
            const auto v = to_bytes(kv.value);
            st.insert(Path{k}, v);
            EXPECT_EQ(hex(st.hash()), kv.hash_hex);
        }
    }

}
