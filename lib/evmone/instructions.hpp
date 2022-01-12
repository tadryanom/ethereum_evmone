// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "baseline.hpp"
#include "execution_state.hpp"
#include "instructions_traits.hpp"
#include "instructions_xmacro.hpp"
#include <ethash/keccak.hpp>

namespace evmone
{
using code_iterator = const uint8_t*;

/// A wrapper for evmc_status_code to indicate that an instruction
/// unconditionally terminates execution.
struct StopToken
{
    const evmc_status_code status;  ///< The status code execution terminates with.
};

constexpr auto max_buffer_size = std::numeric_limits<uint32_t>::max();

/// The size of the EVM 256-bit word.
constexpr auto word_size = 32;

/// Returns number of words what would fit to provided number of bytes,
/// i.e. it rounds up the number bytes to number of words.
inline constexpr int64_t num_words(uint64_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + (word_size - 1)) / word_size);
}

// Grows EVM memory and checks its cost.
//
// This function should not be inlined because this may affect other inlining decisions:
// - making check_memory() too costly to inline,
// - making mload()/mstore()/mstore8() too costly to inline.
//
// TODO: This function should be moved to Memory class.
[[gnu::noinline]] inline bool grow_memory(ExecutionState& state, uint64_t new_size) noexcept
{
    // This implementation recomputes memory.size(). This value is already known to the caller
    // and can be passed as a parameter, but this make no difference to the performance.

    const auto new_words = num_words(new_size);
    const auto current_words = static_cast<int64_t>(state.memory.size() / word_size);
    const auto new_cost = 3 * new_words + new_words * new_words / 512;
    const auto current_cost = 3 * current_words + current_words * current_words / 512;
    const auto cost = new_cost - current_cost;

    if ((state.gas_left -= cost) < 0)
        return false;

    state.memory.grow(static_cast<size_t>(new_words * word_size));
    return true;
}

// Check memory requirements of a reasonable size.
inline bool check_memory(ExecutionState& state, const uint256& offset, uint64_t size) noexcept
{
    // TODO: This should be done in intx.
    // There is "branchless" variant of this using | instead of ||, but benchmarks difference
    // is within noise. This should be decided when moving the implementation to intx.
    if (((offset[3] | offset[2] | offset[1]) != 0) || (offset[0] > max_buffer_size))
        return false;

    const auto new_size = static_cast<uint64_t>(offset) + size;
    if (new_size > state.memory.size())
        return grow_memory(state, new_size);

    return true;
}

// Check memory requirements for "copy" instructions.
inline bool check_memory(ExecutionState& state, const uint256& offset, const uint256& size) noexcept
{
    if (size == 0)  // Copy of size 0 is always valid (even if offset is huge).
        return true;

    // This check has 3 same word checks with the check above.
    // However, compilers do decent although not perfect job unifying common instructions.
    // TODO: This should be done in intx.
    if (((size[3] | size[2] | size[1]) != 0) || (size[0] > max_buffer_size))
        return false;

    return check_memory(state, offset, static_cast<uint64_t>(size));
}

namespace instr
{

inline StopToken stop(ExecutionState& /*state*/) noexcept
{
    return {EVMC_SUCCESS};
}

inline void add(ExecutionState& state) noexcept
{
    state.stack.top() += state.stack.pop();
}

inline void mul(ExecutionState& state) noexcept
{
    state.stack.top() *= state.stack.pop();
}

inline void sub(ExecutionState& state) noexcept
{
    state.stack[1] = state.stack[0] - state.stack[1];
    state.stack.pop();
}

inline void div(ExecutionState& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? state.stack[0] / v : 0;
    state.stack.pop();
}

inline void sdiv(ExecutionState& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? intx::sdivrem(state.stack[0], v).quot : 0;
    state.stack.pop();
}

inline void mod(ExecutionState& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? state.stack[0] % v : 0;
    state.stack.pop();
}

inline void smod(ExecutionState& state) noexcept
{
    auto& v = state.stack[1];
    v = v != 0 ? intx::sdivrem(state.stack[0], v).rem : 0;
    state.stack.pop();
}

inline void addmod(ExecutionState& state) noexcept
{
    const auto x = state.stack.pop();
    const auto y = state.stack.pop();
    auto& m = state.stack.top();
    m = m != 0 ? intx::addmod(x, y, m) : 0;
}

inline void mulmod(ExecutionState& state) noexcept
{
    const auto x = state.stack.pop();
    const auto y = state.stack.pop();
    auto& m = state.stack.top();
    m = m != 0 ? intx::mulmod(x, y, m) : 0;
}

inline evmc_status_code exp(ExecutionState& state) noexcept
{
    const auto base = state.stack.pop();
    auto& exponent = state.stack.top();

    const auto exponent_significant_bytes =
        static_cast<int>(intx::count_significant_bytes(exponent));
    const auto exponent_cost = state.rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    const auto additional_cost = exponent_significant_bytes * exponent_cost;
    if ((state.gas_left -= additional_cost) < 0)
        return EVMC_OUT_OF_GAS;

    exponent = intx::exp(base, exponent);
    return EVMC_SUCCESS;
}

inline void signextend(ExecutionState& state) noexcept
{
    const auto ext = state.stack.pop();
    auto& x = state.stack.top();

    if (ext < 31)  // For 31 we also don't need to do anything.
    {
        const auto e = ext[0];  // uint256 -> uint64.
        const auto sign_word_index =
            static_cast<size_t>(e / sizeof(e));      // Index of the word with the sign bit.
        const auto sign_byte_index = e % sizeof(e);  // Index of the sign byte in the sign word.
        auto& sign_word = x[sign_word_index];

        const auto sign_byte_offset = sign_byte_index * 8;
        const auto sign_byte = sign_word >> sign_byte_offset;  // Move sign byte to position 0.

        // Sign-extend the "sign" byte and move it to the right position. Value bits are zeros.
        const auto sext_byte = static_cast<uint64_t>(int64_t{static_cast<int8_t>(sign_byte)});
        const auto sext = sext_byte << sign_byte_offset;

        const auto sign_mask = ~uint64_t{0} << sign_byte_offset;
        const auto value = sign_word & ~sign_mask;  // Reset extended bytes.
        sign_word = sext | value;                   // Combine the result word.

        // Produce bits (all zeros or ones) for extended words. This is done by SAR of
        // the sign-extended byte. Shift by any value 7-63 would work.
        const auto sign_ex = static_cast<uint64_t>(static_cast<int64_t>(sext_byte) >> 8);

        for (size_t i = 3; i > sign_word_index; --i)
            x[i] = sign_ex;  // Clear extended words.
    }
}

inline void lt(ExecutionState& state) noexcept
{
    const auto x = state.stack.pop();
    state.stack[0] = x < state.stack[0];
}

inline void gt(ExecutionState& state) noexcept
{
    const auto x = state.stack.pop();
    state.stack[0] = state.stack[0] < x;  // Arguments are swapped and < is used.
}

inline void slt(ExecutionState& state) noexcept
{
    const auto x = state.stack.pop();
    state.stack[0] = slt(x, state.stack[0]);
}

inline void sgt(ExecutionState& state) noexcept
{
    const auto x = state.stack.pop();
    state.stack[0] = slt(state.stack[0], x);  // Arguments are swapped and SLT is used.
}

inline void eq(ExecutionState& state) noexcept
{
    state.stack[1] = state.stack[0] == state.stack[1];
    state.stack.pop();
}

inline void iszero(ExecutionState& state) noexcept
{
    state.stack.top() = state.stack.top() == 0;
}

inline void and_(ExecutionState& state) noexcept
{
    state.stack.top() &= state.stack.pop();
}

inline void or_(ExecutionState& state) noexcept
{
    state.stack.top() |= state.stack.pop();
}

inline void xor_(ExecutionState& state) noexcept
{
    state.stack.top() ^= state.stack.pop();
}

inline void not_(ExecutionState& state) noexcept
{
    state.stack.top() = ~state.stack.top();
}

inline void byte(ExecutionState& state) noexcept
{
    const auto n = state.stack.pop();
    auto& x = state.stack.top();

    const bool n_valid = n < 32;
    const uint64_t byte_mask = (n_valid ? 0xff : 0);

    const auto index = 31 - static_cast<unsigned>(n[0] % 32);
    const auto word = x[index / 8];
    const auto byte_index = index % 8;
    const auto byte = (word >> (byte_index * 8)) & byte_mask;
    x = byte;
}

inline void shl(ExecutionState& state) noexcept
{
    state.stack.top() <<= state.stack.pop();
}

inline void shr(ExecutionState& state) noexcept
{
    state.stack.top() >>= state.stack.pop();
}

inline void sar(ExecutionState& state) noexcept
{
    const auto y = state.stack.pop();
    auto& x = state.stack.top();

    const bool is_neg = static_cast<int64_t>(x[3]) < 0;  // Inspect the top bit (words are LE).
    const auto sign_mask = is_neg ? ~uint256{} : uint256{};

    const auto mask_shift = (y < 256) ? (256 - y[0]) : 0;
    x = (x >> y) | (sign_mask << mask_shift);
}


inline evmc_status_code keccak256(ExecutionState& state) noexcept
{
    const auto index = state.stack.pop();
    auto& size = state.stack.top();

    if (!check_memory(state, index, size))
        return EVMC_OUT_OF_GAS;

    const auto i = static_cast<size_t>(index);
    const auto s = static_cast<size_t>(size);
    const auto w = num_words(s);
    const auto cost = w * 6;
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;

    auto data = s != 0 ? &state.memory[i] : nullptr;
    size = intx::be::load<uint256>(ethash::keccak256(data, s));
    return EVMC_SUCCESS;
}


inline void address(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.msg->recipient));
}

inline evmc_status_code balance(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_balance(addr));
    return EVMC_SUCCESS;
}

inline void origin(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_origin));
}

inline void caller(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.msg->sender));
}

inline void callvalue(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.msg->value));
}

inline void calldataload(ExecutionState& state) noexcept
{
    auto& index = state.stack.top();

    if (state.msg->input_size < index)
        index = 0;
    else
    {
        const auto begin = static_cast<size_t>(index);
        const auto end = std::min(begin + 32, state.msg->input_size);

        uint8_t data[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            data[i] = state.msg->input_data[begin + i];

        index = intx::be::load<uint256>(data);
    }
}

inline void calldatasize(ExecutionState& state) noexcept
{
    state.stack.push(state.msg->input_size);
}

inline evmc_status_code calldatacopy(ExecutionState& state) noexcept
{
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    auto dst = static_cast<size_t>(mem_index);
    auto src = state.msg->input_size < input_index ? state.msg->input_size :
                                                     static_cast<size_t>(input_index);
    auto s = static_cast<size_t>(size);
    auto copy_size = std::min(s, state.msg->input_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    return EVMC_SUCCESS;
}

inline void codesize(ExecutionState& state) noexcept
{
    state.stack.push(state.code.size());
}

inline evmc_status_code codecopy(ExecutionState& state) noexcept
{
    // TODO: Similar to calldatacopy().

    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    const auto code_size = state.code.size();
    const auto dst = static_cast<size_t>(mem_index);
    const auto src = code_size < input_index ? code_size : static_cast<size_t>(input_index);
    const auto s = static_cast<size_t>(size);
    const auto copy_size = std::min(s, code_size - src);

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    // TODO: Add unit tests for each combination of conditions.
    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &state.code[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    return EVMC_SUCCESS;
}


inline void gasprice(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().tx_gas_price));
}

inline void basefee(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_base_fee));
}

inline evmc_status_code extcodesize(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = state.host.get_code_size(addr);
    return EVMC_SUCCESS;
}

inline evmc_status_code extcodecopy(ExecutionState& state) noexcept
{
    const auto addr = intx::be::trunc<evmc::address>(state.stack.pop());
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    const auto s = static_cast<size_t>(size);
    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    if (s > 0)
    {
        const auto src =
            (max_buffer_size < input_index) ? max_buffer_size : static_cast<size_t>(input_index);
        const auto dst = static_cast<size_t>(mem_index);
        const auto num_bytes_copied = state.host.copy_code(addr, src, &state.memory[dst], s);
        if (const auto num_bytes_to_clear = s - num_bytes_copied; num_bytes_to_clear > 0)
            std::memset(&state.memory[dst + num_bytes_copied], 0, num_bytes_to_clear);
    }

    return EVMC_SUCCESS;
}

inline void returndatasize(ExecutionState& state) noexcept
{
    state.stack.push(state.return_data.size());
}

inline evmc_status_code returndatacopy(ExecutionState& state) noexcept
{
    const auto mem_index = state.stack.pop();
    const auto input_index = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, mem_index, size))
        return EVMC_OUT_OF_GAS;

    auto dst = static_cast<size_t>(mem_index);
    auto s = static_cast<size_t>(size);

    if (state.return_data.size() < input_index)
        return EVMC_INVALID_MEMORY_ACCESS;
    auto src = static_cast<size_t>(input_index);

    if (src + s > state.return_data.size())
        return EVMC_INVALID_MEMORY_ACCESS;

    const auto copy_cost = num_words(s) * 3;
    if ((state.gas_left -= copy_cost) < 0)
        return EVMC_OUT_OF_GAS;

    if (s > 0)
        std::memcpy(&state.memory[dst], &state.return_data[src], s);

    return EVMC_SUCCESS;
}

inline evmc_status_code extcodehash(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto addr = intx::be::trunc<evmc::address>(x);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::additional_cold_account_access_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_code_hash(addr));
    return EVMC_SUCCESS;
}


inline void blockhash(ExecutionState& state) noexcept
{
    auto& number = state.stack.top();

    const auto upper_bound = state.host.get_tx_context().block_number;
    const auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
    const auto n = static_cast<int64_t>(number);
    const auto header =
        (number < upper_bound && n >= lower_bound) ? state.host.get_block_hash(n) : evmc::bytes32{};
    number = intx::be::load<uint256>(header);
}

inline void coinbase(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_coinbase));
}

inline void timestamp(ExecutionState& state) noexcept
{
    // TODO: Add tests for negative timestamp?
    const auto timestamp = static_cast<uint64_t>(state.host.get_tx_context().block_timestamp);
    state.stack.push(timestamp);
}

inline void number(ExecutionState& state) noexcept
{
    // TODO: Add tests for negative block number?
    const auto block_number = static_cast<uint64_t>(state.host.get_tx_context().block_number);
    state.stack.push(block_number);
}

inline void difficulty(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().block_difficulty));
}

inline void gaslimit(ExecutionState& state) noexcept
{
    const auto block_gas_limit = static_cast<uint64_t>(state.host.get_tx_context().block_gas_limit);
    state.stack.push(block_gas_limit);
}

inline void chainid(ExecutionState& state) noexcept
{
    state.stack.push(intx::be::load<uint256>(state.host.get_tx_context().chain_id));
}

inline void selfbalance(ExecutionState& state) noexcept
{
    // TODO: introduce selfbalance in EVMC?
    state.stack.push(intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)));
}


inline void pop(ExecutionState& state) noexcept
{
    state.stack.pop();
}

inline evmc_status_code mload(ExecutionState& state) noexcept
{
    auto& index = state.stack.top();

    if (!check_memory(state, index, 32))
        return EVMC_OUT_OF_GAS;

    index = intx::be::unsafe::load<uint256>(&state.memory[static_cast<size_t>(index)]);
    return EVMC_SUCCESS;
}

inline evmc_status_code mstore(ExecutionState& state) noexcept
{
    const auto index = state.stack.pop();
    const auto value = state.stack.pop();

    if (!check_memory(state, index, 32))
        return EVMC_OUT_OF_GAS;

    intx::be::unsafe::store(&state.memory[static_cast<size_t>(index)], value);
    return EVMC_SUCCESS;
}

inline evmc_status_code mstore8(ExecutionState& state) noexcept
{
    const auto index = state.stack.pop();
    const auto value = state.stack.pop();

    if (!check_memory(state, index, 1))
        return EVMC_OUT_OF_GAS;

    state.memory[static_cast<size_t>(index)] = static_cast<uint8_t>(value);
    return EVMC_SUCCESS;
}

inline evmc_status_code sload(ExecutionState& state) noexcept
{
    auto& x = state.stack.top();
    const auto key = intx::be::store<evmc::bytes32>(x);

    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->recipient, key) == EVMC_ACCESS_COLD)
    {
        // The warm storage access cost is already applied (from the cost table).
        // Here we need to apply additional cold storage access cost.
        constexpr auto additional_cold_sload_cost =
            instr::cold_sload_cost - instr::warm_storage_read_cost;
        if ((state.gas_left -= additional_cold_sload_cost) < 0)
            return EVMC_OUT_OF_GAS;
    }

    x = intx::be::load<uint256>(state.host.get_storage(state.msg->recipient, key));

    return EVMC_SUCCESS;
}

inline evmc_status_code sstore(ExecutionState& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    if (state.rev >= EVMC_ISTANBUL && state.gas_left <= 2300)
        return EVMC_OUT_OF_GAS;

    const auto key = intx::be::store<evmc::bytes32>(state.stack.pop());
    const auto value = intx::be::store<evmc::bytes32>(state.stack.pop());

    int cost = 0;
    if (state.rev >= EVMC_BERLIN &&
        state.host.access_storage(state.msg->recipient, key) == EVMC_ACCESS_COLD)
        cost = instr::cold_sload_cost;

    const auto status = state.host.set_storage(state.msg->recipient, key, value);

    switch (status)
    {
    case EVMC_STORAGE_UNCHANGED:
    case EVMC_STORAGE_MODIFIED_AGAIN:
        if (state.rev >= EVMC_BERLIN)
            cost += instr::warm_storage_read_cost;
        else if (state.rev == EVMC_ISTANBUL)
            cost = 800;
        else if (state.rev == EVMC_CONSTANTINOPLE)
            cost = 200;
        else
            cost = 5000;
        break;
    case EVMC_STORAGE_MODIFIED:
    case EVMC_STORAGE_DELETED:
        if (state.rev >= EVMC_BERLIN)
            cost += 5000 - instr::cold_sload_cost;
        else
            cost = 5000;
        break;
    case EVMC_STORAGE_ADDED:
        cost += 20000;
        break;
    }
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;
    return EVMC_SUCCESS;
}

/// Internal jump implementation for JUMP/JUMPI instructions.
inline code_iterator jump_impl(ExecutionState& state, const uint256& dst) noexcept
{
    const auto& jumpdest_map = state.analysis.baseline->jumpdest_map;
    if (dst >= jumpdest_map.size() || !jumpdest_map[static_cast<size_t>(dst)])
    {
        state.status = EVMC_BAD_JUMP_DESTINATION;
        return nullptr;
    }

    return state.code.data() + static_cast<size_t>(dst);
}

/// JUMP instruction implementation using baseline::CodeAnalysis.
inline code_iterator jump(ExecutionState& state, code_iterator /*pc*/) noexcept
{
    return jump_impl(state, state.stack.pop());
}

/// JUMPI instruction implementation using baseline::CodeAnalysis.
inline code_iterator jumpi(ExecutionState& state, code_iterator pc) noexcept
{
    const auto dst = state.stack.pop();
    const auto cond = state.stack.pop();
    return cond ? jump_impl(state, dst) : pc + 1;
}

inline code_iterator pc(ExecutionState& state, code_iterator pos) noexcept
{
    state.stack.push(static_cast<uint64_t>(pos - state.code.data()));
    return pos + 1;
}

inline void msize(ExecutionState& state) noexcept
{
    state.stack.push(state.memory.size());
}

inline void gas(ExecutionState& state) noexcept
{
    state.stack.push(state.gas_left);
}

inline void jumpdest(ExecutionState& /*state*/) noexcept {}

/// PUSH instruction implementation.
/// @tparam Len The number of push data bytes, e.g. PUSH3 is push<3>.
///
/// It assumes that the whole data read is valid so code padding is required for some EVM bytecodes
/// having an "incomplete" PUSH instruction at the very end.
template <size_t Len>
inline code_iterator push(ExecutionState& state, code_iterator pos) noexcept
{
    const auto data_pos = pos + 1;
    uint8_t buffer[Len];
    std::memcpy(buffer, data_pos, Len);  // Valid by the assumption code is padded.
    state.stack.push(intx::be::load<intx::uint256>(buffer));
    return pos + (Len + 1);
}

/// DUP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. DUP3 is dup<3>.
template <size_t N>
inline void dup(ExecutionState& state) noexcept
{
    static_assert(N >= 1 && N <= 16);
    state.stack.push(state.stack[N - 1]);
}

/// SWAP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. SWAP3 is swap<3>.
template <size_t N>
inline void swap(ExecutionState& state) noexcept
{
    static_assert(N >= 1 && N <= 16);
    std::swap(state.stack.top(), state.stack[N]);
}


template <size_t NumTopics>
inline evmc_status_code log(ExecutionState& state) noexcept
{
    static_assert(NumTopics <= 4);

    if (state.msg->flags & EVMC_STATIC)
        return EVMC_STATIC_MODE_VIOLATION;

    const auto offset = state.stack.pop();
    const auto size = state.stack.pop();

    if (!check_memory(state, offset, size))
        return EVMC_OUT_OF_GAS;

    const auto o = static_cast<size_t>(offset);
    const auto s = static_cast<size_t>(size);

    const auto cost = int64_t(s) * 8;
    if ((state.gas_left -= cost) < 0)
        return EVMC_OUT_OF_GAS;

    std::array<evmc::bytes32, NumTopics> topics;  // NOLINT(cppcoreguidelines-pro-type-member-init)
    for (auto& topic : topics)
        topic = intx::be::store<evmc::bytes32>(state.stack.pop());

    const auto data = s != 0 ? &state.memory[o] : nullptr;
    state.host.emit_log(state.msg->recipient, data, s, topics.data(), NumTopics);
    return EVMC_SUCCESS;
}


template <evmc_opcode Op>
evmc_status_code call_impl(ExecutionState& state) noexcept;
inline constexpr auto call = call_impl<OP_CALL>;
inline constexpr auto callcode = call_impl<OP_CALLCODE>;
inline constexpr auto delegatecall = call_impl<OP_DELEGATECALL>;
inline constexpr auto staticcall = call_impl<OP_STATICCALL>;

template <evmc_opcode Op>
evmc_status_code create_impl(ExecutionState& state) noexcept;
inline constexpr auto create = create_impl<OP_CREATE>;
inline constexpr auto create2 = create_impl<OP_CREATE2>;

template <evmc_status_code StatusCode>
inline StopToken return_impl(ExecutionState& state) noexcept
{
    const auto offset = state.stack[0];
    const auto size = state.stack[1];

    if (!check_memory(state, offset, size))
        return {EVMC_OUT_OF_GAS};

    state.output_size = static_cast<size_t>(size);
    if (state.output_size != 0)
        state.output_offset = static_cast<size_t>(offset);
    return {StatusCode};
}
inline constexpr auto return_ = return_impl<EVMC_SUCCESS>;
inline constexpr auto revert = return_impl<EVMC_REVERT>;

inline StopToken invalid(ExecutionState& /*state*/) noexcept
{
    return {EVMC_INVALID_INSTRUCTION};
}

inline StopToken selfdestruct(ExecutionState& state) noexcept
{
    if (state.msg->flags & EVMC_STATIC)
        return {EVMC_STATIC_MODE_VIOLATION};

    const auto beneficiary = intx::be::trunc<evmc::address>(state.stack[0]);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(beneficiary) == EVMC_ACCESS_COLD)
    {
        if ((state.gas_left -= instr::cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS};
    }

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
    {
        if (state.rev == EVMC_TANGERINE_WHISTLE || state.host.get_balance(state.msg->recipient))
        {
            // After TANGERINE_WHISTLE apply additional cost of
            // sending value to a non-existing account.
            if (!state.host.account_exists(beneficiary))
            {
                if ((state.gas_left -= 25000) < 0)
                    return {EVMC_OUT_OF_GAS};
            }
        }
    }

    state.host.selfdestruct(state.msg->recipient, beneficiary);
    return {EVMC_SUCCESS};
}


/// Maps an opcode to the instruction implementation.
///
/// The set of template specializations which map opcodes `Op` to the function
/// implementing the instruction identified by the opcode.
///     instr::impl<OP_DUP1>(/*...*/);
/// The unspecialized template is invalid and should never to used.
template <evmc_opcode Op>
inline constexpr auto impl = nullptr;

#define X(OPCODE, IDENTIFIER) \
    template <>               \
    inline constexpr auto impl<OPCODE> = IDENTIFIER;  // opcode -> implementation
MAP_OPCODE_TO_IDENTIFIER
#undef X
}  // namespace instr
}  // namespace evmone
