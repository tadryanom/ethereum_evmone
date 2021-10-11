// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "instruction_traits.hpp"

#include <array>
#include <cassert>
#include <limits>

namespace evmone
{
namespace
{
constexpr uint8_t FORMAT = 0xef;
constexpr uint8_t MAGIC = 0x00;
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t CODE_SECTION = 0x01;
constexpr uint8_t DATA_SECTION = 0x02;
constexpr uint8_t MAX_SECTION = DATA_SECTION;

using EOFSectionHeaders = std::array<size_t, MAX_SECTION + 1>;

std::pair<EOFSectionHeaders, EOFValidationErrror> validate_eof_headers(
    const uint8_t* code, size_t code_size) noexcept
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id = 0;
    EOFSectionHeaders section_headers{};
    const auto* code_end = code + code_size;
    auto it = code + sizeof(MAGIC) + 2;  // FORMAT + MAGIC + VERSION
    while (it != code_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it;
            switch (section_id)
            {
            case TERMINATOR:
                if (section_headers[CODE_SECTION] == 0)
                    return {{}, EOFValidationErrror::code_section_missing};
                state = State::terminated;
                break;
            case DATA_SECTION:
                if (section_headers[CODE_SECTION] == 0)
                    return {{}, EOFValidationErrror::code_section_missing};
                if (section_headers[DATA_SECTION] != 0)
                    return {{}, EOFValidationErrror::multiple_data_sections};
                state = State::section_size;
                break;
            case CODE_SECTION:
                if (section_headers[CODE_SECTION] != 0)
                    return {{}, EOFValidationErrror::multiple_code_sections};
                state = State::section_size;
                break;
            default:
                return {{}, EOFValidationErrror::unknown_section_id};
            }
            break;
        }
        case State::section_size:
        {
            const auto size_hi = *it;
            ++it;
            if (it == code_end)
                return {{}, EOFValidationErrror::incomplete_section_size};
            const auto size_lo = *it;
            const auto section_size = static_cast<size_t>(size_hi << 8) | size_lo;
            if (section_size == 0)
                return {{}, EOFValidationErrror::zero_section_size};

            section_headers[section_id] = section_size;
            state = State::section_id;
            break;
        }
        case State::terminated:
            return {{}, EOFValidationErrror::impossible};
        }

        ++it;
    }

    if (state != State::terminated)
        return {{}, EOFValidationErrror::section_headers_not_terminated};

    const auto section_bodies_size = section_headers[CODE_SECTION] + section_headers[DATA_SECTION];
    const auto remaining_code_size = static_cast<size_t>(code_end - it);
    if (section_bodies_size != remaining_code_size)
        return {{}, EOFValidationErrror::invalid_section_bodies_size};

    return {section_headers, EOFValidationErrror::success};
}

EOFValidationErrror validate_instructions(
    evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    assert(code_size > 0);  // guaranteed by EOF headers validation

    size_t i = 0;
    uint8_t op = 0;
    while (i < code_size)
    {
        op = code[i];
        const auto& since = instr::traits[op].since;
        if (!since.has_value() || *since > rev)
            return EOFValidationErrror::undefined_instruction;

        i += instr::traits[op].immediate_size;
        ++i;
    }
    if (i != code_size)
        return EOFValidationErrror::truncated_immediate;

    if (!instr::traits[op].is_terminating)
        return EOFValidationErrror::missing_terminating_instruction;

    return EOFValidationErrror::success;
}

}  // namespace

size_t EOF1Header::code_begin() const noexcept
{
    assert(code_size != 0);

    if (data_size == 0)
        return 7;  // EF + MAGIC + VERSION + SECTION_ID + SIZE + TERMINATOR
    else
        return 10;  // EF + MAGIC + VERSION + SECTION_ID + SIZE + SECTION_ID + SIZE + TERMINATOR
}

bool is_eof_code(const uint8_t* code, size_t code_size) noexcept
{
    return code_size > 1 && code[0] == FORMAT && code[1] == MAGIC;
}

EOF1Header read_valid_eof1_header(const uint8_t* code) noexcept
{
    EOF1Header header;
    const auto code_size_offset = 4;  // FORMAT + MAGIC + VERSION + CODE_SECTION_ID
    header.code_size = (size_t{code[code_size_offset]} << 8) | code[code_size_offset + 1];
    if (code[code_size_offset + 2] == 2)  // is data section present
    {
        const auto data_size_offset = code_size_offset + 3;
        header.data_size = (size_t{code[data_size_offset]} << 8) | code[data_size_offset + 1];
    }
    return header;
}

uint8_t get_eof_version(const uint8_t* code, size_t code_size) noexcept
{
    return (code_size >= 3 && code[0] == FORMAT && code[1] == MAGIC) ? code[2] : 0;
}

std::pair<EOF1Header, EOFValidationErrror> validate_eof1(
    evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    const auto [section_headers, error_header] = validate_eof_headers(code, code_size);
    if (error_header != EOFValidationErrror::success)
        return {{}, error_header};

    EOF1Header header{section_headers[CODE_SECTION], section_headers[DATA_SECTION]};

    const auto error_instr =
        validate_instructions(rev, &code[header.code_begin()], header.code_size);
    if (error_instr != EOFValidationErrror::success)
        return {{}, error_instr};

    return {header, EOFValidationErrror::success};
}

EOFValidationErrror validate_eof(evmc_revision rev, const uint8_t* code, size_t code_size) noexcept
{
    if (!is_eof_code(code, code_size))
        return EOFValidationErrror::invalid_prefix;

    const auto version = get_eof_version(code, code_size);

    switch (version)
    {
    default:
        return EOFValidationErrror::eof_version_unknown;
    case 1:
    {
        if (rev < EVMC_SHANGHAI)
            return EOFValidationErrror::eof_version_unknown;
        return validate_eof1(rev, code, code_size).second;
    }
    }
}


}  // namespace evmone
