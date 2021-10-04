// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include <evmone/eof.hpp>
#include <evmone/instruction_traits.hpp>
#include <gtest/gtest.h>
#include <test/utils/utils.hpp>

using namespace evmone;

namespace
{
inline EOFValidationErrror validate_eof(bytes_view code, evmc_revision rev = EVMC_SHANGHAI) noexcept
{
    return ::validate_eof(rev, code.data(), code.size());
}
}  // namespace

TEST(eof_validation, validate_empty_code)
{
    EXPECT_EQ(validate_eof({}), EOFValidationErrror::invalid_prefix);
}

TEST(eof_validation, validate_EOF_prefix)
{
    EXPECT_EQ(validate_eof(from_hex("00")), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof(from_hex("FE")), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof(from_hex("EF")), EOFValidationErrror::invalid_prefix);

    EXPECT_EQ(validate_eof(from_hex("EF0101")), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof(from_hex("EFEF01")), EOFValidationErrror::invalid_prefix);
    EXPECT_EQ(validate_eof(from_hex("EFFF01")), EOFValidationErrror::invalid_prefix);

    EXPECT_EQ(validate_eof(from_hex("EF00")), EOFValidationErrror::eof_version_unknown);

    EXPECT_EQ(
        validate_eof(from_hex("EF0001")), EOFValidationErrror::section_headers_not_terminated);
}

// TODO tests from pre-Shanghai

TEST(eof_validation, validate_EOF_version)
{
    EXPECT_EQ(validate_eof(from_hex("EF0002")), EOFValidationErrror::eof_version_unknown);
    EXPECT_EQ(validate_eof(from_hex("EF00FF")), EOFValidationErrror::eof_version_unknown);
}

TEST(eof_validation, minimal_valid_EOF1_code)
{
    EXPECT_EQ(validate_eof(from_hex("EF0001 010001 00 FE")), EOFValidationErrror::success);
}

TEST(eof_validation, minimal_valid_EOF1_code_with_data)
{
    EXPECT_EQ(
        validate_eof(from_hex("EF0001 010001 020001 00 FE DA")), EOFValidationErrror::success);
}

TEST(eof_validation, EOF1_code_section_missing)
{
    EXPECT_EQ(validate_eof(from_hex("EF0001 00")), EOFValidationErrror::code_section_missing);
    EXPECT_EQ(
        validate_eof(from_hex("EF0001 020001 DA")), EOFValidationErrror::code_section_missing);
}

TEST(eof_validation, EOF1_code_section_0_size)
{
    EXPECT_EQ(validate_eof(from_hex("EF0001 010000 020001 00 DA")),
        EOFValidationErrror::zero_section_size);
}

TEST(eof_validation, EOF1_data_section_0_size)
{
    EXPECT_EQ(validate_eof(from_hex("EF0001 010001 020000 00 FE")),
        EOFValidationErrror::zero_section_size);
}

TEST(eof_validation, EOF1_multiple_code_sections)
{
    EXPECT_EQ(validate_eof(from_hex("EF0001 010001 010001 00 FE FE")),
        EOFValidationErrror::multiple_code_sections);
    EXPECT_EQ(validate_eof(from_hex("EF0001 010001 010001 020001 00 FE FE DA")),
        EOFValidationErrror::multiple_code_sections);
}

TEST(eof_validation, EOF1_multiple_data_sections)
{
    EXPECT_EQ(validate_eof(from_hex("EF0001 010001 020001 020001 00 FE DA DA")),
        EOFValidationErrror::multiple_data_sections);
}

TEST(eof_validation, EOF1_undefined_opcodes)
{
    auto code = from_hex("EF0001 010002 00 0000");

    const auto& gas_table = evmone::instr::gas_costs[EVMC_SHANGHAI];

    for (uint16_t opcode = 0; opcode <= 0xff; ++opcode)
    {
        // Skip opcodes requiring immediate arguments.
        // They're all valid in Shanghai and checked in other tests below.
        if (opcode >= OP_PUSH1 && opcode <= OP_PUSH32)
            continue;
        if (opcode == OP_RJUMP || opcode == OP_RJUMPI)
            continue;

        code[code.size() - 2] = static_cast<uint8_t>(opcode);

        const auto expected = (gas_table[opcode] == evmone::instr::undefined ?
                                   EOFValidationErrror::undefined_instruction :
                                   EOFValidationErrror::success);
        EXPECT_EQ(validate_eof(code), expected) << hex(code);
    }

    EXPECT_EQ(validate_eof(from_hex("EF0001 010001 00 FE")), EOFValidationErrror::success);
}

TEST(eof_validation, EOF1_truncated_push)
{
    auto eof_header = from_hex("EF0001 010001 00");
    auto& code_size_byte = eof_header[5];
    for (uint8_t opcode = OP_PUSH1; opcode <= OP_PUSH32; ++opcode)
    {
        const auto required_bytes = static_cast<size_t>(opcode - OP_PUSH1 + 1);
        for (size_t i = 0; i < required_bytes; ++i)
        {
            const bytes code{opcode + bytes(i, 0)};
            code_size_byte = static_cast<uint8_t>(code.size());
            const auto container = eof_header + code;

            EXPECT_EQ(validate_eof(container), EOFValidationErrror::truncated_immediate)
                << hex(container);
        }

        const bytes code{opcode + bytes(required_bytes, 0) + uint8_t{OP_STOP}};
        code_size_byte = static_cast<uint8_t>(code.size());
        const auto container = eof_header + code;

        EXPECT_EQ(validate_eof(container), EOFValidationErrror::success) << hex(container);
    }
}

TEST(eof_validation, EOF1_terminating_instructions)
{
    auto eof_header = from_hex("EF0001 010001 00");
    auto& code_size_byte = eof_header[5];

    const auto& traits = evmone::instr::traits;

    for (uint16_t opcode = 0; opcode <= 0xff; ++opcode)
    {
        const auto& op_traits = traits[opcode];
        // Skip undefined opcodes.
        if (op_traits.name == nullptr)
            continue;

        bytes code{static_cast<uint8_t>(opcode) + bytes(op_traits.immediate_size, 0)};
        code_size_byte = static_cast<uint8_t>(code.size());
        const auto container = eof_header + code;

        const auto expected = ((opcode == OP_STOP || opcode == OP_RETURN || opcode == OP_REVERT ||
                                   opcode == OP_INVALID || opcode == OP_SELFDESTRUCT) ?
                                   EOFValidationErrror::success :
                                   EOFValidationErrror::missing_terminating_instruction);
        EXPECT_EQ(validate_eof(container), expected) << hex(code);
    }
}
