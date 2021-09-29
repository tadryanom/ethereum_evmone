// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"

#include <array>

namespace evmone
{
namespace
{
constexpr uint8_t FORMAT = 0xef;
constexpr uint8_t MAGIC = 0x00;
}  // namespace

bool is_eof_code(const uint8_t* code, size_t code_size) noexcept
{
    return code_size > 1 && code[0] == FORMAT && code[1] == MAGIC;
}

EOF1Header read_valid_eof1_header(const uint8_t* code) noexcept
{
    EOF1Header header;
    const auto code_size_offset = 4; // FORMAT + MAGIC + VERSION + CODE_SECTION_ID
    header.code_size = (size_t{code[code_size_offset]} << 8) | code[code_size_offset + 1];
    if (code[code_size_offset + 2] == 2)  // is data section present
    {
        const auto data_size_offset = code_size_offset + 3;
        header.data_size = (size_t{code[data_size_offset]} << 8) | code[data_size_offset + 1];
    }
    return header;
}
}  // namespace evmone