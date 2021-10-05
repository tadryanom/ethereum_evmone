// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "evm_fixture.hpp"

using evmone::test::evm;

TEST_P(evm, eof1_execution)
{
    const auto code = eof1_bytecode(OP_STOP);

    rev = EVMC_LONDON;
    execute(code);
    EXPECT_STATUS(EVMC_UNDEFINED_INSTRUCTION);

    rev = EVMC_SHANGHAI;
    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
}

TEST_P(evm, eof1_execution_with_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains ret(0, 1)
    auto code = eof1_bytecode(mstore8(0, 1), ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_INVALID_INSTRUCTION);
    EXPECT_EQ(result.output_size, 0);

    // data section contains ret(0, 1)
    code = eof1_bytecode(mstore8(0, 1) + OP_STOP, ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(result.output_size, 0);
}

TEST_P(evm, eof1_pc)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(OP_PC + mstore8(0) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 0);

    code = eof1_bytecode(4 * bytecode{OP_JUMPDEST} + OP_PC + mstore8(0) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 4);
}

TEST_P(evm, eof1_jump_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code =
        eof1_bytecode(jump(4) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_jumpi_inside_code_section)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(jumpi(6, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(
        jumpi(6, 1) + OP_INVALID + OP_JUMPDEST + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof1_jump_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code = eof1_bytecode(jump(3), OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_jumpi_into_data_section)
{
    rev = EVMC_SHANGHAI;
    // data section contains OP_JUMPDEST + mstore8(0, 1) + ret(0, 1)
    const auto code = eof1_bytecode(jumpi(5, 1), OP_JUMPDEST + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_BAD_JUMP_DESTINATION);
}

TEST_P(evm, eof1_codesize)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 16);

    code = eof1_bytecode(mstore8(0, OP_CODESIZE) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 23);
}

TEST_P(evm, eof1_codecopy_full)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{19} + 0 + 0 + OP_CODECOPY + ret(0, 19));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        from_hex("ef000101000c006013600060003960136000f3"));

    code = eof1_bytecode(bytecode{26} + 0 + 0 + OP_CODECOPY + ret(0, 26), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size),
        from_hex("ef000101000c02000400601a6000600039601a6000f3deadbeef"));
}

TEST_P(evm, eof1_codecopy_header)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{7} + 0 + 0 + OP_CODECOPY + ret(0, 7));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), from_hex("ef000101000c00"));

    code = eof1_bytecode(bytecode{10} + 0 + 0 + OP_CODECOPY + ret(0, 10), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), from_hex("ef000101000c02000400"));
}

TEST_P(evm, eof1_codecopy_code)
{
    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(bytecode{12} + 7 + 0 + OP_CODECOPY + ret(0, 12));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), from_hex("600c6007600039600c6000f3"));

    code = eof1_bytecode(bytecode{12} + 10 + 0 + OP_CODECOPY + ret(0, 12), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(
        bytes_view(result.output_data, result.output_size), from_hex("600c600a600039600c6000f3"));
}

TEST_P(evm, eof1_codecopy_data)
{
    rev = EVMC_SHANGHAI;

    const auto code = eof1_bytecode(bytecode{4} + 22 + 0 + OP_CODECOPY + ret(0, 4), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    EXPECT_EQ(bytes_view(result.output_data, result.output_size), from_hex("deadbeef"));
}

TEST_P(evm, eof2_rjump)
{
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code = eof1_bytecode(rjump(1) + OP_INVALID + mstore8(0, 1) + ret(0, 1), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjump_backward)
{
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) + rjump(-13));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);

    code =
        eof1_bytecode(rjump(11) + OP_INVALID + mstore8(0, 1) + ret(0, 1) + rjump(-13), "deadbeef");

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}

TEST_P(evm, eof2_rjump_0_offset)
{
    // Relative jumps are not implemented in Advanced.
    if (isAdvanced())
        return;

    rev = EVMC_SHANGHAI;
    auto code = eof1_bytecode(rjump(0) + mstore8(0, 1) + ret(0, 1));

    execute(code);
    EXPECT_STATUS(EVMC_SUCCESS);
    ASSERT_EQ(result.output_size, 1);
    EXPECT_EQ(result.output_data[0], 1);
}
