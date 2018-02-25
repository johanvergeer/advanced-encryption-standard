package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.boot.test.context.SpringBootTest


@SpringBootTest
class StateTests {

    @BeforeEach
    fun `setUp`() {
    }

    @Test
    fun `Create state with 4 separater words`() {
        val state = State(
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00)
        )

        assertEquals(4, state.size)
    }

    @Test
    fun `Create state with 4 words from list`() {
        val state = State(
                listOf(Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00))
        )

        assertEquals(4, state.size)
    }

    @Test
    fun `Create state with less then 4 words from list`() {
        assertThrows<AssertionError>({
            State(listOf(Word(0x00, 0x00, 0x00, 0x00),
                    Word(0x00, 0x00, 0x00, 0x00),
                    Word(0x00, 0x00, 0x00, 0x00))
            )
        })
    }

    @Test
    fun `Create state with more then 4 words from list`() {
        assertThrows<AssertionError> {
            State(listOf(Word(0x00, 0x00, 0x00, 0x00),
                    Word(0x00, 0x00, 0x00, 0x00),
                    Word(0x00, 0x00, 0x00, 0x00))
            )
        }
    }

    @Test
    fun `Sub Bytes for encryption`() {
        val initialState = State(
                Word(0x19, 0x3D, 0xE3, 0xBE),
                Word(0xA0, 0xF4, 0xE2, 0x2B),
                Word(0x9A, 0xC6, 0x8D, 0x2A),
                Word(0xE9, 0xF8, 0x48, 0x08)
        )
        val expectedState = State(
                Word(0xD4, 0x27, 0x11, 0xAE),
                Word(0xE0, 0xBF, 0x98, 0xF1),
                Word(0xB8, 0xB4, 0x5D, 0xE5),
                Word(0x1E, 0x41, 0x52, 0x30)
        )

        assertEquals(expectedState, initialState.subBytes())
    }

    @Test
    fun `Sub Bytes inverse for decription`() {
        val initialState = State(
                Word(0x19, 0x3D, 0xE3, 0xBE),
                Word(0xA0, 0xF4, 0xE2, 0x2B),
                Word(0x9A, 0xC6, 0x8D, 0x2A),
                Word(0xE9, 0xF8, 0x48, 0x08)
        )

        assertEquals(initialState, initialState.subBytes().subBytesInverse())
    }

    @Test
    fun `Shift rows for encryption`() {
        val initialState = State(
                Word(0xD4, 0x27, 0x11, 0xAE),
                Word(0xE0, 0xBF, 0x98, 0xF1),
                Word(0xB8, 0xB4, 0x5D, 0xE5),
                Word(0x1E, 0x41, 0x52, 0x30)
        )

        val expectedState = State(
                Word(0xD4, 0xBF, 0x5D, 0x30),
                Word(0xE0, 0xB4, 0x52, 0xAE),
                Word(0xB8, 0x41, 0x11, 0xF1),
                Word(0x1E, 0x27, 0x98, 0xE5)
        )

        assertEquals(expectedState, initialState.shiftRows())
    }

    @Test
    fun `Shift rows inverse for description`() {
        val initialState = State(
                Word(0xD4, 0x27, 0x11, 0xAE),
                Word(0xE0, 0xBF, 0x98, 0xF1),
                Word(0xB8, 0xB4, 0x5D, 0xE5),
                Word(0x1E, 0x41, 0x52, 0x30)
        )

        // After shift rows inverse, the final state should be equal to the initial state
        assertEquals(initialState, initialState.shiftRows().shiftRowsInverse())
    }

    @Test
    fun `Mix Columns for encryption`() {
        val initialState = State(
                Word(0xD4, 0xBF, 0x5D, 0x30),
                Word(0xE0, 0xB4, 0x52, 0xAE),
                Word(0xB8, 0x41, 0x11, 0xF1),
                Word(0x1E, 0x27, 0x98, 0xE5)
        )

        val expectedState = State(
                Word(0x04, 0x66, 0x81, 0xE5),
                Word(0xE0, 0xCB, 0x19, 0x9A),
                Word(0x48, 0xF8, 0xD3, 0x7A),
                Word(0x28, 0x06, 0x26, 0x4C)
        )

        assertEquals(expectedState, initialState.mixColumns())
    }

    @Test
    fun `Mix Columns for decryption`() {
        val initialState = State(
                Word(0xD4, 0xBF, 0x5D, 0x30),
                Word(0xE0, 0xB4, 0x52, 0xAE),
                Word(0xB8, 0x41, 0x11, 0xF1),
                Word(0x1E, 0x27, 0x98, 0xE5)
        )

        // After inverse of mix columns, the state should be equal to the initial state
        assertEquals(initialState, initialState.mixColumns().mixColumnsInverse())
    }

    @Test
    fun `Add round key`() {
        val initialState = State(
                Word(0x04, 0x66, 0x81, 0xE5),
                Word(0xE0, 0xCB, 0x19, 0x9A),
                Word(0x48, 0xF8, 0xD3, 0x7A),
                Word(0x28, 0x06, 0x26, 0x4C)
        )

        val expectedState = State(
                Word(0xA4, 0x9C, 0x7F, 0xF2),
                Word(0x68, 0x9F, 0x35, 0x2B),
                Word(0x6B, 0x5B, 0xEA, 0x43),
                Word(0x02, 0x6A, 0x50, 0x49)
        )

        val firstExpandedKey = Key(
                Word(0xA0, 0xFA, 0xFE, 0x17),
                Word(0x88, 0x54, 0x2C, 0xB1),
                Word(0x23, 0xA3, 0x39, 0x39),
                Word(0x2A, 0x6C, 0x76, 0x05))

        assertEquals(expectedState, initialState.addRoundKey(firstExpandedKey))
    }

    @Test
    fun `xor other State object`() {
        val initialState = State(
                Word(0x04, 0x66, 0x81, 0xE5),
                Word(0xE0, 0xCB, 0x19, 0x9A),
                Word(0x48, 0xF8, 0xD3, 0x7A),
                Word(0x28, 0x06, 0x26, 0x4C)
        )

        val otherState = State(
                Word(0xA0, 0xFA, 0xFE, 0x17),
                Word(0x88, 0x54, 0x2C, 0xB1),
                Word(0x23, 0xA3, 0x39, 0x39),
                Word(0x2A, 0x6C, 0x76, 0x05))

        val expectedState = State(
                Word(0xa4, 0x9c, 0x7f, 0xf2),
                Word(0x68, 0x9f, 0x35, 0x2b),
                Word(0x6b, 0x5b, 0xea, 0x43),
                Word(0x02, 0x6a, 0x50, 0x49)
        )

        assertEquals(expectedState, initialState.xorOtherState(otherState))

//        for (i in 0..3) {
//            print("Word(")
//            print((0..3).map { b ->
//                "0x${java.lang.Integer.toHexString(initialState[i][b] xor otherState[i][b]).padStart(2, '0')}"
//            }.joinToString(separator = ", "))
//            print(")")
//            println()
//        }
    }
}