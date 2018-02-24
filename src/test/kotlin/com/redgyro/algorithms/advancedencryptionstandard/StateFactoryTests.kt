package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class StateFactoryTests {

    @Test
    fun `get states from hex list`() {
        val hexList =
                arrayListOf(
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA, 0xBB,
                        0xCC, 0xDD, 0xEE, 0xFF)

        val states = getStatesFromHexList(hexList)

        assertEquals(
                listOf(State(
                        Word(0x11, 0x22, 0x33, 0x44),
                        Word(0x55, 0x66, 0x77, 0x88),
                        Word(0x99, 0x00, 0xAA, 0xBB),
                        Word(0xCC, 0xDD, 0xEE, 0xFF))),
                states
        )
    }

    @Test
    fun `get states from hex list with less then 16 hex values`() {
        val hexList =
                listOf(
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA, 0xBB,
                        0xCC, 0xDD)

        val states = getStatesFromHexList(hexList)

        assertEquals(
                listOf(State(
                        Word(0x11, 0x22, 0x33, 0x44),
                        Word(0x55, 0x66, 0x77, 0x88),
                        Word(0x99, 0x00, 0xAA, 0xBB),
                        Word(0xCC, 0xDD, 0x00, 0x00))),
                states
        )
    }

    @Test
    fun `get states from hex list with less then 4 words`() {
        val hexList =
                listOf(
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA)

        val states = getStatesFromHexList(hexList)

        assertEquals(
                listOf(State(
                        Word(0x11, 0x22, 0x33, 0x44),
                        Word(0x55, 0x66, 0x77, 0x88),
                        Word(0x99, 0x00, 0xAA, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00))),
                states
        )
    }

    @Test
    fun `get multiple states from hex list`() {
        val hexList =
                listOf(0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA, 0xBB,
                        0xCC, 0xDD, 0xEE, 0xFF,
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA, 0xBB,
                        0xCC, 0xDD, 0xEE, 0xFF)

        val states = getStatesFromHexList(hexList)

        assertEquals(
                listOf(
                        State(Word(0x11, 0x22, 0x33, 0x44),
                                Word(0x55, 0x66, 0x77, 0x88),
                                Word(0x99, 0x00, 0xAA, 0xBB),
                                Word(0xCC, 0xDD, 0xEE, 0xFF)),
                        State(Word(0x11, 0x22, 0x33, 0x44),
                                Word(0x55, 0x66, 0x77, 0x88),
                                Word(0x99, 0x00, 0xAA, 0xBB),
                                Word(0xCC, 0xDD, 0xEE, 0xFF))),
                states
        )
    }

    @Test
    fun `get one full and one partial state from hex list`() {
        val hexList =
                listOf(
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA, 0xBB,
                        0xCC, 0xDD, 0xEE, 0xFF,
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA)

        val states = getStatesFromHexList(hexList)

        assertEquals(
                listOf(
                        State(Word(0x11, 0x22, 0x33, 0x44),
                                Word(0x55, 0x66, 0x77, 0x88),
                                Word(0x99, 0x00, 0xAA, 0xBB),
                                Word(0xCC, 0xDD, 0xEE, 0xFF)),
                        State(Word(0x11, 0x22, 0x33, 0x44),
                                Word(0x55, 0x66, 0x77, 0x88),
                                Word(0x99, 0x00, 0xAA, 0x00),
                                Word(0x00, 0x00, 0x00, 0x00))),
                states
        )


    }

    @Test
    fun `Get states from string`() {
        val inputString = "Hello World!!"
        val expected = listOf(
                State(Word(0x48, 0x65, 0x6C, 0x6C),
                        Word(0x6F, 0x20, 0x57, 0x6F),
                        Word(0x72, 0x6c, 0x64, 0x21),
                        Word(0x21, 0x00, 0x00, 0x00))
        )

        val states = getStatesFromString(inputString)

        assertEquals(expected, states)
    }
}