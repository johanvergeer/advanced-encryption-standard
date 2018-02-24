package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
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

        assertArrayEquals(
                arrayListOf(State(
                        Word(0x11, 0x22, 0x33, 0x44),
                        Word(0x55, 0x66, 0x77, 0x88),
                        Word(0x99, 0x00, 0xAA, 0xBB),
                        Word(0xCC, 0xDD, 0xEE, 0xFF))).toArray(),
                states.toTypedArray()
        )
    }

    @Test
    fun `get states from hex list with less then 16 hex values`() {
        val hexList =
                arrayListOf(
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA, 0xBB,
                        0xCC, 0xDD)

        val states = getStatesFromHexList(hexList)

        assertEquals(
                arrayListOf(State(
                        Word(0x11, 0x22, 0x33, 0x44),
                        Word(0x55, 0x66, 0x77, 0x88),
                        Word(0x99, 0x00, 0xAA, 0xBB),
                        Word(0xCC, 0xDD, 0x00, 0x00))).toArray(),
                states.toTypedArray()
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

        assertArrayEquals(
                arrayListOf(State(listOf(
                        Word(0x11, 0x22, 0x33, 0x44),
                        Word(0x55, 0x66, 0x77, 0x88),
                        Word(0x99, 0x00, 0xAA, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00)))).toArray(),
                states.toTypedArray()
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

        assertArrayEquals(
                arrayListOf(
                        State(Word(0x11, 0x22, 0x33, 0x44),
                                Word(0x55, 0x66, 0x77, 0x88),
                                Word(0x99, 0x00, 0xAA, 0xBB),
                                Word(0xCC, 0xDD, 0xEE, 0xFF)),
                        State(Word(0x11, 0x22, 0x33, 0x44),
                                Word(0x55, 0x66, 0x77, 0x88),
                                Word(0x99, 0x00, 0xAA, 0xBB),
                                Word(0xCC, 0xDD, 0xEE, 0xFF))).toArray(),
                states.toTypedArray()
        )
    }

    @Test
    fun `get one full and one partial state from hex list`() {
        val hexList =
                arrayListOf(
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA, 0xBB,
                        0xCC, 0xDD, 0xEE, 0xFF,
                        0x11, 0x22, 0x33, 0x44,
                        0x55, 0x66, 0x77, 0x88,
                        0x99, 0x00, 0xAA)

        val states = getStatesFromHexList(hexList)

        assertArrayEquals(
                arrayListOf(
                        State(listOf(
                                Word(arrayListOf(0x11, 0x22, 0x33, 0x44)),
                                Word(arrayListOf(0x55, 0x66, 0x77, 0x88)),
                                Word(arrayListOf(0x99, 0x00, 0xAA, 0xBB)),
                                Word(arrayListOf(0xCC, 0xDD, 0xEE, 0xFF)))),
                        State(listOf(
                                Word(arrayListOf(0x11, 0x22, 0x33, 0x44)),
                                Word(arrayListOf(0x55, 0x66, 0x77, 0x88)),
                                Word(arrayListOf(0x99, 0x00, 0xAA, 0x00)),
                                Word(arrayListOf(0x00, 0x00, 0x00, 0x00))))).toArray(),
                states.toTypedArray()
        )
    }
}