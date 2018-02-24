package com.redgyro.algorithms.advancedencryptionstandard

import junit.framework.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringRunner


@RunWith(SpringRunner::class)
@SpringBootTest
class StateTests {

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

    @Test(expected = AssertionError::class)
    fun `Create state with less then 4 words from list`() {
        val state = State(
                listOf(Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00))
        )
    }

    @Test(expected = AssertionError::class)
    fun `Create state with more then 4 words from list`() {
        val state = State(
                listOf(Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00))
        )
    }


}