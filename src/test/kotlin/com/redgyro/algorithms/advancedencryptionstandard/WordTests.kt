package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest


@SpringBootTest
class WordTests {

    @Test
    fun `Create new word from 4 separate bytes`() {
        val word = Word(0x00, 0x01, 0x02, 0x03)

        assertEquals(4, word.size)
    }

    @Test
    fun `Create new word list with four bytes`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(4, word.size)
    }

    @Test
    fun `Create new word less then 4 bytes`() {
        val exception = assertThrows(AssertionError::class.java, { Word(listOf(0x00, 0x01, 0x02)) })
    }

    @Test
    fun `Create new word more then 4 bytes`() {
        val exception = assertThrows(
                AssertionError::class.java,
                { Word(listOf(0x00, 0x01, 0x02, 0x03, 0x04)) }
        )
    }


    @Test
    fun `Shift bytes left 1 position`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x01, 0x02, 0x03, 0x00), word.shiftBytesLeft())
    }


    @Test
    fun `Shift bytes left 1 position explicit`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x01, 0x02, 0x03, 0x00), word.shiftBytesLeft(positions = 1))
    }


    @Test
    fun `Shift bytes left 2 positions`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x02, 0x03, 0x00, 0x01), word.shiftBytesLeft(positions = 2))
    }


    @Test
    fun `Shift bytes left 3 positions`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x03, 0x00, 0x01, 0x02), word.shiftBytesLeft(positions = 3))
    }


    @Test
    fun `Shift bytes Right 1 position`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x03, 0x00, 0x01, 0x02), word.shiftBytesRight())
    }


    @Test
    fun `Shift bytes Right 1 position explicit`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x03, 0x00, 0x01, 0x02), word.shiftBytesRight(positions = 1))
    }


    @Test
    fun `Shift bytes Right 2 positions`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x02, 0x03, 0x00, 0x01), word.shiftBytesRight(positions = 2))
    }


    @Test
    fun `Shift bytes Right 3 positions`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x01, 0x02, 0x03, 0x00), word.shiftBytesRight(positions = 3))
    }


    @Test
    fun `rCon replace`() {
        val word = Word(listOf(0x05, 0x06, 0x07, 0x08))
        val otherWord = Word(listOf(0x01, 0x02, 0x03, 0x04))

        assertEquals(Word(0x14, 0x04, 0x04, 0x0C), word.rConReplace(5, otherWord))
    }


    @Test
    fun `subBytes replace`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x63, 0x7c, 0x77, 0x7b), word.subBytes())
    }


    @Test
    fun `subBytes reverse replace`() {
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x52, 0x09, 0x6A, 0xD5), word.subBytesInverse())
    }

    @Test
    fun `mixColumns`() {
        val word = Word(0xD4, 0xBF, 0x5D, 0x30)
        val expected = Word(0x04, 0x66, 0x81, 0xE5)

        assertEquals(expected, word.mixColumns())
    }

    @Test
    fun `addKey`() {
        val word = Word(0x04, 0x66, 0x81, 0xE5)
        val key = Word(0xA0, 0xFA, 0xFE, 0x17)
        val expected = Word(0xA4, 0x9C, 0x7F, 0xF2)

        assertEquals(expected, word.addKey(key))
    }
}