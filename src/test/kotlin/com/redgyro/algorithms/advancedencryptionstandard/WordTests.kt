package com.redgyro.algorithms.advancedencryptionstandard

import junit.framework.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringRunner


@RunWith(SpringRunner::class)
@SpringBootTest
class WordTests {

    @Test
    fun `Create new word from 4 separate bytes`(){
        val word = Word(0x00, 0x01, 0x02, 0x03)

        assertEquals(4, word.size)
    }

    @Test
    fun `Create new word list with four bytes`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(4, word.size)
    }

    @Test(expected = AssertionError::class)
    fun `Create new word less then 4 bytes`(){
        val word = Word(listOf(0x00, 0x01, 0x02))
    }

    @Test(expected = AssertionError::class)
    fun `Create new word more then 4 bytes`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03, 0x04))
    }


    @Test
    fun `Rotate bytes left 1 position`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x01, 0x02, 0x03, 0x00), word.rotateLeft())
    }


    @Test
    fun `Rotate bytes left 1 position explicit`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x01, 0x02, 0x03, 0x00), word.rotateLeft(positions = 1))
    }


    @Test
    fun `Rotate bytes left 2 positions`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x02, 0x03, 0x00, 0x01), word.rotateLeft(positions = 2))
    }


    @Test
    fun `Rotate bytes left 3 positions`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x03, 0x00, 0x01, 0x02), word.rotateLeft(positions = 3))
    }


    @Test
    fun `Rotate bytes Right 1 position`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x03, 0x00, 0x01, 0x02), word.rotateRight())
    }


    @Test
    fun `Rotate bytes Right 1 position explicit`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x03, 0x00, 0x01, 0x02), word.rotateRight(positions = 1))
    }


    @Test
    fun `Rotate bytes Right 2 positions`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x02, 0x03, 0x00, 0x01), word.rotateRight(positions = 2))
    }


    @Test
    fun `Rotate bytes Right 3 positions`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x01, 0x02, 0x03, 0x00), word.rotateRight(positions = 3))
    }


    @Test
    fun `rCon replace`(){
        val word = Word(listOf(0x05, 0x06, 0x07, 0x08))
        val otherWord = Word(listOf(0x01, 0x02, 0x03, 0x04))

        assertEquals(Word(0x14, 0x04, 0x04, 0x0C), word.rConReplace(5, otherWord))
    }


    @Test
    fun `sBox replace`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x63, 0x7c, 0x77, 0x7b), word.sBoxReplace())
    }


    @Test
    fun `sBox reverse replace`(){
        val word = Word(listOf(0x00, 0x01, 0x02, 0x03))

        assertEquals(Word(0x52, 0x09, 0x6A, 0xD5), word.sBoxInverseReplace())
    }
}