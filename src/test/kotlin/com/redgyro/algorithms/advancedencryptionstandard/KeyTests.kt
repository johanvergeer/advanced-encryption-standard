package com.redgyro.algorithms.advancedencryptionstandard

import junit.framework.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
@SpringBootTest
class KeyTests {

    @Test
    fun `Test create key 128 bytes`(){
        val key = Key(
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00)
        )

        assertEquals(4, key.size)
    }

    @Test
    fun `Test create key 192 bytes`(){
        val key = Key(
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00)
        )

        assertEquals(6, key.size)
    }

    @Test
    fun `Test create key 256 bytes`(){
        val key = Key(
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00)
        )

        assertEquals(8, key.size)
    }

    @Test(expected = AssertionError::class)
    fun `Test create key less then 128 bytes`(){
        val key = Key(
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00)
        )
    }

    @Test(expected = AssertionError::class)
    fun `Test create key more then 256 bytes`(){
        val key = Key(
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00)
        )
    }

}