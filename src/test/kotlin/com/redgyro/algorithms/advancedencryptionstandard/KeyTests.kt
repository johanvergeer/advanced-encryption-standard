package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class KeyTests {
    lateinit var key128bit: Key
    lateinit var firstExpandedKeyExpectation: Key
    lateinit var lastExpandedKeyExpectation: Key

    @BeforeEach
    fun `setUp`(){
        this.key128bit = Key(
                Word(0x2B, 0x7E, 0x15, 0x16),
                Word(0x28, 0xAE, 0xD2, 0xA6),
                Word(0xAB, 0xF7, 0x15, 0x88),
                Word(0x09, 0xCF, 0x4F, 0x3C)
        )

        this.firstExpandedKeyExpectation = Key(
                Word(0xA0, 0xFA, 0xFE, 0x17),
                Word(0x88, 0x54, 0x2C, 0xB1),
                Word(0x23, 0xA3, 0x39, 0x39),
                Word(0x2A, 0x6C, 0x76, 0x05))

        this.lastExpandedKeyExpectation = Key(
                Word(0xD0, 0x14, 0xF9, 0xA8),
                Word(0xC9, 0xEE, 0x25, 0x89),
                Word(0xE1, 0x3F, 0x0C, 0xC8),
                Word(0xB6, 0x63, 0x0C, 0xA6))
    }

    @Test
    fun `Test create key 128 bytes`() {
        val key = Key(
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00),
                Word(0x00, 0x00, 0x00, 0x00)
        )

        assertEquals(4, key.size)
    }

    @Test
    fun `Test create key 192 bytes`() {
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
    fun `Test create key 256 bytes`() {
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

    @Test
    fun `Test create key less then 128 bytes`() {
        assertThrows<AssertionError> {
            val key = Key(
                    Word(0x00, 0x00, 0x00, 0x00),
                    Word(0x00, 0x00, 0x00, 0x00),
                    Word(0x00, 0x00, 0x00, 0x00)
            )
        }

    }

    @Test
    fun `Test create key more then 256 bytes`() {
        assertThrows<AssertionError> {
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

    @org.junit.jupiter.api.Test
    fun `Create list containing expanded keys`() {
        val expandedKeys = this.key128bit.expandKeys()

        Assertions.assertEquals(11, expandedKeys.size)
        Assertions.assertEquals(this.firstExpandedKeyExpectation, expandedKeys[1])
        Assertions.assertEquals(this.lastExpandedKeyExpectation, expandedKeys[10])
    }

    @org.junit.jupiter.api.Test
    fun `Create the first expanded key`() {

        val expandedKey = this.key128bit.expandKey(1)

        Assertions.assertEquals(this.firstExpandedKeyExpectation, expandedKey)
    }

    @org.junit.jupiter.api.Test
    fun `Create 10 expanded keys and test the last one`() {

        var lastKey = this.key128bit
        for (round in 1..10) {
            lastKey = lastKey.expandKey(round)
        }

        Assertions.assertEquals(this.lastExpandedKeyExpectation, lastKey)
    }

}