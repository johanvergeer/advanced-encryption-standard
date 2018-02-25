package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class KeyTests {
    lateinit var key128bit: Key
    lateinit var key192bit: Key
    lateinit var key256bit: Key
    private lateinit var firstExpandedKeyExpectation128bit: Key
    private lateinit var lastExpandedKeyExpectation128bit: Key
    private lateinit var firstExpandedKeyExpectation192bit: Key
    lateinit var lastExpandedKeyExpectation192bit: Key

    @BeforeEach
    fun `setUp`() {
        this.key128bit = Key(
                Word(0x2B, 0x7E, 0x15, 0x16),
                Word(0x28, 0xAE, 0xD2, 0xA6),
                Word(0xAB, 0xF7, 0x15, 0x88),
                Word(0x09, 0xCF, 0x4F, 0x3C)
        )

        this.firstExpandedKeyExpectation128bit = Key(
                Word(0xA0, 0xFA, 0xFE, 0x17),
                Word(0x88, 0x54, 0x2C, 0xB1),
                Word(0x23, 0xA3, 0x39, 0x39),
                Word(0x2A, 0x6C, 0x76, 0x05))

        this.lastExpandedKeyExpectation128bit = Key(
                Word(0xD0, 0x14, 0xF9, 0xA8),
                Word(0xC9, 0xEE, 0x25, 0x89),
                Word(0xE1, 0x3F, 0x0C, 0xC8),
                Word(0xB6, 0x63, 0x0C, 0xA6))

        this.key256bit = Key(
                Word(0x2B, 0x7E, 0x15, 0x16),
                Word(0x28, 0xAE, 0xD2, 0xA6),
                Word(0xAB, 0xF7, 0x15, 0x88),
                Word(0xAB, 0xF7, 0x15, 0x88),
                Word(0xAB, 0xF7, 0x15, 0x88),
                Word(0xAB, 0xF7, 0x15, 0x88),
                Word(0xAB, 0xF7, 0x15, 0x88),
                Word(0x09, 0xCF, 0x4F, 0x3C)
        )
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
        assertThrows(AssertionError::class.java,
                {
                    val key = Key(
                            Word(0x00, 0x00, 0x00, 0x00),
                            Word(0x00, 0x00, 0x00, 0x00),
                            Word(0x00, 0x00, 0x00, 0x00)
                    )
                }
        )

    }

    @Test
    fun `Test create key more then 256 bytes`() {
        assertThrows(AssertionError::class.java,
                {
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
        )
    }

    @Test
    fun `Create list containing expanded keys`() {
        val expandedKeys = this.key128bit.expandKeys()

        assertEquals(11, expandedKeys.size)
        assertEquals(this.firstExpandedKeyExpectation128bit, expandedKeys[1])
        assertEquals(this.lastExpandedKeyExpectation128bit, expandedKeys[10])
    }

    @Test
    fun `Test create the first 128 bit expanded key`() {
        val cypherKey = Key(
                Word(0x2b, 0x7e, 0x15, 0x16),
                Word(0x28, 0xae, 0xd2, 0xa6),
                Word(0xab, 0xf7, 0x15, 0x88),
                Word(0x09, 0xcf, 0x4f, 0x3c)
        )

        val expected = Key(
                Word(0xa0, 0xfa, 0xfe, 0x17),
                Word(0x88, 0x54, 0x2c, 0xb1),
                Word(0x23, 0xa3, 0x39, 0x39),
                Word(0x2a, 0x6c, 0x76, 0x05)
        )

        assertEquals(expected, cypherKey.expandKey(1))
    }

    @Test
    fun `Create 10 128 bit expanded keys and test the last one`() {

        var lastKey = this.key128bit
        for (round in 1..10) {
            lastKey = lastKey.expandKey(round)
        }

        assertEquals(this.lastExpandedKeyExpectation128bit, lastKey)
    }

    @Test
    fun `Test first 6 byte expanded key on keyExpansion for 192 bit key`() {
        this.key192bit = Key(
                Word(0x8e, 0x73, 0xb0, 0xf7),
                Word(0xda, 0x0e, 0x64, 0x52),
                Word(0xc8, 0x10, 0xf3, 0x2b),
                Word(0x80, 0x90, 0x79, 0xe5),
                Word(0x62, 0xf8, 0xea, 0xd2),
                Word(0x52, 0x2c, 0x6b, 0x7b))

        this.firstExpandedKeyExpectation192bit = Key(
                Word(0xfe, 0x0c, 0x91, 0xf7),
                Word(0x24, 0x02, 0xf5, 0xa5),
                Word(0xec, 0x12, 0x06, 0x8e),
                Word(0x6c, 0x82, 0x7f, 0x6b),
                Word(0x0e, 0x7a, 0x95, 0xb9),
                Word(0x5c, 0x56, 0xfe, 0xc2))

        val expandedKey = this.key192bit.expandKey(1)

        assertEquals(this.firstExpandedKeyExpectation192bit, expandedKey)
    }

    @Test
    fun `Test last 6 byte expanded key on keyExpansion for 192 bit key`() {
        key192bit = Key(
                Word(0x8e, 0x73, 0xb0, 0xf7),
                Word(0xda, 0x0e, 0x64, 0x52),
                Word(0xc8, 0x10, 0xf3, 0x2b),
                Word(0x80, 0x90, 0x79, 0xe5),
                Word(0x62, 0xf8, 0xea, 0xd2),
                Word(0x52, 0x2c, 0x6b, 0x7b))

        lastExpandedKeyExpectation192bit = Key(
                Word(0xe9, 0x8b, 0xa0, 0x6f),
                Word(0x44, 0x8c, 0x77, 0x3c),
                Word(0x8e, 0xcc, 0x72, 0x04),
                Word(0x01, 0x00, 0x22, 0x02))

        var lastKey = key192bit

        for (round in 1..8) {
            lastKey = lastKey.expandKey(round)
        }

        // Only the first 4 bytes of the last 6 byte expanded key are used
        assertEquals(lastExpandedKeyExpectation192bit.slice(0..3), lastKey.slice(0..3))
    }

    @Test
    fun `Test key expansion for 192 bit key`() {
        key192bit = Key(
                Word(0x8e, 0x73, 0xb0, 0xf7),
                Word(0xda, 0x0e, 0x64, 0x52),
                Word(0xc8, 0x10, 0xf3, 0x2b),
                Word(0x80, 0x90, 0x79, 0xe5),
                Word(0x62, 0xf8, 0xea, 0xd2),
                Word(0x52, 0x2c, 0x6b, 0x7b))

        val firstExpectedKey = Key(
                Word(0x8e, 0x73, 0xb0, 0xf7),
                Word(0xda, 0x0e, 0x64, 0x52),
                Word(0xc8, 0x10, 0xf3, 0x2b),
                Word(0x80, 0x90, 0x79, 0xe5))

        val lastExpandedKey = Key(
                Word(0xe9, 0x8b, 0xa0, 0x6f),
                Word(0x44, 0x8c, 0x77, 0x3c),
                Word(0x8e, 0xcc, 0x72, 0x04),
                Word(0x01, 0x00, 0x22, 0x02))

        val expandedKeys = key192bit.expandKeys()

        assertEquals(firstExpectedKey, expandedKeys.first())
        assertEquals(lastExpandedKey, expandedKeys.last())
    }
}