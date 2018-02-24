package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest


@SpringBootTest
class EncryptorTest {
    lateinit var key: Key
    lateinit var firstExpandedKeyExpectation: Key
    lateinit var lastExpandedKeyExpectation: Key
    lateinit var initialState: State

    lateinit var encryptor: Encryptor

    @BeforeEach
    fun `setup`() {
        this.key = Key(
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


        this.initialState = State(
                Word(0x32, 0x43, 0xF6, 0xA8),
                Word(0x88, 0x5A, 0x30, 0x8D),
                Word(0x31, 0x31, 0x98, 0xA2),
                Word(0xE0, 0x37, 0x07, 0x34)
        )

        this.encryptor = Encryptor(listOf(this.initialState), this.key)
    }

    @Test
    fun `Create list containing expanded keys`() {
        // The list should have a length of 11 keys.

        // expandKeys() is called in init block
//        this.encryptor.expandKeys()

        assertEquals(11, this.encryptor.keys.size)
        assertEquals(this.firstExpandedKeyExpectation, this.encryptor.keys[1])
        assertEquals(this.lastExpandedKeyExpectation, this.encryptor.keys[10])
    }

    @Test
    fun `Create the first expanded key`() {

        val expandedKey = encryptor.expandKey(1, this.key)

        assertEquals(this.firstExpandedKeyExpectation, expandedKey)
    }

    @Test
    fun `Create 10 expanded keys and test the last one`() {

        var lastKey = this.key
        for (round in 1..10) {
            lastKey = encryptor.expandKey(round, lastKey)
        }


        assertEquals(this.lastExpandedKeyExpectation, lastKey)
    }

    @Test
    fun `Encrypt a single state`() {

        val expectedFinalState = listOf(
                State(
                        Word(0x39, 0x25, 0x84, 0x1D),
                        Word(0x02, 0xDC, 0x09, 0xFB),
                        Word(0xDC, 0x11, 0x85, 0x97),
                        Word(0x19, 0x6a, 0x0B, 0x32)
                )
        )

        assertEquals(expectedFinalState, this.encryptor.encryptedStates)
    }
}