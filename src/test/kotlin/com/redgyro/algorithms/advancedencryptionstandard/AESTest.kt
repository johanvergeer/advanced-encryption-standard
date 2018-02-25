package com.redgyro.algorithms.advancedencryptionstandard

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

/**
 * Used to test all values except for ECB:
 *  Text: Hello to everyone in this beautiful world full of wonderful people
 *  Hex (Converted using https://codebeautify.org/string-hex-converter):
 *      48 65 6c 6c
 *      6f 20 74 6f
 *      20 65 76 65
 *      72 79 6f 6e
 *
 *      65 20 69 6e
 *      20 74 68 69
 *      73 20 62 65
 *      61 75 74 69
 *
 *      66 75 6c 20
 *      77 6f 72 6c
 *      64 20 66 75
 *      6c 6c 20 6f
 *
 *      66 20 77 6f
 *      6e 64 65 72
 *      66 75 6c 20
 *      70 65 6f 70
 *
 *      6c 65
 *
 * 128 bit Key used: 77 0A 8A 65 DA 15 6D 24 EE 2A 09 32 77 53 01 42
 *
 * Initial vector used: da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90
 *
 * Regex input to convert results from http://aes.online-domain-tools.com/ to State object:
 * Search: \/\/        ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2}) ([a-z0-9]{2})
 * Replace with: State(\nWord(0x$1, 0x$2, 0x$3, 0x$4), \nWord(0x$5, 0x$6, 0x$7, 0x$8), \nWord(0x$9, 0x$10, 0x$11, 0x$12), \nWord(0x$13, 0x$14, 0x$15, 0x$16)\n)
 */

@SpringBootTest
class AESTest {
    lateinit var key: Key
    lateinit var key128bit: Key
    lateinit var initializationVector: State
    lateinit var firstExpandedKeyExpectation: Key
    lateinit var lastExpandedKeyExpectation: Key
    lateinit var initialState: State
    lateinit var initialStates: List<State>

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

        this.key128bit = Key(
                Word(0x77, 0x0A, 0x8A, 0x65),
                Word(0xDA, 0x15, 0x6D, 0x24),
                Word(0xEE, 0x2A, 0x09, 0x32),
                Word(0x77, 0x53, 0x01, 0x42)
        )

        this.initializationVector = State(
                Word(0xda, 0x39, 0xa3, 0xee),
                Word(0x5e, 0x6b, 0x4b, 0x0d),
                Word(0x32, 0x55, 0xbf, 0xef),
                Word(0x95, 0x60, 0x18, 0x90)
        )

        this.initialStates = listOf(
                State(
                        Word(0x48, 0x65, 0x6c, 0x6c),
                        Word(0x6f, 0x20, 0x74, 0x6f),
                        Word(0x20, 0x65, 0x76, 0x65),
                        Word(0x72, 0x79, 0x6f, 0x6e)
                ),
                State(
                        Word(0x65, 0x20, 0x69, 0x6e),
                        Word(0x20, 0x74, 0x68, 0x69),
                        Word(0x73, 0x20, 0x62, 0x65),
                        Word(0x61, 0x75, 0x74, 0x69)
                ),
                State(
                        Word(0x66, 0x75, 0x6c, 0x20),
                        Word(0x77, 0x6f, 0x72, 0x6c),
                        Word(0x64, 0x20, 0x66, 0x75),
                        Word(0x6c, 0x6c, 0x20, 0x6f)
                ),
                State(
                        Word(0x66, 0x20, 0x77, 0x6f),
                        Word(0x6e, 0x64, 0x65, 0x72),
                        Word(0x66, 0x75, 0x6c, 0x20),
                        Word(0x70, 0x65, 0x6f, 0x70)
                ),
                State(
                        Word(0x6c, 0x65, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00)
                )
        )

        val expectedStatesCFB = listOf(
                State(
                        Word(0xe3, 0x30, 0x34, 0x0f),
                        Word(0x4c, 0xe0, 0x80, 0x9b),
                        Word(0x74, 0x42, 0xd8, 0xa1),
                        Word(0x14, 0xe3, 0x00, 0x4e)
                ),
                State(
                        Word(0x7f, 0x9e, 0x6d, 0x2d),
                        Word(0x0a, 0x6b, 0x9b, 0x91),
                        Word(0xa8, 0x4c, 0x87, 0x29),
                        Word(0x50, 0x0d, 0x34, 0x8d)
                ),
                State(
                        Word(0xb1, 0x72, 0xd3, 0x21),
                        Word(0x27, 0xbd, 0xe5, 0xc4),
                        Word(0x15, 0x98, 0xa4, 0xb8),
                        Word(0x3e, 0xa6, 0xb8, 0x5f)
                ),
                State(
                        Word(0xcc, 0x82, 0x74, 0x55),
                        Word(0xad, 0xf2, 0xeb, 0x57),
                        Word(0x75, 0xd2, 0xbe, 0x12),
                        Word(0x7f, 0x1d, 0x21, 0xbf)
                ),
                State(
                        Word(0x99, 0x95, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00)
                )
        )

        val expectedStatesOFB = listOf(
                State(
                        Word(0xe3, 0xe2, 0x52, 0xe1),
                        Word(0xff, 0x0f, 0xd1, 0x66),
                        Word(0x42, 0x32, 0x5d, 0x7b),
                        Word(0x74, 0xf4, 0x3f, 0xfe)
                ),
                State(
                        Word(0x9d, 0x78, 0xc4, 0xe3),
                        Word(0xe3, 0x95, 0xa8, 0x82),
                        Word(0xe7, 0xa1, 0x18, 0xd2),
                        Word(0x36, 0x04, 0x51, 0xf8)
                ),
                State(
                        Word(0x5b, 0xfd, 0x4b, 0xeb),
                        Word(0x69, 0xe6, 0x38, 0x0f),
                        Word(0x9b, 0x8f, 0x53, 0x04),
                        Word(0x0e, 0xc4, 0xd9, 0xe1)
                ),
                State(
                        Word(0xd9, 0x15, 0x2e, 0xa6),
                        Word(0x06, 0x30, 0x16, 0xaa),
                        Word(0xd8, 0xc3, 0xb0, 0x80),
                        Word(0x78, 0xd4, 0x8c, 0xf7)
                ),
                State(
                        Word(0xfc, 0x44, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00),
                        Word(0x00, 0x00, 0x00, 0x00)
                )
        )
    }

    @Test
    fun `Encrypt a single state using ECB`() {

        val expectedFinalState = listOf(
                State(
                        Word(0x39, 0x25, 0x84, 0x1D),
                        Word(0x02, 0xDC, 0x09, 0xFB),
                        Word(0xDC, 0x11, 0x85, 0x97),
                        Word(0x19, 0x6a, 0x0B, 0x32)
                )
        )

        val aes = AES(listOf(this.initialState), this.key)

        assertEquals(expectedFinalState, aes.encrypt())
    }

    @Test
    fun `Decrypt a single state using ECB`() {
        val encryptedState = AES(listOf(this.initialState), this.key).encrypt()
        val decryptedState = AES(encryptedState, this.key).decrypt()

        assertEquals(this.initialState, decryptedState.first())
    }

    @Test
    fun `Encrypt a list of states using ECB`() {

        val expectedFinalState = listOf(
                State(
                        Word(0xe8, 0x6c, 0x7b, 0x0c),
                        Word(0x9a, 0x39, 0x42, 0xa2),
                        Word(0x8a, 0xc6, 0x45, 0x44),
                        Word(0x51, 0xa9, 0xda, 0x0c)
                ),
                State(
                        Word(0xf8, 0xd3, 0xa5, 0xc6),
                        Word(0x49, 0xbc, 0x4a, 0x49),
                        Word(0x79, 0xd7, 0x84, 0xe9),
                        Word(0xdc, 0xe9, 0x94, 0xe9)
                ),
                State(
                        Word(0x5f, 0x6f, 0x87, 0x34),
                        Word(0xf7, 0xe8, 0x94, 0xb7),
                        Word(0x29, 0x4d, 0x14, 0xa1),
                        Word(0x09, 0x31, 0x49, 0xc6)
                ),
                State(
                        Word(0x60, 0xbc, 0x6d, 0xb0),
                        Word(0x1c, 0xf1, 0x43, 0x1c),
                        Word(0x5e, 0x10, 0x12, 0x14),
                        Word(0x73, 0xa8, 0x65, 0xba)
                ),
                State(
                        Word(0x2d, 0xf6, 0x39, 0x2c),
                        Word(0x88, 0xe4, 0xf6, 0x94),
                        Word(0x3e, 0x85, 0x0c, 0xc6),
                        Word(0xbe, 0xba, 0xc9, 0xd8)
                )
        )

        val aes = AES(this.initialStates, this.key128bit)

        assertEquals(expectedFinalState, aes.encrypt())
    }

    @Test
    fun `Encrypt and Decrypt a list of states using ECB`() {
        val encryptedState = AES(this.initialStates, this.key128bit).encrypt()
        val decryptedState = AES(encryptedState, this.key128bit).decrypt()

        assertEquals(this.initialStates, decryptedState)
    }

    @Test
    fun `Encrypt a list of states using CBC`() {

        val expectedStatesCBC = listOf(
                State(
                        Word(0xbc, 0xa7, 0x83, 0xa0),
                        Word(0xb9, 0xc3, 0xcf, 0x6f),
                        Word(0x67, 0x53, 0x8b, 0xba),
                        Word(0x41, 0x81, 0x7c, 0x5b)
                ),
                State(
                        Word(0xad, 0xd1, 0x58, 0x6a),
                        Word(0x39, 0x5e, 0xf5, 0xb7),
                        Word(0x5e, 0x37, 0x35, 0x9e),
                        Word(0xf0, 0xc7, 0x40, 0x00)
                ),
                State(
                        Word(0x46, 0x72, 0x9d, 0x0b),
                        Word(0x12, 0x18, 0x00, 0x1b),
                        Word(0x2d, 0xeb, 0x79, 0x55),
                        Word(0xbc, 0x9d, 0x61, 0x03)
                ),
                State(
                        Word(0xf9, 0xee, 0x13, 0x35),
                        Word(0x29, 0xf6, 0xb5, 0xd6),
                        Word(0xc3, 0xfc, 0x5a, 0xbc),
                        Word(0xa3, 0xbe, 0x9f, 0x1f)
                ),
                State(
                        Word(0xde, 0x25, 0x4d, 0x3e),
                        Word(0xb7, 0x18, 0x96, 0xe3),
                        Word(0x76, 0x8e, 0x38, 0xbd),
                        Word(0x80, 0x29, 0xa3, 0x9f)
                )
        )

        val aes = AES(this.initialStates,
                this.key128bit,
                BlockCypherMode.CBC,
                this.initializationVector)

        assertEquals(expectedStatesCBC, aes.encrypt())
    }

    @Test
    fun `Decrypt a list of states using CBC`() {

        val encryptedState = AES(
                this.initialStates,
                this.key128bit,
                BlockCypherMode.CBC,
                this.initializationVector).encrypt()

        val decryptedState = AES(
                encryptedState,
                this.key128bit,
                BlockCypherMode.CBC,
                this.initializationVector
        ).decrypt()

        assertEquals(this.initialStates, decryptedState)
    }
}