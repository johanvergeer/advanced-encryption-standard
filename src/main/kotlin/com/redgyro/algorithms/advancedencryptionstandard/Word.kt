package com.redgyro.algorithms.advancedencryptionstandard

import com.redgyro.algorithms.advancedencryptionstandard.transformationTables.*

class Word : TypedMaxLengthMutableList<Int> {

    constructor(values: List<Int>) {
        assert(values.size == 4, { "Word must hold exactly 4 hexadecimal values" })

        innerList.addAll(values)

        validateInnerListValues()
    }

    constructor(value1: Int, value2: Int, value3: Int, value4: Int) {
        innerList.add(value1)
        innerList.add(value2)
        innerList.add(value3)
        innerList.add(value4)

        validateInnerListValues()
    }

    private fun validateInnerListValues() {
        innerList.forEach { value ->
            assert(value in 0x00..0xFF, { "Each value must be a hexadecimal" })
        }
    }

    /**
     * Perform SubBytes operation using sBox
     */
    fun subBytes(): Word {
        return Word(listOf(sBox[this[0]], sBox[this[1]], sBox[this[2]], sBox[this[3]]))
    }

    /**
     * Perform SubBytes operation using inverse sBox
     */
    fun subBytesInverse(): Word {
        return Word(listOf(sBoxInverse[this[0]], sBoxInverse[this[1]], sBoxInverse[this[2]], sBoxInverse[this[3]]))
    }


    /**
     * Use the rCon table and another word to create a new word
     *
     * @sample
     *  word        this        rCon
     *  ----        ----        ----
     *  0x01  xor   0x05  xor   0x10  = 0x14
     *  0x02  xor   0x06  xor   0x00  = 0X04
     *  0x03  xor   0x07  xor   0x00  = 0X04
     *  0x04  xor   0x08  xor   0x00  = 0X0C
     */
    fun rConReplace(i: Int, word: Word): Word = Word((0 until 4).map { b -> word[b] xor this[b] xor rCon[i][b] })

    /**
     * Rotate a word left
     *
     * @param positions The number of positions the bytes should rotate
     */
    fun shiftBytesLeft(positions: Int = 1): Word {
        return when (positions) {
            1 -> Word(this[1], this[2], this[3], this[0])
            2 -> Word(this[2], this[3], this[0], this[1])
            3 -> Word(this[3], this[0], this[1], this[2])
            else -> Word(this)
        }
    }

    /**
     * Rotate a word right
     */
    fun shiftBytesRight(positions: Int = 1): Word {
        return when (positions) {
            1 -> Word(this[3], this[0], this[1], this[2])
            2 -> Word(this[2], this[3], this[0], this[1])
            3 -> Word(this[1], this[2], this[3], this[0])
            else -> Word(this)
        }
    }

    fun mixColumns(): Word {
        return Word(
                mul2[this[0]] xor mul3[this[1]] xor this[2] xor this[3],
                this[0] xor mul2[this[1]] xor mul3[this[2]] xor this[3],
                this[0] xor this[1] xor mul2[this[2]] xor mul3[this[3]],
                mul3[this[0]] xor this[1] xor this[2] xor mul2[this[3]]
        )
    }

    fun mixColumnsInverse(): Word {
        return Word(
                mul14[this[0]] xor mul11[this[1]] xor mul13[this[2]] xor mul9[this[3]],
                mul9[this[0]] xor mul14[this[1]] xor mul11[this[2]] xor mul13[this[3]],
                mul13[this[0]] xor mul9[this[1]] xor mul14[this[2]] xor mul11[this[3]],
                mul11[this[0]] xor mul13[this[1]] xor mul9[this[2]] xor mul14[this[3]]
        )
    }

    fun xorOtherWord(otherWord: Word): Word {
        return Word(
                this[0] xor otherWord[0],
                this[1] xor otherWord[1],
                this[2] xor otherWord[2],
                this[3] xor otherWord[3]
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other is Word && other.innerList == this.innerList) return true
        return false
    }

    override fun hashCode(): Int {
        return javaClass.hashCode()
    }

    override fun toString(): String {
        return this.joinToString(
                separator = ", ",
                transform = { i -> "0x${java.lang.Integer.toHexString(i).padStart(2, '0').toUpperCase()}" })
    }


}
