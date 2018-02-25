package com.redgyro.algorithms.advancedencryptionstandard

class State : TypedMaxLengthMutableList<Word> {

    constructor()

    constructor(words: List<Word>) {
        assert(words.size == 4, { "A State object must contain exactly 4 words" })
        this.addAll(words)
    }

    constructor(value1: Word, value2: Word, value3: Word, value4: Word) {
        this.add(value1)
        this.add(value2)
        this.add(value3)
        this.add(value4)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other is State && this.innerList == other.innerList) return true
        return false
    }

    override fun hashCode(): Int {
        return javaClass.hashCode()
    }

    override fun toString(): String {
        return "State:\n${innerList[0]}\n" +
                "${innerList[1]}\n" +
                "${innerList[2]}\n" +
                "${innerList[3]}\n"
    }

    fun subBytes(): State {
        return State((0..3).map { word ->
            this[word].subBytes()
        })
    }

    fun subBytesInverse(): State {
        return State((0..3).map { word ->
            this[word].subBytesInverse()
        })
    }

    fun shiftRows(): State {
        return State(
                Word(this[0][0], this[1][1], this[2][2], this[3][3]),
                Word(this[1][0], this[2][1], this[3][2], this[0][3]),
                Word(this[2][0], this[3][1], this[0][2], this[1][3]),
                Word(this[3][0], this[0][1], this[1][2], this[2][3])
        )
    }

    fun shiftRowsInverse(): State {
        return State(
                Word(this[0][0], this[3][1], this[2][2], this[1][3]),
                Word(this[1][0], this[0][1], this[3][2], this[2][3]),
                Word(this[2][0], this[1][1], this[0][2], this[3][3]),
                Word(this[3][0], this[2][1], this[1][2], this[0][3])
        )
    }

    fun mixColumns(): State {
        return State((0..3).map { word ->
            this[word].mixColumns()
        })
    }

    fun mixColumnsInverse(): State {
        return State((0..3).map { word ->
            this[word].mixColumnsInverse()
        })
    }

    fun addRoundKey(key: Key): State {
        return State((0..3).map { word ->
            this[word].addRoundKey(key[word])
        })
    }

    /**
     * Used for ECB Block Cypher mode
     */
    fun xorOtherState(state: State): State{
        return State((0..3).map { word ->
            this[word].xorOtherWord(state[word])
        })
    }
}


fun State.printStateAfterStepForRound(round: Int, after: String): State {
    val logLines = StringBuilder("ROUND $round $after\n")
    (0..3).forEach { byte ->
        (0..3).forEach { word ->
            logLines.append("0x${java.lang.Integer.toHexString(this[word][byte]).padStart(2, '0')}  ")
        }
        logLines.append("\n")
    }

    println(logLines)

    return this
}