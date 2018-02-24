package com.redgyro.algorithms.advancedencryptionstandard

class State : TypedMaxLengthMutableList<Word> {

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
}