package com.redgyro.algorithms.advancedencryptionstandard

class Key(val words: List<Word>) : TypedMaxLengthMutableList<Word>(maxSize = 8) {

    constructor(vararg words: Word) : this(words.toList())

    init {
        assert(words.size in listOf(4, 6, 8), { "Key can hold 4, 6 or 8 words. (128, 192 or 256 bytes)" })

        this.innerList.addAll(this.words)
    }

    override fun toString(): String {
        return "Key:\n${words[0]}\n" +
                "${words[1]}\n" +
                "${words[2]}\n" +
                "${words[3]}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other is Key && this.innerList == other.innerList) return true

        return false
    }

    override fun hashCode(): Int {
        return words.hashCode()
    }


}