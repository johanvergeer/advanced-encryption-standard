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

/**
 * Get the number of keys required to encrypt the states
 *
 * 128 bit key -> 4 words -> 10 rounds
 * 192 bit key -> 6 words -> 12 rounds
 * 256 bit key -> 8 words -> 14 rounds
 */
fun Key.getRoundsCount(): Int {
    // The number of rounds to encrypt the data
    return when (this.size) {
        4 -> 10
        6 -> 12
        else -> 14
    }
}


fun Key.expandKeys(): List<Key> {
    val keys = arrayListOf<Key>()

    // Add the original cypherKey to the list
    keys.add(this)

    // Add a expanded key for each cycle
    for (cycle in 1..this.getRoundsCount()) {
        keys.add(keys.last().expandKey(cycle))
    }

    return keys
}

internal fun Key.expandKey(cycleNo: Int): Key {

    // Last word of the last expanded key or cypher key
    var lastWord = this.last()

    // Create a temporary list for the next key and add the first word
    val nextKeyWords = arrayListOf(lastWord.shiftBytesLeft().subBytes().rConReplace(cycleNo, this[0]))

    // Add the rest of the words to the temporary list
    for (k in 1 until this.size) {
        lastWord = nextKeyWords.last()

        // Add a word with 4 bytes
        nextKeyWords.add(Word((0..3).map { b -> this[k][b] xor lastWord[b] }))
    }

    return Key(nextKeyWords)
}