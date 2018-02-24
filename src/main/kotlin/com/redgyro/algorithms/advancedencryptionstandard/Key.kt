package com.redgyro.algorithms.advancedencryptionstandard

class Key(val words: List<Word>) : TypedMaxLengthMutableList<Word>(maxSize = 8) {

    constructor(vararg words: Word): this(words.toList())

    init {
        assert(words.size in listOf(4, 6, 8), { "Key can hold 4, 6 or 8 words. (128, 192 or 256 bytes)" })

        this.innerList.addAll(this.words)
    }
}