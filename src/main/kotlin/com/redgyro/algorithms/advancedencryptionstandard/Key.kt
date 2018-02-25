package com.redgyro.algorithms.advancedencryptionstandard

import kotlin.math.exp

class Key(private val words: List<Word>) : TypedMaxLengthMutableList<Word>(maxSize = 8) {
    var keyLength: Int = 0
        private set
    var numberOfRounds = 0
        private set

    constructor(vararg words: Word) : this(words.toList())

    init {
        assert(words.size in listOf(4, 6, 8), { "Key can hold 4, 6 or 8 words. (128, 192 or 256 bytes)" })

        this.innerList.addAll(this.words)

        // Key length property is only to match the AES standard descriptions
        keyLength = this.size

        /**
         * Set the number of keys required to encrypt the states
         *
         * 128 bit key -> 4 words -> 10 rounds
         * 192 bit key -> 6 words -> 12 rounds
         * 256 bit key -> 8 words -> 14 rounds
         */
        numberOfRounds = when (this.keyLength) {
            4 -> 10
            6 -> 12
            8 -> 14
            else -> throw IllegalArgumentException("keyLength must be 4, 6 or 8")
        }
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


    fun expandKeys(): List<Key> {
        val expandedKeys = arrayListOf<Key>()

        when (this.keyLength) {
            4 -> {
                // Add the original cypherKey to the list
                expandedKeys.add(this)

                // Add a expanded key for each cycle
                for (round in 1..this.numberOfRounds) {
                    expandedKeys.add(expandedKeys.last().expand128bitKey(round))
                }

                return expandedKeys
            }
            6 -> {
                return expandedKeys
            }
            8 -> {
                return expandedKeys
            }
            else -> throw IllegalArgumentException("keyLength must be 4, 6 or 8")
        }
    }

    internal fun expand128bitKey(cycleNo: Int): Key {

        // Last word of the last expanded key or cypher key
        var lastWord = this.last()

        // Create a temporary list for the next key and add the first word
        val nextKeyWords = arrayListOf(lastWord.shiftBytesLeft().subBytes().rConReplace(cycleNo, this[0]))

        // Add the rest of the words to the temporary list
        for (k in 1 until this.keyLength) {
            lastWord = nextKeyWords.last()

            // Add a word with 4 bytes
            nextKeyWords.add(Word((0..3).map { b -> this[k][b] xor lastWord[b] }))
        }

        return Key(nextKeyWords)
    }

    internal fun expand192bitKey(cycleNo: Int): Key {
        return Key()
    }
}