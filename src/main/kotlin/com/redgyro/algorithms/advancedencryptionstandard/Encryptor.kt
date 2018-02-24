package com.redgyro.algorithms.advancedencryptionstandard


class Encryptor(val content: String, private val cypherKey: Key) {
    private val keys = mutableListOf<Key>()
    private var cycles: Int = 10

    init {
        // The number of cycles to encrypt the data
        this.cycles = when (cypherKey.size) {
            4 -> 10
            6 -> 12
            else -> 14
        }
    }

    fun createExpandedKeys() {
        // Add the original cypherKey to the list
        keys.add(cypherKey)

        // Add a expanded key for each cycle
        for (i in 0 until cycles) {
            val lastKey = keys.last()
            // Last word of the last expanded key or cypher key
            var lastWord = lastKey.last()

            // Create a temporary list for the next key and add the first word
            val nextKeyWords = arrayListOf(lastWord.rotateLeft().sBoxReplace().rConReplace(i, lastKey[0]))

            // Add the rest of the words to the temporary list
            for (k in 1 until cypherKey.size) {
                lastWord = nextKeyWords.last()

                // Add a word with 4 bytes
                nextKeyWords.add(Word((1 until 4).map { b -> lastKey[k][b] xor lastWord[b] }))
            }

            keys.add(Key(nextKeyWords))
        }
    }
}