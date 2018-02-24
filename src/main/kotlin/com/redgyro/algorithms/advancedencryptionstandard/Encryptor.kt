package com.redgyro.algorithms.advancedencryptionstandard


class Encryptor(val content: String, private val cypherKey: Key) {
    internal val keys = mutableListOf<Key>()
    private var cycles: Int = 10

    init {
        // The number of cycles to encrypt the data
        this.cycles = when (cypherKey.size) {
            4 -> 10
            6 -> 12
            else -> 14
        }
    }

    fun expandKeys() {
        // Add the original cypherKey to the list
        keys.add(cypherKey)

        // Add a expanded key for each cycle
        for (cycle in 1..cycles) {
            keys.add(expandKey(cycle, keys.last()))
        }
    }

    internal fun expandKey(cycleNo: Int, lastKey: Key): Key {
        // Last word of the last expanded key or cypher key
        var lastWord = lastKey.last()

        // Create a temporary list for the next key and add the first word
        val nextKeyWords = arrayListOf(lastWord.rotateLeft().sBoxReplace().rConReplace(cycleNo, lastKey[0]))

        // Add the rest of the words to the temporary list
        for (k in 1 until cypherKey.size) {
            lastWord = nextKeyWords.last()

            // Add a word with 4 bytes
            nextKeyWords.add(Word((0..3).map { b -> lastKey[k][b] xor lastWord[b] }))
        }

        return Key(nextKeyWords)
    }
}