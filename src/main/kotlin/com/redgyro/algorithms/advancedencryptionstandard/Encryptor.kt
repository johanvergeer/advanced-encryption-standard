package com.redgyro.algorithms.advancedencryptionstandard


class Encryptor(val content: String, private val cypherKey: Key) {
    internal val keys = mutableListOf<Key>()
    internal var statesInput: List<State>
    internal val statesOutput = mutableListOf<State>()
    private var rounds: Int = 10

    init {
        // The number of rounds to encrypt the data
        this.rounds = when (cypherKey.size) {
            4 -> 10
            6 -> 12
            else -> 14
        }

        // Start with performing key expansion
        this.expandKeys()

        // Get state objects from input string
        this.statesInput = getStatesFromString(this.content)


        // Perform all operations on each state in the states list
        statesInput.forEach { state ->
            for (round in 1..rounds) {
                val wordsOutput = (0..3).map{ wordNo ->
                    val word = state[wordNo]
                    val wordSubBytes = word.subBytes()
                    val wordShiftRows= wordSubBytes.shiftBytesLeft(wordNo)
                    val wordMixColumns = wordShiftRows.mixColumns()
                }


            }
        }
    }

    fun expandKeys() {
        // Add the original cypherKey to the list
        keys.add(cypherKey)

        // Add a expanded key for each cycle
        for (cycle in 1..rounds) {
            keys.add(expandKey(cycle, keys.last()))
        }
    }

    internal fun expandKey(cycleNo: Int, lastKey: Key): Key {
        // Last word of the last expanded key or cypher key
        var lastWord = lastKey.last()

        // Create a temporary list for the next key and add the first word
        val nextKeyWords = arrayListOf(lastWord.shiftBytesLeft().subBytes().rConReplace(cycleNo, lastKey[0]))

        // Add the rest of the words to the temporary list
        for (k in 1 until cypherKey.size) {
            lastWord = nextKeyWords.last()

            // Add a word with 4 bytes
            nextKeyWords.add(Word((0..3).map { b -> lastKey[k][b] xor lastWord[b] }))
        }

        return Key(nextKeyWords)
    }
}