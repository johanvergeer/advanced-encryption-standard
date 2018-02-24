package com.redgyro.algorithms.advancedencryptionstandard

import com.sun.org.apache.xpath.internal.operations.Bool


@Suppress("IMPLICIT_CAST_TO_ANY")
class Encryptor(private val statesInput: List<State>, private val cypherKey: Key) {
    internal val keys = mutableListOf<Key>()
    //    private var statesInput: List<State>
    private var rounds: Int = 10

    private val _encryptedStates = mutableListOf<State>()
    val encryptedStates: List<State>
        get() = _encryptedStates

    init {
        // The number of rounds to encrypt the data
        this.rounds = when (cypherKey.size) {
            4 -> 10
            6 -> 12
            else -> 14
        }

        // Start with performing key expansion
        this.expandKeys()

        // Perform all operations on each state in the states list
        statesInput.forEach { state ->
            var roundState = state

            roundState.printState(0, "Before add round key")
            roundState = roundState.addRoundKey(keys[0])
            roundState.printState(0, "After add round key")

            (1 until rounds).forEach { round ->
                roundState = roundState
                        .subBytes()
                        .printState(round, "Sub Bytes")
                        .shiftRows()
                        .printState(round, "Shift Rows")
                        .mixColumns()
                        .printState(round, "Mix Columns")
                        .addRoundKey(keys[round])
                        .printState(round, "Add round key")
            }

            roundState = roundState
                    .subBytes()
                    .printState(keys.size, "Sub Bytes")
                    .shiftRows()
                    .printState(keys.size, "Shift Rows")
                    .addRoundKey(keys.last())
                    .printState(keys.size, "Add round key")

            _encryptedStates.add(roundState)
        }
    }

    private fun State.printState(round: Int, after: String): State {
        val logLines = StringBuilder("ROUND $round AFTER $after\n")
        (0..3).forEach { byte ->
            (0..3).forEach { word ->
                logLines.append("0x${java.lang.Integer.toHexString(this[word][byte]).padStart(2, '0')}  ")
            }
            logLines.append("\n")
        }

        println(logLines)

        return this
    }

    private fun expandKeys() {
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