package com.redgyro.algorithms.advancedencryptionstandard


@Suppress("IMPLICIT_CAST_TO_ANY")
class Encryptor(private val statesInput: List<State>, private val cypherKey: Key) {
//    internal val keys = mutableListOf<Key>()

    private val _encryptedStates = mutableListOf<State>()
    val encryptedStates: List<State>
        get() = _encryptedStates

    init {
        val rounds = cypherKey.getRounds()
        // Start with performing key expansion
        val keys = cypherKey.expandKeys()

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
}