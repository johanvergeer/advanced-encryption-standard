package com.redgyro.algorithms.advancedencryptionstandard

fun aesEncrypt(statesInput: List<State>, cypherKey: Key): List<State> {
    val encryptedStates = arrayListOf<State>()

    val rounds = cypherKey.getRoundsCount()
    // Start with performing key expansion
    val keys = cypherKey.expandKeys()

    // Perform all operations on each state in the states list
    statesInput.forEach { state ->
        var roundState = state

        roundState.printStateAfterStepForRound(0, "Before add round key")
        roundState = roundState.addRoundKey(keys.first())
        roundState.printStateAfterStepForRound(0, "After add round key")

        (1 until rounds).forEach { round ->
            roundState = roundState
                    .subBytes()
                    .printStateAfterStepForRound(round, "Sub Bytes")
                    .shiftRows()
                    .printStateAfterStepForRound(round, "Shift Rows")
                    .mixColumns()
                    .printStateAfterStepForRound(round, "Mix Columns")
                    .addRoundKey(keys[round])
                    .printStateAfterStepForRound(round, "Add round key")
        }

        roundState = roundState
                .subBytes()
                .printStateAfterStepForRound(rounds, "Sub Bytes")
                .shiftRows()
                .printStateAfterStepForRound(rounds, "Shift Rows")
                .addRoundKey(keys.last())
                .printStateAfterStepForRound(rounds, "Add round key")

        encryptedStates.add(roundState)
    }

    return encryptedStates
}

fun aesDecrypt(statesInput: List<State>, cypherKey: Key): List<State> {
    val decryptedStates = arrayListOf<State>()

    val rounds = cypherKey.getRoundsCount()
    // Start with performing key expansion
    val keys = cypherKey.expandKeys()

    // Perform all operations on each state in the states list
    statesInput.forEach { state ->
        var roundState = state

        roundState.printStateAfterStepForRound(0, "Before add round key")
        roundState = roundState.addRoundKey(keys.last())
        roundState.printStateAfterStepForRound(0, "After add round key")

        (rounds - 1 downTo 1).forEach { round ->
            val roundToPrint = rounds - round

            roundState = roundState
                    .shiftRowsInverse()
                    .printStateAfterStepForRound(roundToPrint, "Shift Rows Inverse")
                    .subBytesInverse()
                    .printStateAfterStepForRound(roundToPrint, "Sub Bytes inverse")
                    .addRoundKey(keys[round])
                    .printStateAfterStepForRound(roundToPrint, "Add round key")
                    .mixColumnsInverse()
                    .printStateAfterStepForRound(roundToPrint, "Mix Columns inverse")
        }

        roundState = roundState
                .shiftRowsInverse()
                .printStateAfterStepForRound(rounds, "Shift rows inverse")
                .subBytesInverse()
                .printStateAfterStepForRound(rounds, "Sub Bytes inverse")
                .addRoundKey(keys.first())
                .printStateAfterStepForRound(rounds, "Add round key")

        decryptedStates.add(roundState)
    }

    return decryptedStates
}
