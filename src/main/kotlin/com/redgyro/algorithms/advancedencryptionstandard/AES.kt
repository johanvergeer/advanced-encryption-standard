package com.redgyro.algorithms.advancedencryptionstandard

/**
 * Encrypt a State block using AES encryption
 *
 * @param statesInput List of state objects, each containing 4 Word objects
 * @param cypherKey Public key used to encrypt the states
 * @param blockCypherMode One of the BlockCypherMode Enum values
 * @param initializationVector State object containing Word objects with random bytes
 *  required when blockCypherMode is CBC
 *  The same initializationVector is required for decrypting the CypherText
 */
fun aesEncrypt(
        statesInput: List<State>,
        cypherKey: Key,
        blockCypherMode: BlockCypherMode = BlockCypherMode.ECB,
        initializationVector: State = State()): List<State> {

    val encryptedStates = arrayListOf<State>()
    var iv = initializationVector

    // Perform all operations on each state in the states list
    statesInput.forEach { state ->
        if (blockCypherMode == BlockCypherMode.CBC && encryptedStates.size > 0)
            iv = encryptedStates.last()

        encryptedStates.add(aesEncryptBlock(state, cypherKey, blockCypherMode, iv))
    }

    return encryptedStates
}

fun aesEncryptBlock(state: State,
                    cypherKey: Key,
                    blockCypherMode: BlockCypherMode = BlockCypherMode.ECB,
                    initializationVector: State = State()): State {

    if (blockCypherMode == BlockCypherMode.CBC && initializationVector.size == 0)
        throw IllegalArgumentException("initializationVector state cannot be empty when blockCypherMode is CBC")


    val rounds = cypherKey.getNumberOfRounds()
    // Start with performing key expansion
    val keys = cypherKey.expandKeys()

    var roundState = state

    if (blockCypherMode == BlockCypherMode.CBC)
        roundState = roundState.xorOtherState(initializationVector)

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

    return roundState
}

fun aesDecrypt(cypherText: List<State>,
               cypherKey: Key,
               blockCypherMode: BlockCypherMode = BlockCypherMode.ECB,
               initializationVector: State = State()): List<State> {

    var iv = initializationVector
    val decryptedStates = arrayListOf<State>()


    // Perform all operations on each state in the states list
    cypherText.forEachIndexed { i, state ->
        if (blockCypherMode == BlockCypherMode.CBC && decryptedStates.size > 0)
            iv = cypherText[i - 1]

        decryptedStates.add(aesDecryptBlock(state, cypherKey, blockCypherMode, iv))
    }

    return decryptedStates
}

fun aesDecryptBlock(state: State,
                    cypherKey: Key,
                    blockCypherMode: BlockCypherMode = BlockCypherMode.ECB,
                    initializationVector: State = State()): State {

    if (blockCypherMode == BlockCypherMode.CBC && initializationVector.size == 0)
        throw IllegalArgumentException("initializationVector state cannot be empty when blockCypherMode is CBC")

    val rounds = cypherKey.getNumberOfRounds()
    // Start with performing key expansion
    val keys = cypherKey.expandKeys()

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

    if (blockCypherMode == BlockCypherMode.CBC)
        roundState = roundState.xorOtherState(initializationVector)

    return roundState
}