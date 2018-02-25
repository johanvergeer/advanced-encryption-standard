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
class AES(private val statesInput: List<State>,
          private val cypherKey: Key,
          private val blockCypherMode: BlockCypherMode = BlockCypherMode.ECB,
          private var initializationVector: State = State()) {

    private val processedStates = arrayListOf<State>()
    private val roundKeys = arrayListOf<Key>()
    private var numberOfRounds = 0

    init {
        roundKeys.addAll(cypherKey.expandKeys())
        numberOfRounds = cypherKey.numberOfRounds

        if (this.blockCypherMode == BlockCypherMode.CBC && this.initializationVector.size == 0)
            throw IllegalArgumentException("initializationVector state cannot be empty when blockCypherMode is CBC")
    }

    fun encrypt(): List<State> {
        this.statesInput.forEach { state ->
            if (blockCypherMode == BlockCypherMode.CBC && this.processedStates.size > 0)
                this.initializationVector = this.processedStates.last()

            this.processedStates.add(this.encryptBlock(state))
        }

        return this.processedStates
    }

    private fun encryptBlock(state: State): State {
        var roundState = state

        if (this.blockCypherMode == BlockCypherMode.CBC)
            roundState = roundState.xorOtherState(initializationVector)

        roundState.printStateAfterStepForRound(0, "Before add round key")
        roundState = roundState.addRoundKey(this.roundKeys.first())
        roundState.printStateAfterStepForRound(0, "After add round key")

        (1 until this.numberOfRounds).forEach { round ->
            roundState = roundState
                    .subBytes()
                    .printStateAfterStepForRound(round, "Sub Bytes")
                    .shiftRows()
                    .printStateAfterStepForRound(round, "Shift Rows")
                    .mixColumns()
                    .printStateAfterStepForRound(round, "Mix Columns")
                    .addRoundKey(this.roundKeys[round])
                    .printStateAfterStepForRound(round, "Add round key")
        }

        roundState = roundState
                .subBytes()
                .printStateAfterStepForRound(this.numberOfRounds, "Sub Bytes")
                .shiftRows()
                .printStateAfterStepForRound(this.numberOfRounds, "Shift Rows")
                .addRoundKey(this.roundKeys.last())
                .printStateAfterStepForRound(this.numberOfRounds, "Add round key")

        return roundState
    }

    fun decrypt(): List<State> {
        // Perform all operations on each state in the states list
        this.statesInput.forEachIndexed { i, state ->
            if (blockCypherMode == BlockCypherMode.CBC && processedStates.size > 0)
                this.initializationVector = this.statesInput[i - 1]

            this.processedStates.add(this.decryptBlock(state))
        }

        return this.processedStates
    }

    private fun decryptBlock(state: State): State {
        var roundState = state

        roundState.printStateAfterStepForRound(0, "Before add round key")
        roundState = roundState.addRoundKey(this.roundKeys.last())
        roundState.printStateAfterStepForRound(0, "After add round key")

        (this.numberOfRounds - 1 downTo 1).forEach { round ->
            val roundToPrint = this.numberOfRounds - round

            roundState = roundState
                    .shiftRowsInverse()
                    .printStateAfterStepForRound(roundToPrint, "Shift Rows Inverse")
                    .subBytesInverse()
                    .printStateAfterStepForRound(roundToPrint, "Sub Bytes inverse")
                    .addRoundKey(this.roundKeys[round])
                    .printStateAfterStepForRound(roundToPrint, "Add round key")
                    .mixColumnsInverse()
                    .printStateAfterStepForRound(roundToPrint, "Mix Columns inverse")
        }

        roundState = roundState
                .shiftRowsInverse()
                .printStateAfterStepForRound(this.numberOfRounds, "Shift rows inverse")
                .subBytesInverse()
                .printStateAfterStepForRound(this.numberOfRounds, "Sub Bytes inverse")
                .addRoundKey(this.roundKeys.first())
                .printStateAfterStepForRound(this.numberOfRounds, "Add round key")

        if (blockCypherMode == BlockCypherMode.CBC)
            roundState = roundState.xorOtherState(initializationVector)

        return roundState
    }
}
