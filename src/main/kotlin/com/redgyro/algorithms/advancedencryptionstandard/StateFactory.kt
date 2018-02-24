package com.redgyro.algorithms.advancedencryptionstandard

fun getStatesFromString(stringInput: String): List<State> {
    val bytes = stringInput.toByteArray()
    val hexList = bytes.map { byte -> byte.toInt() }

    return getStatesFromHexList(hexList)
}

fun getStatesFromHexList(hexList: List<Int>): List<State> {
    val states = arrayListOf<State>()
    val wordsList = arrayListOf<Word>()

    var i = 0
    while (hexList.isNotEmpty()) {
        val hexLeft = if (hexList.size - i >= 4) 4 else hexList.size - i
        if (hexLeft == 0) break

        val hexSubList = ArrayList(hexList.subList(i, i + hexLeft))

        while (hexSubList.size < 4) {
            hexSubList.add(0x00)
        }

        wordsList.add(Word(ArrayList(hexSubList)))
        i += hexLeft
    }

    i = 0
    while (wordsList.isNotEmpty()) {
        val wordsLeft = if (wordsList.size - i >= 4) 4 else wordsList.size - i
        if (wordsLeft == 0) break

        val wordsSubList = ArrayList(wordsList.subList(i, i + wordsLeft))

        while (wordsSubList.size < 4) {
            wordsSubList.add(Word(arrayListOf(0x00, 0x00, 0x00, 0x00)))
        }

        states.add(State(wordsSubList))
        i += wordsLeft
    }

    return states
}

