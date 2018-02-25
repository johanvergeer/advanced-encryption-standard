package com.redgyro.algorithms.advancedencryptionstandard.transformationTables

// rCon is Round Constant used for the Key Expansion, first column is 2^(r-1) in GF(2^8)
val rCon = arrayOf(
        arrayOf(0x00, 0x00, 0x00, 0x00),
        arrayOf(0x01, 0x00, 0x00, 0x00),
        arrayOf(0x02, 0x00, 0x00, 0x00),
        arrayOf(0x04, 0x00, 0x00, 0x00),
        arrayOf(0x08, 0x00, 0x00, 0x00),
        arrayOf(0x10, 0x00, 0x00, 0x00),
        arrayOf(0x20, 0x00, 0x00, 0x00),
        arrayOf(0x40, 0x00, 0x00, 0x00),
        arrayOf(0x80, 0x00, 0x00, 0x00),
        arrayOf(0x1b, 0x00, 0x00, 0x00),
        arrayOf(0x36, 0x00, 0x00, 0x00)
)