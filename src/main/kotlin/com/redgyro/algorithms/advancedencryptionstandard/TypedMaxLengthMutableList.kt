package com.redgyro.algorithms.advancedencryptionstandard

abstract class TypedMaxLengthMutableList<T>(private val maxSize: Int = 4) : MutableList<T> {

    internal val innerList = mutableListOf<T>()

    override val size: Int
        get() = this.innerList.size

    private fun addEmptyElement(element: T) = innerList.add(element)

    override fun contains(element: T) = this.innerList.contains(element)

    override fun containsAll(elements: Collection<T>) = this.innerList.containsAll(elements)

    /**
     * Returns the element at the specified index in the list.
     */
    override fun get(index: Int) = this.innerList[index]

    /**
     * Returns the index of the first occurrence of the specified element in the list, or -1 if the specified
     * element is not contained in the list.
     */
    override fun indexOf(element: T) = this.innerList.indexOf(element)

    override fun isEmpty() = this.innerList.isEmpty()

    override fun iterator() = this.innerList.iterator()

    /**
     * Returns the index of the last occurrence of the specified element in the list, or -1 if the specified
     * element is not contained in the list.
     */
    override fun lastIndexOf(element: T) = this.innerList.lastIndexOf(element)

    override fun add(element: T): Boolean {
        if (this.checkSize())
            return this.innerList.add(element)
        return false
    }

    /**
     * Inserts an element into the list at the specified [index].
     */
    override fun add(index: Int, element: T) {
        if (checkIndex(index) && checkSize())
            this.innerList.add(index, element)
        else
            throw IndexOutOfBoundsException("The maximum number of Word objects in a State is $maxSize")
    }

    /**
     * Inserts all of the elements in the specified collection [elements] into this list at the specified [index].
     *
     * @return `true` if the list was changed as the result of the operation.
     */
    override fun addAll(index: Int, elements: Collection<T>) = this.innerList.addAll(index, elements)

    override fun addAll(elements: Collection<T>) = this.innerList.addAll(elements)

    override fun clear() = this.innerList.clear()

    override fun listIterator() = this.innerList.listIterator()

    override fun listIterator(index: Int) = this.innerList.listIterator(index)

    override fun remove(element: T) = this.innerList.remove(element)

    override fun removeAll(elements: Collection<T>) = this.innerList.removeAll(elements)

    /**
     * Removes an element at the specified [index] from the list.
     *
     * @return the element that has been removed.
     */
    override fun removeAt(index: Int) = this.innerList.removeAt(index)

    override fun retainAll(elements: Collection<T>) = this.innerList.retainAll(elements)

    /**
     * Replaces the element at the specified position in this list with the specified element.
     *
     * @return the element previously at the specified position.
     */
    override fun set(index: Int, element: T) = this.innerList.set(index, element)

    override fun subList(fromIndex: Int, toIndex: Int) = this.innerList.subList(fromIndex, toIndex)

    /**
     * Check if the size of innerList does not exceed maxSize
     */
    private fun checkSize(): Boolean = this.innerList.size < maxSize

    /**
     * Check if the given index is out of the maxSize bounds
     */
    private fun checkIndex(index: Int): Boolean = index + 1 <= maxSize
}