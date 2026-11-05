package org.junit

annotation class Test

object Assert {
    fun assertEquals(expected: Any?, actual: Any?) {
        if (expected != actual) throw AssertionError("expected <$expected> but was <$actual>")
    }

    fun assertEquals(expected: Double, actual: Double, delta: Double) {
        if (kotlin.math.abs(expected - actual) > delta) {
            throw AssertionError("expected <$expected> ± $delta but was <$actual>")
        }
    }

    fun assertEquals(expected: Float, actual: Float, delta: Float) {
        if (kotlin.math.abs(expected - actual) > delta) {
            throw AssertionError("expected <$expected> ± $delta but was <$actual>")
        }
    }

    fun assertTrue(condition: Boolean) {
        if (!condition) throw AssertionError("expected true")
    }

    fun assertTrue(message: String, condition: Boolean) {
        if (!condition) throw AssertionError(message)
    }

    fun assertFalse(condition: Boolean) {
        if (condition) throw AssertionError("expected false")
    }

    fun assertNotNull(value: Any?) {
        if (value == null) throw AssertionError("expected non-null")
    }

    fun assertNull(value: Any?) {
        if (value != null) throw AssertionError("expected null but was <$value>")
    }

    fun fail(message: String): Nothing = throw AssertionError(message)
}
