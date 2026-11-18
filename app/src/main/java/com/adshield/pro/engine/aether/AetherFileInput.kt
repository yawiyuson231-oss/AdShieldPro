package com.adshield.pro.engine.aether

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.InputStream
import java.io.OutputStream

/** A document provider can misreport size, so enforce the limit against the bytes actually read. */
internal object AetherFileInput {
    const val MAX_MIB = 24
    private const val MAX_BYTES = MAX_MIB * 1024 * 1024L

    suspend fun copy(input: InputStream, output: OutputStream, maximum: Long = MAX_BYTES): Boolean {
        require(maximum >= 0)
        val buffer = ByteArray(16 * 1024)
        var remaining = maximum
        val context = currentCoroutineContext()
        while (remaining > 0) {
            context.ensureActive()
            val count = input.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
            context.ensureActive()
            if (count < 0) return true
            if (count == 0) {
                val byte = input.read()
                context.ensureActive()
                if (byte < 0) return true
                output.write(byte)
                remaining--
            } else {
                output.write(buffer, 0, count)
                remaining -= count
            }
        }
        context.ensureActive()
        // An exact-limit file is allowed. Never write the extra byte or scan a truncated copy.
        val endOfFile = input.read() < 0
        context.ensureActive()
        return endOfFile
    }
}

/** The callback for a canceled, replaced, or already used picker can't authorize a scan. */
internal class AetherFilePickerApproval {
    private var pending: AetherTaskApproval.Approved? = null

    fun await(approved: AetherTaskApproval.Approved) {
        require(approved.task == AetherSecurityTask.SCAN_FILE)
        pending = approved
    }

    fun consume(id: Long): AetherTaskApproval.Approved? {
        val approved = pending?.takeIf { it.id == id } ?: return null
        pending = null
        return approved
    }

    fun clear() { pending = null }
}
