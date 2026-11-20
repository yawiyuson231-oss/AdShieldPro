package com.adshield.pro.engine.evolution

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** One atomic activation record. The caller holds the stager's cross-process lock for mutations. */
internal class EvolutionActivationStore(private val directory: File) {
    data class State(val current: ByteArray, val previous: ByteArray?, val rejectedThrough: Long)
    private val target get() = File(directory, "activation.evo")

    fun read(): State? {
        if (!target.exists()) return null
        require(target.length() <= 2L * SignedEvolutionPackage.MAX_BYTES + 64)
        val input = DataInputStream(ByteArrayInputStream(target.readBytes()))
        require(input.readInt() == 0x45564131)
        val rejected = input.readLong()
        require(rejected >= 0)
        fun packet(optional: Boolean): ByteArray? {
            val size = input.readInt()
            if (optional && size == 0) return null
            require(size in 1..SignedEvolutionPackage.MAX_BYTES && size <= input.available())
            return ByteArray(size).also(input::readFully)
        }
        val current = requireNotNull(packet(false))
        val previous = packet(true)
        require(input.available() == 0)
        return State(current, previous, rejected)
    }

    fun write(state: State) {
        require(state.rejectedThrough >= 0)
        val bytes = ByteArrayOutputStream().also { output ->
            DataOutputStream(output).use { stream ->
                stream.writeInt(0x45564131); stream.writeLong(state.rejectedThrough)
                for (packet in listOf(state.current, state.previous)) {
                    require(packet == null || packet.size in 1..SignedEvolutionPackage.MAX_BYTES)
                    stream.writeInt(packet?.size ?: 0)
                    if (packet != null) stream.write(packet)
                }
            }
        }.toByteArray()
        val temporary = File.createTempFile("activation-", ".tmp", directory)
        try {
            FileOutputStream(temporary).use { it.write(bytes); it.fd.sync() }
            Files.move(temporary.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING)
        } finally { temporary.delete() }
    }
}
