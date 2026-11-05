package com.adshield.pro.gps.engine

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Build
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlin.math.abs

/**
 * AdShield Pro — compass / heading sensor.
 *
 * Prefers `TYPE_ROTATION_VECTOR` (sensor fusion: accelerometer + gyro + magnetometer, the most
 * stable heading on modern phones), falls back to the raw magnetometer, and reports
 * [HeadingSource] so the UI never claims "compass" when it is showing GNSS course.
 *
 * The azimuth is normalised to 0..360 clockwise from magnetic north. Declination is *not* applied
 * (Android does not expose it), which means true-north error of up to ~20° in some regions; the
 * navigation bearing prefers course-over-ground above walking speed for exactly this reason.
 */
class HeadingSensor(private val context: Context) {

    private val sensorManager: SensorManager? =
        context.getSystemService(Context.SENSOR_SERVICE) as? SensorManager

    fun hasCompass(): Boolean = sensorManager?.getDefaultSensor(Sensor.TYPE_ROTATION_VECTOR) != null ||
        sensorManager?.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) != null

    fun hasGyroscope(): Boolean = sensorManager?.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null

    fun hasAccelerometer(): Boolean = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null

    /** Raw accelerometer magnitude, used for crash/impact style movement hints (not claimed as detection). */
    fun accelerometerMagnitude(): Flow<Float> = callbackFlow {
        val manager = sensorManager ?: run { close(); return@callbackFlow }
        val sensor = manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) ?: run { close(); return@callbackFlow }
        val listener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                val x = event.values[0]
                val y = event.values[1]
                val z = event.values[2]
                trySend(kotlin.math.sqrt(x * x + y * y + z * z))
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }
        manager.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_UI)
        awaitClose { manager.unregisterListener(listener) }
    }

    fun headings(): Flow<HeadingSample> = callbackFlow {
        val manager = sensorManager ?: run { close(); return@callbackFlow }

        val rotationSensor = manager.getDefaultSensor(Sensor.TYPE_ROTATION_VECTOR)
        val magnetometer = manager.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD)
        val accelerometer = manager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)

        val rotationMatrix = FloatArray(9)
        val orientation = FloatArray(3)
        var smoothed: Double? = null

        fun emit(degrees: Double, accuracy: Double?, source: HeadingSource) {
            val normalized = if (degrees < 0) degrees + 360.0 else degrees % 360.0
            // A light low-pass here keeps the needle readable; HeadingFusion does the real blend
            // with GNSS course, so this one only removes single-sample spikes.
            val previous = smoothed
            val value = if (previous != null && abs(normalized - previous) > 180.0) {
                // wrap around 0/360 without spinning the needle the long way
                val adjusted = if (normalized > previous) normalized - 360.0 else normalized + 360.0
                previous + (adjusted - previous) * 0.35
            } else if (previous != null) {
                previous + (normalized - previous) * 0.35
            } else {
                normalized
            }
            smoothed = value
            trySend(
                HeadingSample(
                    degrees = if (value < 0) value + 360.0 else value % 360.0,
                    accuracyDegrees = accuracy,
                    source = source
                )
            )
        }

        if (rotationSensor != null) {
            val listener = object : SensorEventListener {
                override fun onSensorChanged(event: SensorEvent) {
                    SensorManager.getRotationMatrixFromVector(rotationMatrix, event.values)
                    SensorManager.getOrientation(rotationMatrix, orientation)
                    val azimuth = Math.toDegrees(orientation[0].toDouble())
                    // A rotation vector with unstable magnetometer calibration is reported as
                    // low accuracy; convert that into an approximate ±degrees figure.
                    val accuracy = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        when (event.accuracy) {
                            SensorManager.SENSOR_STATUS_ACCURACY_HIGH -> 5.0
                            SensorManager.SENSOR_STATUS_ACCURACY_MEDIUM -> 15.0
                            SensorManager.SENSOR_STATUS_ACCURACY_LOW -> 35.0
                            else -> null
                        }
                    } else {
                        null
                    }
                    emit(azimuth, accuracy, HeadingSource.ROTATION_VECTOR)
                }

                override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
            }
            manager.registerListener(listener, rotationSensor, SensorManager.SENSOR_DELAY_GAME)
            awaitClose { manager.unregisterListener(listener) }
        } else if (magnetometer != null && accelerometer != null) {
            val gravity = FloatArray(3)
            val geomagnetic = FloatArray(3)
            val rotation = FloatArray(9)
            val listener = object : SensorEventListener {
                override fun onSensorChanged(event: SensorEvent) {
                    when (event.sensor.type) {
                        Sensor.TYPE_ACCELEROMETER -> lowPass(event.values, gravity)
                        Sensor.TYPE_MAGNETIC_FIELD -> lowPass(event.values, geomagnetic)
                    }
                    if (SensorManager.getRotationMatrix(rotation, null, gravity, geomagnetic)) {
                        SensorManager.getOrientation(rotation, orientation)
                        emit(Math.toDegrees(orientation[0].toDouble()), null, HeadingSource.MAGNETIC)
                    }
                }

                override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
            }
            manager.registerListener(listener, accelerometer, SensorManager.SENSOR_DELAY_GAME)
            manager.registerListener(listener, magnetometer, SensorManager.SENSOR_DELAY_GAME)
            awaitClose {
                manager.unregisterListener(listener)
            }
        } else {
            // No compass hardware: emit nothing rather than a fake 0°. The dashboard shows
            // "no compass" and uses GNSS course when moving.
            close()
        }
    }

    private fun lowPass(input: FloatArray, output: FloatArray, alpha: Float = 0.15f) {
        for (index in input.indices) {
            output[index] = output[index] + alpha * (input[index] - output[index])
        }
    }

    fun describe(): String {
        val manager = sensorManager
        val compass = manager?.getDefaultSensor(Sensor.TYPE_ROTATION_VECTOR) != null
        val magnetometer = manager?.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) != null
        val gyro = manager?.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null
        return buildString {
            append(if (compass) "Rotation vector compass" else if (magnetometer) "Magnetometer only" else "No compass")
            if (gyro) append(" · gyroscope present")
        }
    }
}
