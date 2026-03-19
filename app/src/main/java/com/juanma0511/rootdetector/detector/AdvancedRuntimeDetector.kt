package com.juanma0511.rootdetector.detector

import java.io.File

object AdvancedRuntimeDetector {

    fun checkMountNamespace(): Boolean {
        return try {
            val selfMounts = File("/proc/self/mounts").readText()

            val zygotePid = findZygotePid() ?: return false

            val zygoteMounts = File("/proc/$zygotePid/mounts").readText()

            selfMounts != zygoteMounts
        } catch (e: Exception) {
            false
        }
    }

    fun checkZygoteInjection(): List<String> {

        val found = mutableListOf<String>()

        try {

            val zygotePid = findZygotePid() ?: return found

            val maps = File("/proc/$zygotePid/maps").readText()

            val suspicious = listOf(
                "zygisk",
                "magisk",
                "lsposed",
                "riru",
                "edxp"
            )

            suspicious.forEach {
                if (maps.contains(it, true)) {
                    found.add(it)
                }
            }

        } catch (_: Exception) {}

        return found
    }

    fun checkKallsymsReadable(): Boolean {
        return try {
            val file = File("/proc/kallsyms")
            file.exists() && file.canRead()
        } catch (_: Exception) {
            false
        }
    }

    fun checkProcessCapabilities(): Boolean {

        return try {

            val status = File("/proc/self/status").readText()

            val capLine = status.lines().firstOrNull {
                it.startsWith("CapEff")
            } ?: return false

            val value = capLine.split(":")[1].trim()

            value != "0000000000000000"

        } catch (_: Exception) {
            false
        }
    }

    private fun findZygotePid(): String? {

        return try {

            File("/proc").listFiles()?.firstOrNull {

                val pid = it.name.toIntOrNull() ?: return@firstOrNull false

                val cmdline = File("/proc/$pid/cmdline")

                cmdline.exists() && cmdline.readText().contains("zygote")

            }?.name

        } catch (_: Exception) {
            null
        }
    }
}