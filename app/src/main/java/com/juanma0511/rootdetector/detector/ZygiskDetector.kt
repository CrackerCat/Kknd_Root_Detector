package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.*
import java.io.File

class ZygiskDetector {

    fun detect(): DetectionItem {

        var detected = false
        var detail: String? = null

        try {

            File("/proc/self/maps").forEachLine {

                if (
                    it.contains("zygisk") ||
                    it.contains("lsposed") ||
                    it.contains("riru") ||
                    it.contains("edxp")
                ) {

                    detected = true
                    detail = it
                    return@forEachLine
                }
            }

        } catch (_: Exception) {}

        return DetectionItem(
            id = "zygisk_runtime",
            name = "Runtime Injection Framework",
            description = "Zygisk / LSPosed runtime detected",
            category = DetectionCategory.MAGISK,
            severity = Severity.HIGH,
            detected = detected,
            detail = detail
        )
    }
}