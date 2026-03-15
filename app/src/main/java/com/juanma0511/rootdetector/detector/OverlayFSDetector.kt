package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.*
import java.io.File

class OverlayFsDetector {

    fun detect(): DetectionItem {

        var detected = false
        var detail: String? = null

        try {

            File("/proc/mounts").forEachLine {

                if (
                    it.contains("overlay") &&
                    (
                        it.contains("/system") ||
                        it.contains("/vendor") ||
                        it.contains("/product")
                    )
                ) {

                    detected = true
                    detail = it
                    return@forEachLine
                }
            }

        } catch (_: Exception) {}

        return DetectionItem(
            id = "overlayfs_system",
            name = "OverlayFS Modification",
            description = "Overlay filesystem mounted over system partition",
            category = DetectionCategory.MOUNT_POINTS,
            severity = Severity.HIGH,
            detected = detected,
            detail = detail
        )
    }
}