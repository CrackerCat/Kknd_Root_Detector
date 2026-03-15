package com.juanma0511.rootdetector.detector

import com.juanma0511.rootdetector.model.*
import java.io.File

class MountNamespaceDetector {

    fun detect(): DetectionItem {

        var detected = false

        try {

            val self = File("/proc/self/mounts").readText()
            val init = File("/proc/1/mounts").readText()

            detected = self != init

        } catch (_: Exception) {}

        return DetectionItem(
            id = "mount_namespace",
            name = "Mount Namespace Isolation",
            description = "Different mount namespace detected",
            category = DetectionCategory.MOUNT_POINTS,
            severity = Severity.HIGH,
            detected = detected
        )
    }
}