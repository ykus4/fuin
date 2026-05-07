package com.fuin.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Fuin Packer Gradle Plugin.
 *
 * Registers a `fuinPack` task that runs after APK assembly.
 * Automatically hooks into `assembleRelease` when the Android application plugin is applied.
 */
class FuinPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val extension = project.extensions.create("fuin", FuinExtension::class.java)

        // Set defaults
        extension.enabled.convention(true)
        extension.cliPath.convention("fuin-pack")
        extension.rootDetection.convention(false)
        extension.emulatorDetection.convention(false)
        extension.encryptStrings.convention(false)
        extension.encryptNativeLibs.convention(true)
        extension.encryptResources.convention(true)

        project.afterEvaluate {
            if (!extension.enabled.getOrElse(true)) return@afterEvaluate

            // Register fuinPack task
            val fuinTask = project.tasks.register("fuinPack", FuinPackTask::class.java) { task ->
                task.group = "fuin"
                task.description = "Pack and encrypt the release APK with fuin"
                task.extension = extension
            }

            // Hook into assembleRelease if it exists
            project.tasks.findByName("assembleRelease")?.let { assembleTask ->
                fuinTask.get().dependsOn(assembleTask)
                // Also make it finalize assembleRelease so it runs automatically
                assembleTask.finalizedBy(fuinTask)
            }
        }
    }
}
