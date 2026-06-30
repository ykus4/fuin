plugins {
    kotlin("jvm") version "2.4.0"
    `java-gradle-plugin`
    `maven-publish`
}

group = "com.fuin"
version = "0.1.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation(gradleApi())
    implementation("com.squareup.okhttp3:okhttp:5.4.0")
    implementation("org.json:json:20260522")
}

gradlePlugin {
    plugins {
        create("fuinPacker") {
            id = "com.fuin.packer"
            implementationClass = "com.fuin.gradle.FuinPlugin"
            displayName = "Fuin APK Packer"
            description = "Automatically pack and encrypt APKs after assembly"
        }
    }
}

kotlin {
    jvmToolchain(17)
}
