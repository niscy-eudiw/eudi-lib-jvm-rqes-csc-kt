import org.jetbrains.dokka.DokkaConfiguration
import org.jetbrains.dokka.gradle.DokkaTask
import org.owasp.dependencycheck.gradle.extension.DependencyCheckExtension
import java.net.URL

// Set project group and version for publishing
project.group = "eu.europa.ec.eudi.rqes.csc"
project.version = "1.0.0-SNAPSHOT"

object Meta {
    const val BASE_URL = "https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-rqes-csc-kt"
}

plugins {
    base
    alias(libs.plugins.android.library)
    alias(libs.plugins.dokka)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.spotless)
    alias(libs.plugins.kover)
    alias(libs.plugins.dependency.check)
    alias(libs.plugins.maven.publish)
    alias(libs.plugins.binary.compatibility.validator)
}

android {
    namespace = "eu.europa.ec.eudi.rqes.csc"
    compileSdk = 34

    defaultConfig {
        minSdk = 21
        // targetSdk = 34 // Warning about this, can be removed if not specifically needed for library testOptions/lint
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = libs.versions.composeCompiler.get()
    }
}

dependencies {
    api(libs.nimbus.oauth2.oidc.sdk)
    api(libs.ktor.client.core)
    api(libs.ktor.client.content.negotiation)
    api(libs.ktor.client.serialization)
    api(libs.ktor.serialization.kotlinx.json)
    implementation(libs.uri.kmp)
    implementation("podofo-android:podofo-android:@aar")

    // Jetpack Compose Dependencies
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.runtime)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.material3)
    debugImplementation(libs.compose.ui.tooling.preview)

    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.jsoup)
    testImplementation(kotlin("test"))
    implementation(libs.ktor.client.okhttp)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.server.content.negotiation)
    testImplementation(libs.ktor.client.mock)
    testImplementation(libs.ktor.client.logging)
    testImplementation(libs.logback.classic)
}

/* // Commenting out for Android compatibility
java {
    sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
}
*/

/* // Commenting out for Android compatibility
kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(libs.versions.java.get()))
        vendor.set(JvmVendorSpec.ADOPTIUM)
    }
}
*/

spotless {
    kotlin {
        ktlint(libs.versions.ktlint.get())
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        ktlint(libs.versions.ktlint.get())
    }
}

tasks.withType<DokkaTask>().configureEach {
    dokkaSourceSets {
        named("main") {
            moduleName.set("EUDI rQES CSC library")

            includes.from("Module.md")

            documentedVisibilities.set(setOf(DokkaConfiguration.Visibility.PUBLIC, DokkaConfiguration.Visibility.PROTECTED))

            val remoteSourceUrl = System.getenv()["GIT_REF_NAME"]?.let { URL("${Meta.BASE_URL}/tree/$it/src") }
            remoteSourceUrl
                ?.let {
                    sourceLink {
                        localDirectory.set(projectDir.resolve("src"))
                        remoteUrl.set(it)
                        remoteLineSuffix.set("#L")
                    }
                }
        }
    }
}

mavenPublishing {
    pom {
        name.set(project.name)
        description.set("EUDI rQES CSC library for Android")
        url.set(Meta.BASE_URL)

        ciManagement {
            system = "github"
            url = Meta.BASE_URL + "/actions"
        }
        licenses {
            license {
                name.set("The Apache License, Version 2.0")
                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
            }
        }
        scm {
            connection.set("scm:git:" + Meta.BASE_URL + ".git")
            developerConnection.set("scm:git:ssh://git@github.com" + Meta.BASE_URL.substringAfter("https://github.com") + ".git")
            url.set(Meta.BASE_URL)
        }
    }
}

val nvdApiKey: String? = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString()
val dependencyCheckExtension = extensions.findByType(DependencyCheckExtension::class.java)
dependencyCheckExtension?.apply {
    formats = mutableListOf("XML", "HTML")
    nvd.apiKey = nvdApiKey ?: ""
}

// Task to create fat AAR with embedded dependencies
tasks.register("fatAar") {
    dependsOn("assembleRelease")
    doLast {
        val releaseAar = file("build/outputs/aar/${project.name}-release.aar")
        val fatAar = file("build/outputs/aar/${project.name}-fat-release.aar")
        val tempDir = file("build/tmp/fatAar")

        // Clean temp directory
        tempDir.deleteRecursively()
        tempDir.mkdirs()

        // Extract main AAR
        copy {
            from(zipTree(releaseAar))
            into(tempDir)
        }

        // Extract and merge podofo AAR
        val podofoAar = file("libs/podofo-android.aar")
        if (podofoAar.exists()) {
            val podofoTemp = file("build/tmp/podofo")
            podofoTemp.deleteRecursively()
            podofoTemp.mkdirs()

            copy {
                from(zipTree(podofoAar))
                into(podofoTemp)
            }

            // Merge classes.jar files
            val mainClassesJar = file("$tempDir/classes.jar")
            val podofoClassesJar = file("$podofoTemp/classes.jar")

            if (podofoClassesJar.exists()) {
                val mergedClassesDir = file("build/tmp/mergedClasses")
                mergedClassesDir.deleteRecursively()
                mergedClassesDir.mkdirs()

                // Extract both JARs
                copy {
                    from(zipTree(mainClassesJar))
                    into(mergedClassesDir)
                }
                copy {
                    from(zipTree(podofoClassesJar))
                    into(mergedClassesDir)
                }

                // Create merged classes.jar
                ant.withGroovyBuilder {
                    "jar"("destfile" to mainClassesJar) {
                        "fileset"("dir" to mergedClassesDir)
                    }
                }
            }

            // Copy native libraries
            val podofoJniLibs = file("$podofoTemp/jni")
            if (podofoJniLibs.exists()) {
                copy {
                    from(podofoJniLibs)
                    into("$tempDir/jni")
                }
            }

            // Copy resources
            val podofoRes = file("$podofoTemp/res")
            if (podofoRes.exists()) {
                copy {
                    from(podofoRes)
                    into("$tempDir/res")
                }
            }
        }

        // Create fat AAR
        ant.withGroovyBuilder {
            "zip"("destfile" to fatAar) {
                "fileset"("dir" to tempDir)
            }
        }

        println("Fat AAR created: ${fatAar.absolutePath}")
    }
}