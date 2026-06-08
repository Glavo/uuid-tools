import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

plugins {
    id("java-library")
    id("jacoco")
    id("maven-publish")
    id("signing")
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
    id("org.glavo.load-maven-publish-properties") version "0.1.0"
    id("org.teavm") version "0.14.0"
}

group = "org.glavo"
version = "0.2.0" + "-SNAPSHOT"
description = "A lightweight Java UUID utility library for generating, parsing, formatting, and comparing UUIDs."

repositories {
    mavenCentral()
}

val teavmVersion = "0.14.0"
val mainSourceSet = sourceSets["main"]

val teavmSourceSet = sourceSets.getByName("teavm").apply {
    java.setSrcDirs(listOf("src/website/java"))
    resources.setSrcDirs(listOf("src/website/teavm-resources"))

    compileClasspath += mainSourceSet.output + mainSourceSet.compileClasspath
    runtimeClasspath += mainSourceSet.output + mainSourceSet.runtimeClasspath
}

val benchmark by sourceSets.creating {
    java.srcDir("src/benchmark/java")
    compileClasspath += mainSourceSet.output
    runtimeClasspath += output + compileClasspath
}

val teavmClasslibPatch by sourceSets.creating {
    java.srcDir("src/website/teavm-classlib-patch/java")
}

val teavmClasslibOriginal by configurations.creating {
    isTransitive = false
}

val patchTeaVMClasslib by tasks.registering(Jar::class) {
    description = "Builds a TeaVM classlib jar patched for the demo website."

    dependsOn(tasks.named(teavmClasslibPatch.classesTaskName))

    archiveBaseName.set("teavm-classlib")
    archiveVersion.set(teavmVersion)
    archiveClassifier.set("uuid-tools-patched")

    from({ zipTree(teavmClasslibOriginal.singleFile) }) {
        exclude("org/teavm/classlib/java/lang/invoke/TMethodHandles.class")
        exclude("org/teavm/classlib/java/util/TUUID.class")
        exclude("org/teavm/classlib/java/security/TNoSuchAlgorithmException.class")
    }
    from(teavmClasslibPatch.output)

    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

dependencies {
    compileOnly("org.jetbrains:annotations:26.1.0")

    testImplementation(platform("org.junit:junit-bom:6.0.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("com.github.f4b6a3:uuid-creator:6.1.1")
    testCompileOnly("org.jetbrains:annotations:26.1.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    add("benchmarkCompileOnly", "org.jetbrains:annotations:26.1.0")
    add("benchmarkImplementation", "org.openjdk.jmh:jmh-core:1.37")
    add("benchmarkAnnotationProcessor", "org.openjdk.jmh:jmh-generator-annprocess:1.37")

    add(teavmClasslibPatch.compileOnlyConfigurationName, "org.jetbrains:annotations:26.1.0")
    add(teavmClasslibPatch.compileOnlyConfigurationName, "org.teavm:teavm-classlib:$teavmVersion")
    teavmClasslibOriginal("org.teavm:teavm-classlib:$teavmVersion")
    teavm(files(patchTeaVMClasslib))
    teavm("org.teavm:teavm-classlib:$teavmVersion")
    teavm("org.teavm:teavm-jso:$teavmVersion")
    teavm("org.teavm:teavm-jso-impl:$teavmVersion")
    add(teavmSourceSet.compileOnlyConfigurationName, "org.teavm:teavm-core:$teavmVersion")
}

java {
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<JavaCompile> {
    options.release.set(17)
    options.encoding = "UTF-8"
    options.javaModuleVersion = project.version.toString()
}

tasks.named<JavaCompile>(teavmSourceSet.compileJavaTaskName) {
    modularity.inferModulePath.set(false)
}

tasks.test {
    useJUnitPlatform()
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)

    reports {
        xml.required.set(true)
        csv.required.set(true)
        html.required.set(true)
    }
}

tasks.register<JavaExec>("benchmark") {
    group = "verification"
    description = "Runs the JMH benchmarks."
    mainClass.set("org.openjdk.jmh.Main")
    classpath = benchmark.runtimeClasspath
}

teavm {
    all {
        mainClass.set("org.glavo.uuid.website.UUIDToolsDemo")
        outputDir.set(layout.buildDirectory.dir("generated/teavm"))
        fastGlobalAnalysis.set(true)
        processMemory.set(1024)
    }

    wasmGC {
        targetFileName.set("uuid-tools-demo.wasm")
        relativePathInOutputDir.set("wasm-gc")
        copyRuntime.set(true)
        obfuscated.set(false)
        sourceMap.set(true)
        strict.set(true)
    }
}

val websiteOutputDir = layout.buildDirectory.dir("website")
val teavmWasmOutputDir = layout.buildDirectory.dir("generated/teavm/wasm-gc")

fun websiteContentType(fileName: String): String =
    when (fileName.substringAfterLast('.', "").lowercase()) {
        "html" -> "text/html; charset=utf-8"
        "css" -> "text/css; charset=utf-8"
        "js" -> "application/javascript; charset=utf-8"
        "json", "map" -> "application/json; charset=utf-8"
        "wasm" -> "application/wasm"
        "svg" -> "image/svg+xml"
        "png" -> "image/png"
        "jpg", "jpeg" -> "image/jpeg"
        "webp" -> "image/webp"
        else -> "application/octet-stream"
    }

fun sendWebsiteResponse(
    exchange: HttpExchange,
    status: Int,
    body: ByteArray,
    contentType: String,
    headOnly: Boolean,
) {
    exchange.responseHeaders.set("Content-Type", contentType)
    exchange.responseHeaders.set("Cache-Control", "no-store")
    exchange.sendResponseHeaders(status, if (headOnly) -1L else body.size.toLong())
    if (!headOnly) {
        exchange.responseBody.write(body)
    }
}

tasks.register<Sync>("buildWebsite") {
    group = "website"
    description = "Builds the static demo website."

    dependsOn(tasks.named("buildWasmGC"))

    from("src/website/resources")
    from(teavmWasmOutputDir) {
        into("wasm-gc")
    }

    into(websiteOutputDir)
}

tasks.register("serveWebsite") {
    group = "website"
    description = "Builds and serves the demo website locally. Set -Pwebsite.port=8080 to choose a port."

    dependsOn(tasks.named("buildWebsite"))

    doLast {
        val port = providers.gradleProperty("website.port").orElse("8080").get().toInt()
        val root = websiteOutputDir.get().asFile.toPath().toAbsolutePath().normalize()
        val executor = Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "uuid-tools-website-server").apply {
                isDaemon = true
            }
        }
        val server = HttpServer.create(
            InetSocketAddress(InetAddress.getLoopbackAddress(), port),
            0,
        )

        server.executor = executor
        server.createContext("/") { exchange ->
            try {
                val headOnly = exchange.requestMethod.equals("HEAD", ignoreCase = true)
                if (!headOnly && !exchange.requestMethod.equals("GET", ignoreCase = true)) {
                    exchange.responseHeaders.set("Allow", "GET, HEAD")
                    sendWebsiteResponse(
                        exchange,
                        405,
                        "Method Not Allowed".toByteArray(Charsets.UTF_8),
                        "text/plain; charset=utf-8",
                        false,
                    )
                    return@createContext
                }

                val decodedPath = URLDecoder.decode(
                    exchange.requestURI.rawPath ?: "/",
                    Charsets.UTF_8,
                )
                var file = root.resolve(decodedPath.removePrefix("/")).normalize()
                if (!file.startsWith(root)) {
                    sendWebsiteResponse(
                        exchange,
                        403,
                        "Forbidden".toByteArray(Charsets.UTF_8),
                        "text/plain; charset=utf-8",
                        headOnly,
                    )
                    return@createContext
                }

                if (Files.isDirectory(file)) {
                    file = file.resolve("index.html")
                }

                if (!Files.isRegularFile(file)) {
                    sendWebsiteResponse(
                        exchange,
                        404,
                        "Not Found".toByteArray(Charsets.UTF_8),
                        "text/plain; charset=utf-8",
                        headOnly,
                    )
                    return@createContext
                }

                sendWebsiteResponse(
                    exchange,
                    200,
                    Files.readAllBytes(file),
                    websiteContentType(file.fileName.toString()),
                    headOnly,
                )
            } finally {
                exchange.close()
            }
        }

        val stopped = AtomicBoolean(false)

        fun stopServer() {
            if (stopped.compareAndSet(false, true)) {
                server.stop(0)
                executor.shutdownNow()
            }
        }

        val shutdownHook = Thread(::stopServer, "uuid-tools-website-server-shutdown")
        Runtime.getRuntime().addShutdownHook(shutdownHook)

        try {
            server.start()
            println("Serving ${root.toUri()} at http://127.0.0.1:$port/")
            println("Press Ctrl+C to stop.")
            CountDownLatch(1).await()
        } finally {
            stopServer()
            try {
                Runtime.getRuntime().removeShutdownHook(shutdownHook)
            } catch (_: IllegalStateException) {
                // The JVM is already shutting down.
            }
        }
    }
}

tasks.withType<GenerateModuleMetadata> {
    enabled = false
}

publishing.publications.create<MavenPublication>("maven") {
    groupId = project.group.toString()
    artifactId = project.name
    version = project.version.toString()

    from(components["java"])

    pom {
        name.set(project.name)
        description.set(project.description)
        url.set("https://github.com/Glavo/uuid-tools")

        licenses {
            license {
                name.set("Mozilla Public License 2.0")
                url.set("https://www.mozilla.org/en-US/MPL/2.0/")
            }
        }

        developers {
            developer {
                id.set("Glavo")
                name.set("Glavo")
                email.set("zjx001202@gmail.com")
            }
        }

        scm {
            url.set("https://github.com/Glavo/uuid-tools")
        }
    }
}

if (System.getenv("JITPACK").isNullOrBlank() && rootProject.ext.has("signing.key")) {
    signing {
        useInMemoryPgpKeys(
            rootProject.ext["signing.keyId"].toString(),
            rootProject.ext["signing.key"].toString(),
            rootProject.ext["signing.password"].toString(),
        )
        sign(publishing.publications["maven"])
    }
}

// ./gradlew publishToSonatype closeAndReleaseSonatypeStagingRepository
nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))

            username.set(rootProject.ext["sonatypeUsername"].toString())
            password.set(rootProject.ext["sonatypePassword"].toString())
        }
    }
}
