plugins {
    id("java-library")
    id("maven-publish")
    id("signing")
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
    id("org.glavo.load-maven-publish-properties") version "0.1.0"
    id("org.teavm") version "0.14.0"
}

group = "org.glavo"
version = "0.1.0" + "-SNAPSHOT"
description = "A lightweight Java UUID utility library for generating, parsing, formatting, and comparing UUIDs."

repositories {
    mavenCentral()
}

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

dependencies {
    compileOnly("org.jetbrains:annotations:26.1.0")

    testImplementation(platform("org.junit:junit-bom:6.0.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testCompileOnly("org.jetbrains:annotations:26.1.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    add("benchmarkCompileOnly", "org.jetbrains:annotations:26.1.0")
    add("benchmarkImplementation", "org.openjdk.jmh:jmh-core:1.37")
    add("benchmarkAnnotationProcessor", "org.openjdk.jmh:jmh-generator-annprocess:1.37")

    val teavmVersion = "0.14.0"
    teavm("org.teavm:teavm-jso:$teavmVersion")
    teavm("org.teavm:teavm-jso-impl:$teavmVersion")
    teavm("org.teavm:teavm-classlib:$teavmVersion")
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
