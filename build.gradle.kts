plugins {
    id("java")
}

group = "org.glavo"
version = "0.1.0" + "-SNAPSHOT"

repositories {
    mavenCentral()
}

val benchmark by sourceSets.creating {
    java.srcDir("src/benchmark/java")
    compileClasspath += sourceSets.main.get().output
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
}

tasks.withType<JavaCompile> {
    options.release.set(17)
    options.encoding = "UTF-8"
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
