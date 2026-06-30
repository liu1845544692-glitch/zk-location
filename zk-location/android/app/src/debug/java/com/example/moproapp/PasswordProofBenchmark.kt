/*
 * 文件功能：
 * - 独立的密码证明 len8 Android/mopro benchmark 页面。
 * - 固定使用 Rust 内置测试向量构造输入，不接入登录、注册或服务端。
 *
 * 执行流程：
 * 1. 校验并复制 password_policy_commitment_final.zkey 到 filesDir。
 * 2. 调用 Rust/UniFFI 构造 len8 Circom input。
 * 3. 调用 mopro native witness + Groth16 proof。
 * 4. 调用本地 verify，并执行 commitment+1 负向测试。
 */
package com.example.moproapp

import android.content.Context
import android.os.Debug
import android.os.SystemClock
import android.util.Log
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.CircomProofResult
import uniffi.mopro.ProofLib
import uniffi.mopro.generatePasswordCircomProofDiagnostic
import uniffi.mopro.generatePasswordBenchmarkInput
import uniffi.mopro.generatePasswordLen8BenchmarkInput
import uniffi.mopro.hashCircomProofResult
import uniffi.mopro.verifyCircomProof
import java.io.File
import java.math.BigInteger
import java.security.MessageDigest
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

private const val PASSWORD_BENCHMARK_TAG = "PasswordBenchmark"
private const val EXPECTED_COMMITMENT =
    "19506709927157339127216134994054708157265210932536273927045978637769242245953"

@Composable
fun PasswordProofBenchmarkScreen(
    autoRun: Boolean,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var status by remember { mutableStateOf("Idle") }
    var busy by remember { mutableStateOf(false) }
    var zkeyPath by remember { mutableStateOf<String?>(null) }
    var circuitInput by remember { mutableStateOf<String?>(null) }
    var proofResult by remember { mutableStateOf<CircomProofResult?>(null) }
    var autoStarted by remember { mutableStateOf(false) }

    val appendStatus: (String) -> Unit = { line ->
        status = listOf(status, line).filter { it.isNotBlank() && it != "Idle" }.joinToString("\n")
        Log.i(PASSWORD_BENCHMARK_TAG, line)
    }

    suspend fun runPrepare() {
        val zkey = withContext(Dispatchers.IO) {
            val first = preparePasswordZkey(context)
            val second = preparePasswordZkey(context)
            writeBenchmarkFile(context, "artifact_integrity.txt", first.toReport("first") + "\n" + second.toReport("reuse"))
            first to second
        }
        zkeyPath = zkey.first.path
        appendStatus("zkey ready: copyMs=${zkey.first.copyMs}, reuseMs=${zkey.second.reuseMs}")

        val inputStarted = nowNs()
        val input = generatePasswordLen8BenchmarkInput()
        val inputMs = elapsedMs(inputStarted)
        validatePasswordInputSummary(input)
        circuitInput = input
        appendStatus("input ready: ${inputMs}ms, public commitment ok")
        appendBenchmarkLine(context, "benchmark.txt", "input_construct_ms=$inputMs")
    }

    suspend fun runProof() {
        val input = requireNotNull(circuitInput) { "Prepare input first" }
        val zkey = requireNotNull(zkeyPath) { "Prepare zkey first" }
        val before = sampleMemory("before_proving")
        val sampler = MemorySampler()
        val started = nowNs()
        sampler.start()
        val diagnostic = try {
            runLargeStack("password-len8-proof") {
                generatePasswordCircomProofDiagnostic(zkey, input)
            }
        } finally {
            sampler.stop()
        }
        val proof = diagnostic.proofResult
        val proofMs = elapsedMs(started)
        val after = sampleMemory("after_proving")
        val proofSize = proofResultJson(proof).toByteArray(Charsets.UTF_8).size
        val ffiProofSha256 = hashCircomProofResult(proof)
        appendBenchmarkLine(context, "benchmark.txt", "public_signal_count=${proof.inputs.size}")
        appendBenchmarkLine(context, "benchmark.txt", "public_signal_0=${proof.inputs.firstOrNull() ?: ""}")
        appendBenchmarkLine(context, "benchmark.txt", "expected_commitment=$EXPECTED_COMMITMENT")
        appendBenchmarkLine(context, "benchmark.txt", "native_verify=${diagnostic.nativeVerify}")
        appendBenchmarkLine(context, "benchmark.txt", "native_proof_json_bytes=${diagnostic.proofJsonBytes}")
        appendBenchmarkLine(context, "benchmark.txt", "native_proof_sha256=${diagnostic.proofSha256}")
        appendBenchmarkLine(context, "benchmark.txt", "ffi_proof_sha256=$ffiProofSha256")
        appendBenchmarkLine(context, "benchmark.txt", "ffi_proof_match=${ffiProofSha256 == diagnostic.proofSha256}")
        appendBenchmarkLine(context, "benchmark.txt", "native_zkey_sha256=${diagnostic.zkeySha256}")
        require(proof.inputs.size == 1) { "expected one public signal, got ${proof.inputs.size}" }
        require(proof.inputs.first() == EXPECTED_COMMITMENT) {
            "public commitment mismatch: got ${proof.inputs.first()}"
        }
        require(diagnostic.nativeVerify) { "native immediate Arkworks verify returned false" }
        require(ffiProofSha256 == diagnostic.proofSha256) { "proof changed across UniFFI" }
        require(diagnostic.zkeySha256 == PASSWORD_ZKEY_SHA256) { "native zkey SHA-256 mismatch" }
        proofResult = proof
        appendStatus("proof ok: ${proofMs}ms, proofBytes=$proofSize")
        appendBenchmarkLine(context, "benchmark.txt", "witness_generate_ms=not_separately_exposed_by_mopro_generateCircomProof")
        appendBenchmarkLine(context, "benchmark.txt", "proof_generate_ms=$proofMs")
        appendBenchmarkLine(context, "benchmark.txt", "proof_size_bytes=$proofSize")
        appendMemoryReport(context, before, sampler.peak, after)
    }

    suspend fun runVerify() {
        val zkey = requireNotNull(zkeyPath) { "Prepare zkey first" }
        val proof = requireNotNull(proofResult) { "Generate proof first" }
        val arkStarted = nowNs()
        val arkValid = runLargeStack("password-len8-verify-arkworks") {
            verifyCircomProof(zkey, proof, ProofLib.ARKWORKS)
        }
        val arkMs = elapsedMs(arkStarted)
        appendBenchmarkLine(context, "benchmark.txt", "verify_arkworks_ms=$arkMs")
        appendBenchmarkLine(context, "benchmark.txt", "verify_arkworks=$arkValid")
        require(arkValid) { "local Arkworks verify returned false" }
        appendStatus("verify ok: ${arkMs}ms, backend=ARKWORKS")
        appendBenchmarkLine(context, "benchmark.txt", "verify_ms=$arkMs")
        appendBenchmarkLine(context, "benchmark.txt", "verify_backend=ARKWORKS")
        writeBenchmarkFile(
            context,
            "final_result.txt",
            listOf(
                "proof_generated=true",
                "verify_pass=true",
                "verify_backend=ARKWORKS",
                "public_signal_count=${proof.inputs.size}",
                "public_commitment=${proof.inputs.first()}",
                "oom=false"
            ).joinToString("\n") + "\n"
        )
    }

    suspend fun runNegative() {
        val zkey = requireNotNull(zkeyPath) { "Prepare zkey first" }
        val proof = requireNotNull(proofResult) { "Generate proof first" }
        val tamperedCommitment = BigInteger(EXPECTED_COMMITMENT).add(BigInteger.ONE).toString()
        val tamperedProof = CircomProofResult(proof.proof, listOf(tamperedCommitment))
        val started = nowNs()
        val tamperedVerified = runLargeStack("password-len8-negative-verify") {
            verifyCircomProof(zkey, tamperedProof, ProofLib.ARKWORKS)
        }
        val elapsed = elapsedMs(started)
        val restoreStarted = nowNs()
        val restored = runLargeStack("password-len8-restore-verify") {
            verifyCircomProof(zkey, proof, ProofLib.ARKWORKS)
        }
        val restoreMs = elapsedMs(restoreStarted)
        require(!tamperedVerified) { "tampered commitment unexpectedly verified" }
        require(restored) { "original proof did not verify after negative test" }
        val report = listOf(
            "negative_backend=ARKWORKS",
            "negative_result=tampered_public_input_verify_$tamperedVerified",
            "tampered_commitment=$tamperedCommitment",
            "negative_verify_ms=$elapsed",
            "restore_original_verify=$restored",
            "restore_verify_ms=$restoreMs"
        ).joinToString("\n") + "\n"
        writeBenchmarkFile(context, "negative_test.txt", report)
        appendBenchmarkLine(context, "final_result.txt", "tampered_commitment_verify=$tamperedVerified")
        appendBenchmarkLine(context, "final_result.txt", "restore_original_verify=$restored")
        appendStatus("negative done: ${report.lineSequence().first()}")
    }

    suspend fun runAll() {
        busy = true
        status = ""
        try {
            resetBenchmarkReports(context)
            appendBenchmarkLine(context, "benchmark.txt", "started_elapsed_ms=${SystemClock.elapsedRealtime()}")
            writeBenchmarkFile(context, "device_app_memory_start.txt", sampleMemory("app_start").toReport())
            runPrepare()
            runProof()
            runVerify()
            runNegative()
            appendStatus("benchmark complete")
        } catch (error: Throwable) {
            val message = error.message ?: error.toString()
            appendStatus("benchmark failed: $message")
            writeBenchmarkFile(context, "final_result.txt", "proof_generated=false\nverify_pass=false\noom=false\nerror=$message\n")
        } finally {
            busy = false
        }
    }

    LaunchedEffect(autoRun) {
        if (autoRun && !autoStarted) {
            autoStarted = true
            runAll()
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Password Proof Benchmark", style = MaterialTheme.typography.titleLarge)
        Text("Fixed len8 vector, local Android proving only.", style = MaterialTheme.typography.bodyMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(onClick = onBack, enabled = !busy) { Text("Back") }
            Button(onClick = { status = ""; busy = true }, enabled = false) { Text(if (busy) "Running" else "Ready") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = { runAsync(context, appendStatus) { busy = true; runPrepare(); busy = false } },
                enabled = !busy
            ) { Text("Prepare len8 input") }
            Button(
                onClick = { runAsync(context, appendStatus) { busy = true; runProof(); busy = false } },
                enabled = !busy && circuitInput != null
            ) { Text("Generate proof") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = { runAsync(context, appendStatus) { busy = true; runVerify(); busy = false } },
                enabled = !busy && proofResult != null
            ) { Text("Verify proof") }
            OutlinedButton(
                onClick = {
                    zkeyPath = null
                    circuitInput = null
                    proofResult = null
                    status = "Cleared"
                },
                enabled = !busy
            ) { Text("Clear") }
        }
        Text(status.ifBlank { "Idle" }, style = MaterialTheme.typography.bodySmall)
    }
}

private data class PasswordMatrixVector(
    val runName: String,
    val password: String,
    val salt: String,
    val length: Int,
    val commitment: String
)

@Composable
fun PasswordMatrixBenchmarkScreen(modifier: Modifier = Modifier) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var status by remember { mutableStateOf("running") }

    LaunchedEffect(Unit) {
        val outputDir = passwordMatrixDir(context)
        val completed = mutableListOf<String>()
        try {
            val vectors = listOf(
                PasswordMatrixVector("len8_run1", "Aa1!bbbb", "1008", 8, EXPECTED_COMMITMENT),
                PasswordMatrixVector("len8_run2", "Aa1!bbbb", "1008", 8, EXPECTED_COMMITMENT),
                PasswordMatrixVector("len8_run3", "Aa1!bbbb", "1008", 8, EXPECTED_COMMITMENT),
                PasswordMatrixVector(
                    "len16",
                    "Aa1!bbbbbbbbbbbb",
                    "1016",
                    16,
                    "11186526345370232576299025816516415797176095098189845436645573564034254234122"
                ),
                PasswordMatrixVector(
                    "len32",
                    "Aa1!bbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "1032",
                    32,
                    "15382327428467064216367910183421615477503124169574981342044370954693189986584"
                )
            )

            vectors.forEach { vector ->
                val runStartedElapsedMs = SystemClock.elapsedRealtime()
                val totalStarted = nowNs()
                val zkey = withContext(Dispatchers.IO) { preparePasswordZkey(context) }
                val inputStarted = nowNs()
                val input = generatePasswordBenchmarkInput(vector.length.toUByte())
                val inputMs = elapsedMs(inputStarted)
                validatePasswordVector(input, vector)

                val before = sampleMemory("before_proving")
                val sampler = MemorySampler()
                val proofStarted = nowNs()
                sampler.start()
                val diagnostic = try {
                    runLargeStack("${vector.runName}-proof") {
                        generatePasswordCircomProofDiagnostic(zkey.path, input)
                    }
                } finally {
                    sampler.stop()
                }
                val proofMs = elapsedMs(proofStarted)
                val after = sampleMemory("after_proving")
                val proof = diagnostic.proofResult
                val proofSize = proofResultJson(proof).toByteArray(Charsets.UTF_8).size
                val ffiHash = hashCircomProofResult(proof)

                check(proof.inputs.size == 1) { "${vector.runName}: expected one public signal" }
                check(proof.inputs[0] == vector.commitment) { "${vector.runName}: commitment mismatch" }
                check(diagnostic.nativeVerify) { "${vector.runName}: native verify failed" }
                check(diagnostic.proofSha256 == ffiHash) { "${vector.runName}: FFI proof hash mismatch" }
                check(diagnostic.zkeySha256 == PASSWORD_ZKEY_SHA256) { "${vector.runName}: zkey hash mismatch" }

                val verifyStarted = nowNs()
                val verified = runLargeStack("${vector.runName}-verify") {
                    verifyCircomProof(zkey.path, proof, ProofLib.ARKWORKS)
                }
                val verifyMs = elapsedMs(verifyStarted)
                check(verified) { "${vector.runName}: Kotlin verify failed" }

                val tamperedCommitment = BigInteger(vector.commitment).add(BigInteger.ONE).toString()
                val tamperedProof = CircomProofResult(proof.proof, listOf(tamperedCommitment))
                val negativeStarted = nowNs()
                val tamperedVerified = runLargeStack("${vector.runName}-negative") {
                    verifyCircomProof(zkey.path, tamperedProof, ProofLib.ARKWORKS)
                }
                val negativeMs = elapsedMs(negativeStarted)
                check(!tamperedVerified) { "${vector.runName}: tampered commitment verified" }

                val restoreStarted = nowNs()
                val restored = runLargeStack("${vector.runName}-restore") {
                    verifyCircomProof(zkey.path, proof, ProofLib.ARKWORKS)
                }
                val restoreMs = elapsedMs(restoreStarted)
                check(restored) { "${vector.runName}: restored commitment failed" }
                val totalMs = elapsedMs(totalStarted)

                val report = listOf(
                    "run=${vector.runName}",
                    "run_started_elapsed_ms=$runStartedElapsedMs",
                    "run_completed_elapsed_ms=${SystemClock.elapsedRealtime()}",
                    "password=${vector.password}",
                    "salt=${vector.salt}",
                    "password_length=${vector.length}",
                    "expected_commitment=${vector.commitment}",
                    "zkey_copied=${zkey.copied}",
                    "zkey_copy_ms=${zkey.copyMs}",
                    "zkey_reuse_ms=${zkey.reuseMs}",
                    "input_construct_ms=$inputMs",
                    "proof_ms=$proofMs",
                    "verify_ms=$verifyMs",
                    "negative_verify_ms=$negativeMs",
                    "restore_verify_ms=$restoreMs",
                    "total_ms=$totalMs",
                    "proof_size_bytes=$proofSize",
                    "public_signal_count=${proof.inputs.size}",
                    "public_signal_0=${proof.inputs[0]}",
                    "native_verify=${diagnostic.nativeVerify}",
                    "native_proof_sha256=${diagnostic.proofSha256}",
                    "ffi_proof_sha256=$ffiHash",
                    "ffi_proof_match=${diagnostic.proofSha256 == ffiHash}",
                    "positive_verify=$verified",
                    "tampered_verify=$tamperedVerified",
                    "restore_verify=$restored",
                    "before_pss_kb=${before.totalPssKb}",
                    "before_rss_kb=${before.totalRssKb}",
                    "peak_pss_kb=${sampler.peakPssKb}",
                    "peak_rss_kb=${sampler.peakRssKb}",
                    "after_pss_kb=${after.totalPssKb}",
                    "after_rss_kb=${after.totalRssKb}",
                    "after_native_heap_bytes=${after.nativeHeapAllocatedBytes}",
                    "result=PASS"
                ).joinToString("\n") + "\n"
                File(outputDir, "${vector.runName}.txt").writeText(report)
                completed += "${vector.runName}=PASS"
                File(outputDir, "summary.txt").writeText(completed.joinToString("\n") + "\nresult=RUNNING\n")
                Log.i(PASSWORD_BENCHMARK_TAG, "${vector.runName}: PASS proofMs=$proofMs verifyMs=$verifyMs")
                kotlinx.coroutines.delay(1_000)
            }

            val storageBytes = context.filesDir.walkTopDown()
                .filter { it.isFile }
                .sumOf { it.length() }
            File(outputDir, "summary.txt").writeText(
                (completed + listOf(
                    "application_storage_bytes=$storageBytes",
                    "oom=false",
                    "result=PASS"
                )).joinToString("\n") + "\n"
            )
            status = "PASS"
        } catch (error: Throwable) {
            val message = error.message ?: error.toString()
            File(outputDir, "summary.txt").writeText(
                (completed + listOf("result=FAIL", "error=$message")).joinToString("\n") + "\n"
            )
            Log.e(PASSWORD_BENCHMARK_TAG, "matrix failed: $message", error)
            status = "FAIL: $message"
        }
    }

    Column(modifier = modifier.fillMaxSize().padding(16.dp)) {
        Text("Password Proof Benchmark", style = MaterialTheme.typography.titleLarge)
        Text(status)
    }
}

private fun runAsync(context: Context, appendStatus: (String) -> Unit, block: suspend () -> Unit) {
    kotlinx.coroutines.CoroutineScope(Dispatchers.Main).launch {
        try {
            block()
        } catch (error: Throwable) {
            val message = error.message ?: error.toString()
            appendStatus("action failed: $message")
            writeBenchmarkFile(context, "final_result.txt", "proof_generated=false\nverify_pass=false\nerror=$message\n")
        }
    }
}

private fun validatePasswordInputSummary(input: String) {
    val json = JSONObject(input)
    val matchLength = jsonFieldString(json, "matchLength").toInt()
    require(matchLength == 10) { "matchLength mismatch: $matchLength" }
    val passwordLength = matchLength - 2
    require(passwordLength == 8) { "passwordLength mismatch: $passwordLength" }
    require(jsonFieldString(json, "passwordCommitment") == EXPECTED_COMMITMENT) { "commitment mismatch" }
    require(json.getJSONArray("inHaystack").length() == 35) { "inHaystack length mismatch" }
}

private fun validatePasswordVector(input: String, vector: PasswordMatrixVector) {
    val json = JSONObject(input)
    val matchLength = jsonFieldString(json, "matchLength").toInt()
    require(matchLength == vector.length + 2) {
        "${vector.runName}: matchLength mismatch: $matchLength"
    }
    require(jsonFieldString(json, "passwordCommitment") == vector.commitment) {
        "${vector.runName}: commitment mismatch"
    }
    require(jsonFieldString(json, "salt") == vector.salt) {
        "${vector.runName}: salt mismatch"
    }
    require(json.getJSONArray("inHaystack").length() == 35) {
        "${vector.runName}: inHaystack length mismatch"
    }
}

private fun jsonFieldString(json: JSONObject, name: String): String {
    val value = json.get(name)
    return if (value is JSONArray) {
        require(value.length() == 1) { "$name must be scalar or single-item array" }
        value.getString(0)
    } else {
        value.toString()
    }
}

private class MemorySampler {
    @Volatile private var running = false
    @Volatile var peak: MemorySample = sampleMemory("peak_initial")
        private set
    @Volatile var peakPssKb: Int = peak.totalPssKb
        private set
    @Volatile var peakRssKb: Int = peak.totalRssKb
        private set
    private var thread: Thread? = null

    fun start() {
        running = true
        thread = Thread {
            while (running) {
                val sample = sampleMemory("proving_sample")
                if (sample.totalPssKb > peak.totalPssKb) peak = sample
                if (sample.totalPssKb > peakPssKb) peakPssKb = sample.totalPssKb
                if (sample.totalRssKb > peakRssKb) peakRssKb = sample.totalRssKb
                Thread.sleep(500)
            }
        }
        thread?.start()
    }

    fun stop() {
        running = false
        thread?.join(1000)
    }
}

private data class MemorySample(
    val label: String,
    val totalPssKb: Int,
    val totalRssKb: Int,
    val javaHeapUsedBytes: Long,
    val nativeHeapAllocatedBytes: Long,
    val runtimeMaxBytes: Long
) {
    fun toReport(): String = listOf(
        "label=$label",
        "total_pss_kb=$totalPssKb",
        "total_rss_kb=$totalRssKb",
        "java_heap_used_bytes=$javaHeapUsedBytes",
        "native_heap_allocated_bytes=$nativeHeapAllocatedBytes",
        "runtime_max_bytes=$runtimeMaxBytes"
    ).joinToString("\n") + "\n"
}

private fun sampleMemory(label: String): MemorySample {
    val info = Debug.MemoryInfo()
    Debug.getMemoryInfo(info)
    val runtime = Runtime.getRuntime()
    return MemorySample(
        label = label,
        totalPssKb = info.totalPss,
        totalRssKb = info.memoryStats["summary.total-rss"]?.toIntOrNull() ?: -1,
        javaHeapUsedBytes = runtime.totalMemory() - runtime.freeMemory(),
        nativeHeapAllocatedBytes = Debug.getNativeHeapAllocatedSize(),
        runtimeMaxBytes = runtime.maxMemory()
    )
}

private fun appendMemoryReport(context: Context, before: MemorySample, peak: MemorySample, after: MemorySample) {
    writeBenchmarkFile(
        context,
        "memory.txt",
        listOf(
            "[before]",
            before.toReport(),
            "[peak]",
            peak.toReport(),
            "[after]",
            after.toReport()
        ).joinToString("\n")
    )
}

private fun nowNs(): Long = SystemClock.elapsedRealtimeNanos()

private fun elapsedMs(startNs: Long): Long = (SystemClock.elapsedRealtimeNanos() - startNs) / 1_000_000L

private fun benchmarkDir(context: Context): File = File(context.filesDir, "password_benchmark").also { it.mkdirs() }

private fun passwordMatrixDir(context: Context): File =
    File(context.filesDir, "password_matrix").also { it.mkdirs() }

private fun writeBenchmarkFile(context: Context, name: String, text: String) {
    File(benchmarkDir(context), name).writeText(text, Charsets.UTF_8)
}

private fun appendBenchmarkLine(context: Context, name: String, line: String) {
    File(benchmarkDir(context), name).appendText(line + "\n", Charsets.UTF_8)
}

private fun resetBenchmarkReports(context: Context) {
    benchmarkDir(context).listFiles()?.forEach { it.delete() }
}
