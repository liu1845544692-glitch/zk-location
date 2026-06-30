package com.example.moproapp

import android.util.Log
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONArray
import org.json.JSONObject
import uniffi.mopro.ProofLib
import uniffi.mopro.generateCircomProof
import uniffi.mopro.generateLocationCircuitInput
import uniffi.mopro.verifyCircomProof
import java.io.File
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val REGRESSION_TAG = "WitnessRegression"

private data class RegressionCase(
    val name: String,
    val zkeyPath: String,
    val expectedPublicCount: Int,
    val expectedPublic: (String) -> String,
    val buildInput: () -> String
)

@Composable
fun WitnessRegressionScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val areajudge = getFilePathFromAssets("areajudge_final.zkey")
    val regexIp = getFilePathFromAssets("regex_ip_final.zkey")
    val timestamp = getFilePathFromAssets("regex_timestamp_final.zkey")
    val portTrans = getFilePathFromAssets("port_trans_final.zkey")
    val unit = getFilePathFromAssets("unit_final.zkey")
    val protocol = getFilePathFromAssets("protocol_regex_final.zkey")
    var status by remember { mutableStateOf("running") }

    LaunchedEffect(Unit) {
        val outputDir = File(context.filesDir, "witness_regression").apply { mkdirs() }
        val results = mutableListOf<String>()
        try {
            val cases = listOf(
                locationCase(areajudge),
                regexCase("source_ip", regexIp, "192.168.1.12".ipv4Bytes()),
                regexCase("destination_ip", regexIp, "192.168.1.1".ipv4Bytes()),
                regexCase("timestamp", timestamp, "2024-02-29 23:59:59.999999".asciiBytes()),
                regexCase("port", portTrans, "00502".asciiBytes()),
                regexCase("trans", portTrans, "19164".asciiBytes()),
                regexCase("unit", unit, "000".asciiBytes()),
                regexCase("protocol", protocol, "Modbus/TCP".asciiBytes())
            )
            for (case in cases) {
                val inputStarted = System.nanoTime()
                val input = case.buildInput()
                val expectedPublic = case.expectedPublic(input)
                val inputMs = elapsedMillis(inputStarted)
                val proofStarted = System.nanoTime()
                val proof = regressionWorker("${case.name}-proof") {
                    generateCircomProof(case.zkeyPath, input, ProofLib.ARKWORKS)
                }
                val proofMs = elapsedMillis(proofStarted)
                val verifyStarted = System.nanoTime()
                val verified = regressionWorker("${case.name}-verify") {
                    verifyCircomProof(case.zkeyPath, proof, ProofLib.ARKWORKS)
                }
                val verifyMs = elapsedMillis(verifyStarted)
                val publicValue = proof.inputs.firstOrNull()
                val passed = verified &&
                    proof.inputs.size == case.expectedPublicCount &&
                    publicValue == expectedPublic
                val report = listOf(
                    "module=${case.name}",
                    "input_construct_ms=$inputMs",
                    "proof_ms=$proofMs",
                    "verify_ms=$verifyMs",
                    "public_inputs_count=${proof.inputs.size}",
                    "expected_public_inputs_count=${case.expectedPublicCount}",
                    "public_input_0=${publicValue.orEmpty()}",
                    "expected_public=$expectedPublic",
                    "verify=$verified",
                    "passed=$passed"
                ).joinToString("\n") + "\n"
                File(outputDir, "${case.name}.txt").writeText(report)
                Log.i(REGRESSION_TAG, "${case.name}: verify=$verified publicMatch=${publicValue == expectedPublic}")
                check(passed) { "${case.name} regression failed" }
                results += "${case.name}=PASS"
            }
            File(outputDir, "android-summary.txt").writeText(
                (results + listOf("oom=false", "result=PASS")).joinToString("\n") + "\n"
            )
            status = "PASS"
        } catch (error: Throwable) {
            val message = error.message ?: error.toString()
            File(outputDir, "android-summary.txt").writeText(
                (results + listOf("result=FAIL", "error=$message")).joinToString("\n") + "\n"
            )
            Log.e(REGRESSION_TAG, "regression failed: $message", error)
            status = "FAIL: $message"
        }
    }

    Column(modifier = modifier.fillMaxSize().padding(16.dp)) {
        Text("Witness Regression", style = MaterialTheme.typography.titleLarge)
        Text(status)
    }
}

private fun locationCase(zkeyPath: String): RegressionCase {
    return RegressionCase(
        name = "location",
        zkeyPath = zkeyPath,
        expectedPublicCount = 37,
        expectedPublic = { input ->
            JSONObject(input).getJSONArray("public_commitment").getString(0)
        },
        buildInput = { generateLocationCircuitInput(39.9042, 116.3974, 9.toUByte()) }
    )
}

private fun regexCase(name: String, zkeyPath: String, bytes: List<String>) = RegressionCase(
    name = name,
    zkeyPath = zkeyPath,
    expectedPublicCount = 1,
    expectedPublic = { "1" },
    buildInput = { JSONObject().put("msg", JSONArray(bytes)).toString() }
)

private fun String.asciiBytes(): List<String> = map { it.code.toString() }

private fun String.ipv4Bytes(): List<String> = split('.')
    .joinToString(".") { it.padStart(3, '0') }
    .asciiBytes()

private fun elapsedMillis(started: Long): Long = (System.nanoTime() - started) / 1_000_000L

private suspend fun <T> regressionWorker(name: String, block: () -> T): T =
    suspendCancellableCoroutine { continuation ->
        Thread(
            null,
            {
                try {
                    continuation.resume(block())
                } catch (error: Throwable) {
                    continuation.resumeWithException(error)
                }
            },
            name,
            64L * 1024L * 1024L
        ).start()
    }
