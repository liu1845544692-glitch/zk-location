package com.example.moproapp

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class DebugToolsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val initialTool = when {
            intent.getBooleanExtra("password_matrix_auto", false) -> "password-matrix"
            intent.getBooleanExtra("witness_regression_auto", false) -> "witness-regression"
            intent.getBooleanExtra("password_benchmark_auto", false) -> "password-len8"
            else -> "menu"
        }
        setContent {
            MaterialTheme {
                var tool by remember { mutableStateOf(initialTool) }
                when (tool) {
                    "password-len8" -> PasswordProofBenchmarkScreen(
                        autoRun = initialTool == "password-len8",
                        onBack = { tool = "menu" }
                    )
                    "password-matrix" -> PasswordMatrixBenchmarkScreen()
                    "witness-regression" -> WitnessRegressionScreen()
                    else -> Column(
                        modifier = Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text("Debug Tools", style = MaterialTheme.typography.headlineSmall)
                        Button(onClick = { tool = "password-len8" }) { Text("Password len8") }
                        Button(onClick = { tool = "password-matrix" }) { Text("Password matrix") }
                        Button(onClick = { tool = "witness-regression" }) { Text("Witness regression") }
                    }
                }
            }
        }
    }
}
