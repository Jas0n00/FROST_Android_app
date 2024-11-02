// MainActivity.kt

package cz.but.frost

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.TextView

class MainActivity : AppCompatActivity() {

    // Load the native library
    init {
        System.loadLibrary("native-lib")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Test parameters for the cryptographic protocol
        val threshold = 3
        val participants = 5
        val message = "Test message"
        val indices = intArrayOf(0, 1, 2)

        // Execute the cryptographic signing protocol
        executeSigning(threshold, participants, message, indices)

        // Output display (Add a TextView with the id `textView` in your layout)
        val textView: TextView = findViewById(R.id.textView)
        textView.text = "Signature protocol executed. Check logs for output."
    }

    // Native function declaration
    external fun executeSigning(threshold: Int, participants: Int, message: String, indices: IntArray)
}
