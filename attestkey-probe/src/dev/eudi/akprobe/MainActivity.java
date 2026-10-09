package dev.eudi.akprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Runs a probe off the UI thread and shows its summary: the {@link Probe} by default, or one
 * side of the {@link ForeignKeyProbe} when started with {@code --es mode bob|alice}.
 */
public class MainActivity extends Activity {
    static final String TAG = "AKPROBE";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        final TextView out = new TextView(this);
        out.setTextIsSelectable(true);
        out.setPadding(32, 32, 32, 32);
        out.setText("Running attest-key probe…");
        ScrollView scroll = new ScrollView(this);
        scroll.addView(out);
        setContentView(scroll);

        final String mode = getIntent().getStringExtra("mode");
        // Anonymous classes rather than lambdas: android.jar lacks the LambdaMetafactory javac needs.
        new Thread(new Runnable() {
            @Override
            public void run() {
                String text;
                try {
                    if ("bob".equals(mode)) {
                        text = new ForeignKeyProbe(getApplicationContext()).runBob();
                    } else if ("alice".equals(mode)) {
                        text = new ForeignKeyProbe(getApplicationContext()).runAlice();
                    } else {
                        text = new Probe(getApplicationContext()).run();
                    }
                } catch (Throwable t) {
                    text = "FATAL\n" + Log.getStackTraceString(t);
                    Log.e(TAG, text);
                }
                final String shown = text;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        out.setText(shown);
                    }
                });
            }
        }).start();
    }
}
