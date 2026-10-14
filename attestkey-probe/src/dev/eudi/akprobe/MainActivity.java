package dev.eudi.akprobe;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Runs a probe off the UI thread and shows its summary: the {@link Probe} by default, one side
 * of the {@link ForeignKeyProbe} when started with {@code --es mode bob|alice}, or a stage of the
 * {@link LateAttestProbe} with {@code --es mode late-setup|late-attest}.
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
                    text = MainActivity.run(getApplicationContext(), mode);
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

    /** The probe selected by {@code mode}; shared with {@link ProbeInstrumentation}. */
    static String run(Context ctx, String mode) throws Exception {
        if ("bob".equals(mode)) return new ForeignKeyProbe(ctx).runBob();
        if ("alice".equals(mode)) return new ForeignKeyProbe(ctx).runAlice();
        if ("late-setup".equals(mode)) return new LateAttestProbe(ctx).runSetup();
        if ("late-attest".equals(mode)) return new LateAttestProbe(ctx).runAttest();
        return new Probe(ctx).run();
    }
}
