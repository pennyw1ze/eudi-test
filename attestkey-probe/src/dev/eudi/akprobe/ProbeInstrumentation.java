package dev.eudi.akprobe;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.util.Log;

/**
 * Runs a probe mode under instrumentation, in a fresh process, and returns its summary as the
 * instrumentation result. Started this way, the shell can pass --no-hidden-api-checks, which
 * lets {@link LateAttestProbe} call keystore2's binder interface directly:
 *
 * adb shell am instrument -w [--no-hidden-api-checks] -e mode MODE dev.eudi.akprobe/dev.eudi.akprobe.ProbeInstrumentation
 */
public class ProbeInstrumentation extends Instrumentation {
    private String mode;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        mode = arguments == null ? null : arguments.getString("mode");
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        int code = Activity.RESULT_OK;
        String text;
        try {
            text = MainActivity.run(getTargetContext(), mode);
        } catch (Throwable t) {
            text = "FATAL\n" + Log.getStackTraceString(t);
            Log.e(MainActivity.TAG, text);
            code = Activity.RESULT_CANCELED;
        }
        result.putString(REPORT_KEY_STREAMRESULT, text);
        finish(code, result);
    }
}
