package dev.eudi.akprobe;

import android.content.Context;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import javax.security.auth.x500.X500Principal;

/**
 * Probes KeyMint app attestation keys (PURPOSE_ATTEST_KEY + setAttestKeyAlias) as a
 * co-residency primitive: two keys whose attestation certificates are signed by the same
 * attest key (AK) were generated in the KeyMint instance holding that AK.
 *
 * Per security level it records the AK chain and two AK-attested keys, then tries what an
 * attacker would: use the AK as an ordinary signing key, use it across KeyMint instances,
 * and vouch for a foreign ("Bob's") key by re-signing an attestation certificate with an
 * ordinary key of the same device. Everything lands in files/akprobe-<run>.json for
 * verify_attestkey.py on the host.
 */
final class Probe {
    private static final String TAG = MainActivity.TAG;
    private static final String STRONGBOX = "strongbox";
    private static final String TEE = "tee";
    private static final int TIMING_RUNS = 5;

    private final Context ctx;
    private final KeyStore ks;
    private final SecureRandom random = new SecureRandom();
    private final StringBuilder summary = new StringBuilder();
    private final long runId = System.currentTimeMillis();

    Probe(Context ctx) throws Exception {
        this.ctx = ctx;
        ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
    }

    String run() throws Exception {
        PackageManager pm = ctx.getPackageManager();
        boolean strongbox = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        boolean appAttestKeys = pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY);
        line("Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + "), "
                + Build.MANUFACTURER + " " + Build.MODEL);
        line("StrongBox: " + strongbox + ", app attest keys: " + appAttestKeys);

        JSONObject result = new JSONObject();
        result.put("run_id", runId);
        result.put("device", deviceInfo(strongbox, appAttestKeys));

        JSONObject levels = new JSONObject();
        for (String level : strongbox ? new String[]{STRONGBOX, TEE} : new String[]{TEE}) {
            levels.put(level, probeLevel(level));
        }
        result.put("levels", levels);
        if (strongbox) {
            result.put("cross_level", crossLevel());
        }

        File f = write(result);
        line("");
        line("Results: " + f.getAbsolutePath());
        return summary.toString();
    }

    private JSONObject probeLevel(String level) throws Exception {
        JSONObject o = new JSONObject();
        line("");
        line("== " + level);

        // The AK persists across runs, so a key generated on a later run (an EAA key months
        // after the PID key) can still be checked against the same AK.
        String akAlias = "ak-" + level;
        JSONObject ak = new JSONObject();
        boolean reused = ks.containsAlias(akAlias);
        ak.put("alias", akAlias);
        ak.put("reused", reused);
        if (!reused) {
            byte[] challenge = challenge();
            long t = System.nanoTime();
            try {
                generate(akAlias, KeyProperties.PURPOSE_ATTEST_KEY, level, challenge, null, null);
            } catch (Exception e) {
                ak.put("error", describe(e));
                o.put("ak", ak);
                line("AK generation FAILED: " + describe(e));
                return o;
            }
            ak.put("gen_ms", ms(t));
            ak.put("challenge", b64(challenge));
        }
        ak.put("chain", chain(akAlias));
        o.put("ak", ak);
        line(reused ? "AK reused from a previous run" : "AK generated in " + ak.getLong("gen_ms") + " ms");

        // The pair whose co-residency the verifier has to establish.
        for (String name : new String[]{"k1", "k2"}) {
            String alias = name + "-" + level + "-" + runId;
            byte[] challenge = challenge();
            JSONObject k = new JSONObject();
            k.put("alias", alias);
            long t = System.nanoTime();
            try {
                generate(alias, KeyProperties.PURPOSE_SIGN, level, challenge, akAlias, null);
                k.put("gen_ms", ms(t));
                k.put("challenge", b64(challenge));
                k.put("chain", chain(alias));
                line(name + " attested by the AK in " + k.getLong("gen_ms") + " ms (chain length "
                        + k.getJSONArray("chain").length() + ")");
            } catch (Exception e) {
                k.put("error", describe(e));
                line(name + " FAILED: " + describe(e));
            }
            o.put(name, k);
        }

        o.put("ak_sign_attempt", tryToSignWith(akAlias));
        line("AK used to sign arbitrary data: " + o.getString("ak_sign_attempt"));

        if (o.getJSONObject("k2").has("chain")) {
            o.put("forgery", forge(level, akAlias, o.getJSONObject("k2").getString("alias")));
        }
        o.put("timing", timing(level, akAlias));

        deleteQuietly(o.getJSONObject("k1").getString("alias"));
        deleteQuietly(o.getJSONObject("k2").getString("alias"));
        return o;
    }

    /** An attest key may sign attestations only; anything else must be refused. */
    private String tryToSignWith(String alias) {
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign((PrivateKey) ks.getKey(alias, null));
            s.update("an arbitrary statement chosen by the app".getBytes(StandardCharsets.UTF_8));
            s.sign();
            return "SIGNED (the attest key signs arbitrary data!)";
        } catch (Exception e) {
            return "refused: " + describe(e);
        }
    }

    /**
     * The attack the AK has to withstand: Alice vouches for Bob's key with hardware of her
     * own. The AK cannot sign arbitrary data, so she takes an ordinary SIGN key of the same
     * KeyMint, gives it the AK's certificate subject, and re-signs k2's attestation
     * certificate with Bob's public key spliced in. The issuer's purpose (ATTEST_KEY vs
     * SIGN) is then the only thing that tells the forgery apart.
     */
    private JSONObject forge(String level, String akAlias, String k2Alias) throws Exception {
        JSONObject f = new JSONObject();
        String signerAlias = "alice-sign-" + level + "-" + runId;
        try {
            X500Principal akSubject = ((X509Certificate) ks.getCertificate(akAlias)).getSubjectX500Principal();
            byte[] challenge = challenge();
            generate(signerAlias, KeyProperties.PURPOSE_SIGN, level, challenge, null, akSubject);
            f.put("signer_chain", chain(signerAlias));
            f.put("signer_challenge", b64(challenge));

            KeyPairGenerator soft = KeyPairGenerator.getInstance("EC");
            soft.initialize(new ECGenParameterSpec("secp256r1"));
            byte[] bobSpki = soft.generateKeyPair().getPublic().getEncoded();

            X509Certificate leaf = (X509Certificate) ks.getCertificate(k2Alias);
            byte[] tbs = leaf.getTBSCertificate();
            byte[] spki = leaf.getPublicKey().getEncoded();
            int at = indexOf(tbs, spki);
            if (at < 0 || spki.length != bobSpki.length) {
                f.put("error", "could not splice Bob's key into the TBS (at=" + at + ")");
                return f;
            }
            System.arraycopy(bobSpki, 0, tbs, at, bobSpki.length);

            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign((PrivateKey) ks.getKey(signerAlias, null));
            s.update(tbs);
            f.put("tbs", b64(tbs));
            f.put("signature", b64(s.sign()));
            f.put("bob_spki", b64(bobSpki));
            line("Forgery prepared: Bob's key re-signed by an ordinary " + level + " key of Alice");
        } catch (Exception e) {
            f.put("error", describe(e));
            line("Forgery step failed: " + describe(e));
        } finally {
            deleteQuietly(signerAlias);
        }
        return f;
    }

    private JSONObject timing(String level, String akAlias) throws Exception {
        JSONArray akGen = new JSONArray();
        JSONArray systemAttested = new JSONArray();
        JSONArray akAttested = new JSONArray();
        for (int i = 0; i < TIMING_RUNS; i++) {
            akGen.put(timedGenerate("t-ak-" + level + "-" + i, KeyProperties.PURPOSE_ATTEST_KEY, level, null));
            systemAttested.put(timedGenerate("t-sys-" + level + "-" + i, KeyProperties.PURPOSE_SIGN, level, null));
            akAttested.put(timedGenerate("t-byak-" + level + "-" + i, KeyProperties.PURPOSE_SIGN, level, akAlias));
        }
        JSONObject t = new JSONObject();
        t.put("attest_key_gen_ms", akGen);
        t.put("system_attested_key_gen_ms", systemAttested);
        t.put("ak_attested_key_gen_ms", akAttested);
        line("Timing ms x" + TIMING_RUNS + ": AK " + akGen + " | key+system attestation "
                + systemAttested + " | key+AK attestation " + akAttested);
        return t;
    }

    private long timedGenerate(String alias, int purpose, String level, String attestKeyAlias) {
        long t = System.nanoTime();
        try {
            generate(alias, purpose, level, challenge(), attestKeyAlias, null);
            return ms(t);
        } catch (Exception e) {
            Log.w(TAG, "timing run failed: " + describe(e));
            return -1;
        } finally {
            deleteQuietly(alias);
        }
    }

    /** An AK is a key blob of one KeyMint instance; the other instance has to refuse it. */
    private JSONObject crossLevel() throws Exception {
        JSONObject c = new JSONObject();
        c.put("tee_key_attested_by_strongbox_ak", attempt("x-tee-" + runId, TEE, "ak-" + STRONGBOX));
        c.put("strongbox_key_attested_by_tee_ak", attempt("x-sb-" + runId, STRONGBOX, "ak-" + TEE));
        line("");
        line("TEE key + StrongBox AK: " + c.getJSONObject("tee_key_attested_by_strongbox_ak").getString("outcome"));
        line("StrongBox key + TEE AK: " + c.getJSONObject("strongbox_key_attested_by_tee_ak").getString("outcome"));
        return c;
    }

    private JSONObject attempt(String alias, String level, String akAlias) throws Exception {
        JSONObject a = new JSONObject();
        try {
            generate(alias, KeyProperties.PURPOSE_SIGN, level, challenge(), akAlias, null);
            a.put("outcome", "ACCEPTED");
            a.put("chain", chain(alias));
        } catch (Exception e) {
            a.put("outcome", "refused: " + describe(e));
        } finally {
            deleteQuietly(alias);
        }
        return a;
    }

    private void generate(String alias, int purposes, String level, byte[] challenge,
                          String attestKeyAlias, X500Principal subject) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setIsStrongBoxBacked(STRONGBOX.equals(level));
        if ((purposes & KeyProperties.PURPOSE_SIGN) != 0) b.setDigests(KeyProperties.DIGEST_SHA256);
        if (challenge != null) b.setAttestationChallenge(challenge);
        if (attestKeyAlias != null) b.setAttestKeyAlias(attestKeyAlias);
        if (subject != null) b.setCertificateSubject(subject);
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        g.initialize(b.build());
        g.generateKeyPair();
    }

    private JSONObject deviceInfo(boolean strongbox, boolean appAttestKeys) throws Exception {
        JSONObject d = new JSONObject();
        d.put("manufacturer", Build.MANUFACTURER);
        d.put("model", Build.MODEL);
        d.put("release", Build.VERSION.RELEASE);
        d.put("sdk", Build.VERSION.SDK_INT);
        d.put("security_patch", Build.VERSION.SECURITY_PATCH);
        d.put("strongbox", strongbox);
        d.put("app_attest_keys", appAttestKeys);
        JSONObject features = new JSONObject();
        for (FeatureInfo fi : ctx.getPackageManager().getSystemAvailableFeatures()) {
            if (fi.name != null && (fi.name.contains("keystore") || fi.name.contains("strongbox"))) {
                features.put(fi.name, fi.version);
            }
        }
        d.put("keystore_features", features);
        return d;
    }

    private JSONArray chain(String alias) throws Exception {
        JSONArray a = new JSONArray();
        Certificate[] certs = ks.getCertificateChain(alias);
        if (certs != null) {
            for (Certificate c : certs) a.put(b64(c.getEncoded()));
        }
        return a;
    }

    private File write(JSONObject result) throws Exception {
        File f = new File(ctx.getFilesDir(), "akprobe-" + runId + ".json");
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(result.toString(2).getBytes(StandardCharsets.UTF_8));
        }
        Log.i(TAG, "wrote " + f.getAbsolutePath());
        return f;
    }

    private void line(String s) {
        summary.append(s).append('\n');
        Log.i(TAG, s);
    }

    private byte[] challenge() {
        byte[] c = new byte[16];
        random.nextBytes(c);
        return c;
    }

    private void deleteQuietly(String alias) {
        try {
            ks.deleteEntry(alias);
        } catch (Exception ignored) {
            // best effort: a leftover throwaway key is harmless
        }
    }

    private static long ms(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    private static String b64(byte[] b) {
        return Base64.encodeToString(b, Base64.NO_WRAP);
    }

    private static String describe(Throwable e) {
        StringBuilder s = new StringBuilder(e.getClass().getSimpleName() + ": " + e.getMessage());
        for (Throwable c = e.getCause(); c != null; c = c.getCause()) {
            s.append(" <- ").append(c.getClass().getSimpleName()).append(": ").append(c.getMessage());
        }
        return s.toString();
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }
}
