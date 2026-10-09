package dev.eudi.akprobe;

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.TreeSet;

/**
 * Can Alice's attest key vouch for a key that lives in Bob's wallet?
 *
 * Bob (one app, i.e. one keystore namespace) generates a hardware key and hands over what a
 * wallet can hand over: the public key and its attestation chain. Alice (another app) then
 * tries every route the platform offers to get her AK to certify that public key: have the AK
 * sign a certificate body carrying Bob's key, generate a key under the AK, and import.
 */
final class ForeignKeyProbe {
    private static final String TAG = MainActivity.TAG;
    private static final String STRONGBOX = "strongbox";
    private static final String TEE = "tee";

    private final Context ctx;
    private final KeyStore ks;
    private final SecureRandom random = new SecureRandom();
    private final StringBuilder summary = new StringBuilder();
    private final long runId = System.currentTimeMillis();
    private final String level;

    ForeignKeyProbe(Context ctx) throws Exception {
        this.ctx = ctx;
        ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        level = ctx.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE) ? STRONGBOX : TEE;
    }

    /** Bob: a wallet key with an ordinary system attestation, and an attempt to export it. */
    String runBob() throws Exception {
        String alias = "bob-key";
        deleteQuietly(alias);
        generate(alias, KeyProperties.PURPOSE_SIGN, challenge(), null);

        JSONObject o = new JSONObject();
        o.put("role", "bob");
        o.put("level", level);
        o.put("chain", chain(alias));
        PrivateKey key = (PrivateKey) ks.getKey(alias, null);
        byte[] encoded = key.getEncoded();
        o.put("export_getEncoded", encoded == null ? "null (no key material)" : "EXPORTED " + encoded.length + " bytes");
        try {
            KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore").getKeySpec(key, PKCS8EncodedKeySpec.class);
            o.put("export_pkcs8", "EXPORTED");
        } catch (Exception e) {
            o.put("export_pkcs8", "refused: " + describe(e));
        }
        line("Bob generated '" + alias + "' in " + level);
        line("Bob exports his private key, getEncoded(): " + o.getString("export_getEncoded"));
        line("Bob exports his private key, PKCS#8: " + o.getString("export_pkcs8"));
        write("bob-" + runId + ".json", o);
        return summary.toString();
    }

    /** Alice: everything she can try with Bob's public key and chain (files/bob.json). */
    String runAlice() throws Exception {
        JSONObject bob = new JSONObject(read(new File(ctx.getFilesDir(), "bob.json")));
        Certificate[] bobChain = certs(bob.getJSONArray("chain"));
        byte[] bobSpki = bobChain[0].getPublicKey().getEncoded();
        String bobLevel = bob.getString("level");
        String akAlias = "ak-" + bobLevel;
        if (!ks.containsAlias(akAlias)) {
            generate(akAlias, KeyProperties.PURPOSE_ATTEST_KEY, challenge(), null);
        }

        JSONObject o = new JSONObject();
        o.put("role", "alice");
        o.put("level", bobLevel);
        o.put("ak_chain", chain(akAlias));
        o.put("bob_spki", b64(bobSpki));
        line("Alice received Bob's public key and chain (" + bobChain.length + " certificates)");

        // Route 1: the AK signs a certificate body carrying Bob's key. The body is a genuine
        // AK-issued attestation certificate of Alice with Bob's key spliced in.
        String template = "alice-template-" + runId;
        generate(template, KeyProperties.PURPOSE_SIGN, challenge(), akAlias);
        X509Certificate t = (X509Certificate) ks.getCertificate(template);
        byte[] tbs = t.getTBSCertificate();
        byte[] own = t.getPublicKey().getEncoded();
        int at = indexOf(tbs, own);
        if (at >= 0 && own.length == bobSpki.length) {
            System.arraycopy(bobSpki, 0, tbs, at, bobSpki.length);
            o.put("route1_tbs", b64(tbs));
            try {
                Signature s = Signature.getInstance("SHA256withECDSA");
                s.initSign((PrivateKey) ks.getKey(akAlias, null));
                s.update(tbs);
                o.put("route1_signature", b64(s.sign()));
                o.put("route1_outcome", "SIGNED");
            } catch (Exception e) {
                o.put("route1_outcome", "refused: " + describe(e));
            }
        } else {
            o.put("route1_outcome", "could not build the certificate body (at=" + at + ")");
        }
        line("Route 1, AK signs a certificate for Bob's key: " + o.getString("route1_outcome"));

        // Route 2: generation under the AK. The attested key is always the one generated by
        // that call; the spec has no parameter for an external public key.
        o.put("route2_chain", chain(template));
        o.put("route2_generated_key_is_bobs", Arrays.equals(own, bobSpki));
        o.put("keygen_attestation_setters", attestationSetters(KeyGenParameterSpec.Builder.class));
        line("Route 2, key generated under the AK is Bob's key: " + o.getBoolean("route2_generated_key_is_bobs"));
        line("   generation API, attestation setters: " + o.getJSONArray("keygen_attestation_setters"));

        // Route 3: import. Importing needs the private key (Bob's keystore refuses to export it),
        // and the import API has no attestation parameter at all. Best try: a software key of
        // Alice's stored with Bob's genuine chain as its certificate chain.
        o.put("import_attestation_setters", attestationSetters(KeyProtection.Builder.class));
        line("Route 3, import API, attestation setters: " + o.getJSONArray("import_attestation_setters"));
        String imported = "alice-import-" + runId;
        try {
            KeyPairGenerator soft = KeyPairGenerator.getInstance("EC");
            soft.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = soft.generateKeyPair();
            ks.setEntry(imported, new KeyStore.PrivateKeyEntry(kp.getPrivate(), bobChain),
                    new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setIsStrongBoxBacked(STRONGBOX.equals(bobLevel))
                            .build());
            o.put("route3_outcome", "imported");
            o.put("route3_chain", chain(imported));
        } catch (Exception e) {
            o.put("route3_outcome", "refused: " + describe(e));
        }
        line("   import of a software key with Bob's chain: " + o.getString("route3_outcome"));

        deleteQuietly(template);
        deleteQuietly(imported);
        write("alice-" + runId + ".json", o);
        return summary.toString();
    }

    private void generate(String alias, int purposes, byte[] challenge, String attestKeyAlias) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setIsStrongBoxBacked(STRONGBOX.equals(level))
                .setAttestationChallenge(challenge);
        if ((purposes & KeyProperties.PURPOSE_SIGN) != 0) b.setDigests(KeyProperties.DIGEST_SHA256);
        if (attestKeyAlias != null) b.setAttestKeyAlias(attestKeyAlias);
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        g.initialize(b.build());
        g.generateKeyPair();
    }

    /** Public methods of a builder whose name mentions attestation: the platform's entry points. */
    private static JSONArray attestationSetters(Class<?> builder) {
        TreeSet<String> names = new TreeSet<>();
        for (Method m : builder.getMethods()) {
            if (m.getName().toLowerCase().contains("attest")) names.add(m.getName());
        }
        return new JSONArray(names);
    }

    private JSONArray chain(String alias) throws Exception {
        JSONArray a = new JSONArray();
        Certificate[] certs = ks.getCertificateChain(alias);
        if (certs != null) {
            for (Certificate c : certs) a.put(b64(c.getEncoded()));
        }
        return a;
    }

    private static Certificate[] certs(JSONArray chain) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate[] out = new Certificate[chain.length()];
        for (int i = 0; i < chain.length(); i++) {
            out[i] = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(chain.getString(i), Base64.NO_WRAP)));
        }
        return out;
    }

    private void write(String name, JSONObject o) throws Exception {
        File f = new File(ctx.getFilesDir(), name);
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(o.toString(2).getBytes(StandardCharsets.UTF_8));
        }
        line("");
        line("Results: " + f.getAbsolutePath());
        Log.i(TAG, "wrote " + f.getAbsolutePath());
    }

    private static String read(File f) throws Exception {
        byte[] buf = new byte[(int) f.length()];
        try (InputStream in = new FileInputStream(f)) {
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n < 0) break;
                off += n;
            }
        }
        return new String(buf, StandardCharsets.UTF_8);
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
