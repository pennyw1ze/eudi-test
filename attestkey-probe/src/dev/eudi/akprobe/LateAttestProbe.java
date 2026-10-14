package dev.eudi.akprobe;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.IBinder;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;

/**
 * Can an attest key (AK) created now certify a key that already exists?
 *
 * Stage {@code late-setup} generates, per security level, two ordinary hardware keys with the
 * platform's usual attestation, while no AK exists. Stage {@code late-attest}, run later in a
 * new process, creates a fresh AK and tries every route to an AK-signed attestation for those
 * older keys: the AK signs a certificate body, export and re-import, copy the keystore entry,
 * regenerate under the same alias, and keystore2's binder interface itself (generateKey and
 * importKey with the AK as attestation key). The binder calls are hidden API, so late.sh runs
 * that stage with {@code am instrument --no-hidden-api-checks}. verify_late.py checks the two
 * result files on the host.
 */
final class LateAttestProbe {
    private static final String TAG = MainActivity.TAG;
    private static final String STRONGBOX = "strongbox";
    private static final String TEE = "tee";
    private static final String KM = "android.hardware.security.keymint.";
    private static final String KS2 = "android.system.keystore2.";
    private static final byte[] MESSAGE = "signed with a key that predates the AK".getBytes(StandardCharsets.UTF_8);

    // Aliases, suffixed with the security level. OLD and REGEN are the pre-existing keys.
    private static final String PREFIX = "late-";
    private static final String OLD = PREFIX + "old-";
    private static final String REGEN = PREFIX + "regen-";
    private static final String AK = PREFIX + "ak-";
    private static final String TEMPLATE = PREFIX + "template-";
    private static final String COPY = PREFIX + "copy-";
    private static final String BINDER = PREFIX + "binder-";

    private final Context ctx;
    private final KeyStore ks;
    private final SecureRandom random = new SecureRandom();
    private final StringBuilder summary = new StringBuilder();
    private final long runId = System.currentTimeMillis();
    private final boolean strongbox;

    LateAttestProbe(Context ctx) throws Exception {
        this.ctx = ctx;
        ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        strongbox = ctx.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
    }

    /** The pre-existing keys: ordinary hardware keys, attested by the platform, no AK anywhere. */
    String runSetup() throws Exception {
        for (String alias : Collections.list(ks.aliases())) {
            if (alias.startsWith(PREFIX)) deleteQuietly(alias);
        }
        JSONObject result = header("setup");
        JSONObject levels = new JSONObject();
        for (String level : levels()) {
            line("");
            line("== " + level);
            JSONObject o = new JSONObject();
            o.put("old", generateRecorded(OLD + level, KeyProperties.PURPOSE_SIGN, level, null));
            o.put("regen", generateRecorded(REGEN + level, KeyProperties.PURPOSE_SIGN, level, null));
            o.put("ak_exists", ks.containsAlias(AK + level));
            line("old and regen keys generated with the platform's attestation: "
                    + outcome(o.getJSONObject("old")) + ", " + outcome(o.getJSONObject("regen")));
            line("an AK exists at this point: " + o.getBoolean("ak_exists"));
            levels.put(level, o);
        }
        result.put("levels", levels);
        write("late-setup-" + runId + ".json", result);
        return summary.toString();
    }

    /** A fresh AK, then every route to have it attest the keys made in the setup stage. */
    String runAttest() throws Exception {
        JSONObject result = header("attest");
        JSONObject surface = surface();
        result.put("binder_surface", surface);
        result.put("keygen_attestation_setters", ForeignKeyProbe.attestationSetters(KeyGenParameterSpec.Builder.class));
        result.put("import_attestation_setters", ForeignKeyProbe.attestationSetters(KeyProtection.Builder.class));
        JSONObject levels = new JSONObject();
        for (String level : levels()) {
            levels.put(level, attestLevel(level, surface.optBoolean("available")));
        }
        result.put("levels", levels);
        write("late-attest-" + runId + ".json", result);
        return summary.toString();
    }

    private JSONObject attestLevel(String level, boolean binder) throws Exception {
        JSONObject o = new JSONObject();
        line("");
        line("== " + level);
        String old = OLD + level, regen = REGEN + level, ak = AK + level, template = TEMPLATE + level;
        if (!ks.containsAlias(old) || !ks.containsAlias(regen)) {
            o.put("error", "pre-existing keys missing: run late-setup first");
            line(o.getString("error"));
            return o;
        }
        o.put("old_chain", chain(old));
        o.put("regen_chain_before", chain(regen));
        // The old key is live and the app's own: it signs on request.
        o.put("old_signature", b64(sign(old, MESSAGE)));

        deleteQuietly(ak);
        JSONObject akInfo = generateRecorded(ak, KeyProperties.PURPOSE_ATTEST_KEY, level, null);
        o.put("ak", akInfo);
        line("fresh AK: " + outcome(akInfo));
        if (akInfo.has("error")) return o;

        // Control: a key generated under the AK gets an AK-signed attestation.
        JSONObject t = generateRecorded(template, KeyProperties.PURPOSE_SIGN, level, ak);
        o.put("template", t);
        line("control, new key generated under the AK: " + outcome(t));

        if (t.has("chain")) {
            o.put("route_sign", signBody(ak, template, old));
            line("route 1, AK signs a certificate body carrying the old key: " + o.getJSONObject("route_sign").getString("outcome"));
        }
        o.put("route_export", export(old));
        line("route 2, export the old key: getEncoded " + o.getJSONObject("route_export").getString("getEncoded")
                + "; PKCS#8 " + o.getJSONObject("route_export").getString("pkcs8"));
        o.put("route_copy", copyEntry(old, COPY + level, level));
        line("route 3, copy the old key's entry to a new alias: " + o.getJSONObject("route_copy").getString("outcome"));
        if (binder) {
            o.put("binder", binderRoutes(level, ak));
        }
        // Destructive, so last: generating under the old key's alias with the AK.
        o.put("route_regenerate", regenerate(regen, level, ak));
        line("route 5, generate under the regen key's alias with the AK: "
                + o.getJSONObject("route_regenerate").getString("outcome"));

        for (String alias : Collections.list(ks.aliases())) {
            if (alias.startsWith(TEMPLATE) || alias.startsWith(COPY) || alias.startsWith(BINDER)) deleteQuietly(alias);
        }
        return o;
    }

    /** Route 1: a genuine AK-issued certificate body with the old key swapped in, for the AK to sign. */
    private JSONObject signBody(String akAlias, String templateAlias, String oldAlias) throws Exception {
        JSONObject r = new JSONObject();
        X509Certificate t = (X509Certificate) ks.getCertificate(templateAlias);
        byte[] tbs = t.getTBSCertificate();
        byte[] own = t.getPublicKey().getEncoded();
        byte[] old = ks.getCertificate(oldAlias).getPublicKey().getEncoded();
        int at = indexOf(tbs, own);
        if (at < 0 || own.length != old.length) {
            r.put("outcome", "could not build the certificate body (at=" + at + ")");
            return r;
        }
        System.arraycopy(old, 0, tbs, at, old.length);
        r.put("tbs", b64(tbs));
        try {
            r.put("signature", b64(sign(akAlias, tbs)));
            r.put("outcome", "SIGNED");
        } catch (Exception e) {
            r.put("outcome", "refused: " + describe(e));
        }
        return r;
    }

    /** Route 2: re-importing the old key anywhere needs its private key. */
    private JSONObject export(String alias) throws Exception {
        JSONObject r = new JSONObject();
        PrivateKey key = (PrivateKey) ks.getKey(alias, null);
        byte[] encoded = key.getEncoded();
        r.put("getEncoded", encoded == null ? "null (no key material)" : "EXPORTED " + encoded.length + " bytes");
        try {
            KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore").getKeySpec(key, PKCS8EncodedKeySpec.class);
            r.put("pkcs8", "EXPORTED");
        } catch (Exception e) {
            r.put("pkcs8", "refused: " + describe(e));
        }
        return r;
    }

    /** Route 3: store the old key's handle under a new alias, as an import would. */
    private JSONObject copyEntry(String oldAlias, String copyAlias, String level) throws Exception {
        JSONObject r = new JSONObject();
        try {
            ks.setEntry(copyAlias, new KeyStore.PrivateKeyEntry((PrivateKey) ks.getKey(oldAlias, null),
                            ks.getCertificateChain(oldAlias)),
                    new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setIsStrongBoxBacked(STRONGBOX.equals(level))
                            .build());
            r.put("outcome", "COPIED");
            r.put("chain", chain(copyAlias));
        } catch (Exception e) {
            r.put("outcome", "refused: " + describe(e));
        }
        return r;
    }

    /** Route 5: the generation API with the old key's alias and the AK. */
    private JSONObject regenerate(String alias, String level, String akAlias) throws Exception {
        JSONObject r = new JSONObject();
        byte[] c = challenge();
        try {
            generate(alias, KeyProperties.PURPOSE_SIGN, level, c, akAlias);
            r.put("outcome", "generated");
            r.put("challenge", b64(c));
            r.put("chain", chain(alias));
            r.put("signature", b64(sign(alias, MESSAGE)));
        } catch (Exception e) {
            r.put("outcome", "refused: " + describe(e));
        }
        return r;
    }

    // --- keystore2 binder interface (hidden API) ---------------------------------------------

    /**
     * What the app reaches below the public API: keystore2's two interfaces (their methods are
     * the whole key-management surface an app has), and whether KeyMint's HAL answers the app
     * directly.
     */
    private JSONObject surface() throws Exception {
        JSONObject s = new JSONObject();
        try {
            s.put("IKeystoreService", methods(Class.forName(KS2 + "IKeystoreService")));
            s.put("IKeystoreSecurityLevel", methods(Class.forName(KS2 + "IKeystoreSecurityLevel")));
            s.put("available", keystoreLevel(constant(KM + "SecurityLevel", "TRUSTED_ENVIRONMENT")) != null);
        } catch (Throwable t) {
            s.put("available", false);
            s.put("error", describe(unwrap(t)));
        }
        try {
            s.put("IKeyMintDevice", methods(Class.forName(KM + "IKeyMintDevice")));
        } catch (Throwable t) {
            s.put("IKeyMintDevice", "not loadable: " + describe(unwrap(t)));
        }
        for (String instance : new String[]{"default", "strongbox"}) {
            String name = KM + "IKeyMintDevice/" + instance;
            try {
                Object b = Class.forName("android.os.ServiceManager").getMethod("checkService", String.class).invoke(null, name);
                s.put("keymint_hal_" + instance, b == null ? "not reachable (no binder for the app)" : "BINDER OBTAINED");
            } catch (Throwable t) {
                s.put("keymint_hal_" + instance, "not reachable: " + describe(unwrap(t)));
            }
        }
        line("keystore2 binder interface reachable: " + s.getBoolean("available")
                + (s.has("error") ? " (" + s.getString("error") + ")" : ""));
        line("KeyMint HAL from the app: default " + s.getString("keymint_hal_default")
                + ", strongbox " + s.getString("keymint_hal_strongbox"));
        return s;
    }

    /**
     * Route 4: keystore2 itself. generateKey with the AK is the control (the descriptor does
     * reach the AK); then importKey with the AK, without it, and with it but no challenge.
     */
    private JSONObject binderRoutes(String level, String akAlias) throws Exception {
        JSONObject b = new JSONObject();
        Object securityLevel;
        try {
            securityLevel = keystoreLevel(constant(KM + "SecurityLevel", STRONGBOX.equals(level) ? "STRONGBOX" : "TRUSTED_ENVIRONMENT"));
        } catch (Throwable t) {
            b.put("error", describe(unwrap(t)));
            line("route 4 skipped: " + b.getString("error"));
            return b;
        }
        Object ak = descriptor(akAlias);
        KeyPairGenerator soft = KeyPairGenerator.getInstance("EC");
        soft.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = soft.generateKeyPair();
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        b.put("imported_spki", b64(kp.getPublic().getEncoded()));

        b.put("generate_with_ak", binderCall(securityLevel, "generateKey", BINDER + "gen-" + level, ak, true, null));
        b.put("import_with_ak", binderCall(securityLevel, "importKey", BINDER + "imp-ak-" + level, ak, true, pkcs8));
        b.put("import_without_ak", binderCall(securityLevel, "importKey", BINDER + "imp-noak-" + level, null, true, pkcs8));
        b.put("import_with_ak_no_challenge", binderCall(securityLevel, "importKey", BINDER + "imp-nochal-" + level, ak, false, pkcs8));
        line("route 4, keystore2 binder: generateKey with AK " + b.getJSONObject("generate_with_ak").getString("outcome")
                + " | importKey with AK " + b.getJSONObject("import_with_ak").getString("outcome")
                + " | importKey without AK " + b.getJSONObject("import_without_ak").getString("outcome")
                + " | importKey with AK, no challenge " + b.getJSONObject("import_with_ak_no_challenge").getString("outcome"));
        return b;
    }

    /** generateKey/importKey(key, attestationKey, params, flags, entropy | keyData) on keystore2. */
    private JSONObject binderCall(Object securityLevel, String op, String alias, Object attestKey,
                                  boolean withChallenge, byte[] keyData) throws Exception {
        JSONObject r = new JSONObject();
        r.put("attestation_key", attestKey == null ? "none" : "the fresh AK");
        deleteQuietly(alias);
        List<Object> params = new ArrayList<>();
        params.add(param("ALGORITHM", "algorithm", constant(KM + "Algorithm", "EC")));
        params.add(param("EC_CURVE", "ecCurve", constant(KM + "EcCurve", "P_256")));
        params.add(param("PURPOSE", "keyPurpose", constant(KM + "KeyPurpose", "SIGN")));
        params.add(param("DIGEST", "digest", constant(KM + "Digest", "SHA_2_256")));
        params.add(param("NO_AUTH_REQUIRED", "boolValue", true));
        if (withChallenge) {
            byte[] c = challenge();
            params.add(param("ATTESTATION_CHALLENGE", "blob", c));
            r.put("challenge", b64(c));
        }
        Object array = Array.newInstance(Class.forName(KM + "KeyParameter"), params.size());
        for (int i = 0; i < params.size(); i++) Array.set(array, i, params.get(i));
        Class<?> descriptor = Class.forName(KS2 + "KeyDescriptor");
        byte[] last = keyData != null ? keyData : randomBytes(32);   // keyData, or entropy for generateKey
        Method m = Class.forName(KS2 + "IKeystoreSecurityLevel")
                .getMethod(op, descriptor, descriptor, array.getClass(), int.class, byte[].class);
        try {
            Object metadata = m.invoke(securityLevel, descriptor(alias), attestKey, array, 0, last);
            r.put("outcome", "OK");
            byte[] cert = (byte[]) metadata.getClass().getField("certificate").get(metadata);
            byte[] rest = (byte[]) metadata.getClass().getField("certificateChain").get(metadata);
            if (cert != null) r.put("certificate", b64(cert));
            if (rest != null) r.put("certificate_chain", b64(rest));
            JSONObject origin = origin(metadata);
            if (origin != null) r.put("origin", origin);
        } catch (InvocationTargetException e) {
            Throwable cause = unwrap(e);
            r.put("outcome", "refused: " + describe(cause));
            if ("android.os.ServiceSpecificException".equals(cause.getClass().getName())) {
                int code = cause.getClass().getField("errorCode").getInt(cause);
                r.put("error_code", code);
                r.put("error_name", errorName(code));
            }
        }
        return r;
    }

    private static Object keystoreLevel(int securityLevel) throws Exception {
        IBinder b = (IBinder) Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class).invoke(null, KS2 + "IKeystoreService/default");
        Object service = Class.forName(KS2 + "IKeystoreService$Stub").getMethod("asInterface", IBinder.class).invoke(null, b);
        return Class.forName(KS2 + "IKeystoreService").getMethod("getSecurityLevel", int.class).invoke(service, securityLevel);
    }

    /** A key in the caller's own namespace (Domain.APP), as the AndroidKeyStore provider builds it. */
    private static Object descriptor(String alias) throws Exception {
        Class<?> c = Class.forName(KS2 + "KeyDescriptor");
        Object d = c.getConstructor().newInstance();
        c.getField("domain").setInt(d, constant(KS2 + "Domain", "APP"));
        c.getField("nspace").setLong(d, -1L);   // ignored for Domain.APP: keystore2 uses the caller's uid
        c.getField("alias").set(d, alias);
        return d;
    }

    private static Object param(String tag, String kind, Object value) throws Exception {
        Class<?> kp = Class.forName(KM + "KeyParameter");
        Class<?> type = value instanceof Boolean ? boolean.class : value instanceof byte[] ? byte[].class : int.class;
        Object p = kp.getConstructor().newInstance();
        kp.getField("tag").setInt(p, constant(KM + "Tag", tag));
        kp.getField("value").set(p, Class.forName(KM + "KeyParameterValue").getMethod(kind, type).invoke(null, value));
        return p;
    }

    /** Tag::ORIGIN among the key characteristics KeyMint returned. */
    private static JSONObject origin(Object metadata) throws Exception {
        int originTag = constant(KM + "Tag", "ORIGIN");
        Object[] authorizations = (Object[]) metadata.getClass().getField("authorizations").get(metadata);
        if (authorizations == null) return null;
        for (Object a : authorizations) {
            Object kp = a.getClass().getField("keyParameter").get(a);
            if (kp.getClass().getField("tag").getInt(kp) == originTag) {
                Object v = kp.getClass().getField("value").get(kp);
                JSONObject o = new JSONObject();
                o.put("origin", ((Integer) v.getClass().getMethod("getOrigin").invoke(v)).intValue());
                o.put("security_level", a.getClass().getField("securityLevel").getInt(a));
                return o;
            }
        }
        return null;
    }

    private static int constant(String className, String field) throws Exception {
        return Class.forName(className).getField(field).getInt(null);
    }

    /** KeyMint ErrorCode (negative) or keystore2 ResponseCode (positive) for a binder error. */
    private static String errorName(int code) {
        for (String cls : new String[]{KM + "ErrorCode", KS2 + "ResponseCode"}) {
            try {
                for (Field f : Class.forName(cls).getFields()) {
                    if (Modifier.isStatic(f.getModifiers()) && f.getType() == int.class && f.getInt(null) == code) {
                        return cls.substring(cls.lastIndexOf('.') + 1) + "." + f.getName();
                    }
                }
            } catch (Throwable ignored) {
                // name lookup is cosmetic
            }
        }
        return null;
    }

    private static JSONArray methods(Class<?> c) {
        TreeSet<String> out = new TreeSet<>();
        for (Method m : c.getDeclaredMethods()) {
            if (m.isSynthetic() || Modifier.isStatic(m.getModifiers())) continue;
            StringBuilder sig = new StringBuilder(m.getName()).append('(');
            Class<?>[] p = m.getParameterTypes();
            for (int i = 0; i < p.length; i++) sig.append(i == 0 ? "" : ", ").append(p[i].getSimpleName());
            out.add(sig.append(')').toString());
        }
        return new JSONArray(out);
    }

    private static Throwable unwrap(Throwable t) {
        while (t instanceof InvocationTargetException && t.getCause() != null) t = t.getCause();
        return t;
    }

    // --- shared ------------------------------------------------------------------------------

    private String[] levels() {
        return strongbox ? new String[]{STRONGBOX, TEE} : new String[]{TEE};
    }

    private JSONObject header(String stage) throws Exception {
        line("Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + "), "
                + Build.MANUFACTURER + " " + Build.MODEL + ", stage " + stage);
        JSONObject result = new JSONObject();
        result.put("run_id", runId);
        result.put("stage", stage);
        result.put("message", b64(MESSAGE));
        JSONObject d = new JSONObject();
        d.put("manufacturer", Build.MANUFACTURER);
        d.put("model", Build.MODEL);
        d.put("release", Build.VERSION.RELEASE);
        d.put("sdk", Build.VERSION.SDK_INT);
        d.put("security_patch", Build.VERSION.SECURITY_PATCH);
        d.put("strongbox", strongbox);
        result.put("device", d);
        return result;
    }

    private JSONObject generateRecorded(String alias, int purposes, String level, String attestKeyAlias) throws Exception {
        JSONObject k = new JSONObject();
        byte[] c = challenge();
        k.put("alias", alias);
        try {
            generate(alias, purposes, level, c, attestKeyAlias);
            k.put("challenge", b64(c));
            k.put("chain", chain(alias));
        } catch (Exception e) {
            k.put("error", describe(e));
        }
        return k;
    }

    private void generate(String alias, int purposes, String level, byte[] challenge, String attestKeyAlias) throws Exception {
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

    private byte[] sign(String alias, byte[] data) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign((PrivateKey) ks.getKey(alias, null));
        s.update(data);
        return s.sign();
    }

    private static String outcome(JSONObject k) throws Exception {
        return k.has("error") ? "FAILED " + k.getString("error") : "ok (chain length " + k.getJSONArray("chain").length() + ")";
    }

    private JSONArray chain(String alias) throws Exception {
        JSONArray a = new JSONArray();
        Certificate[] certs = ks.getCertificateChain(alias);
        if (certs != null) {
            for (Certificate c : certs) a.put(b64(c.getEncoded()));
        }
        return a;
    }

    private void write(String name, JSONObject o) throws Exception {
        File f = new File(ctx.getFilesDir(), name);
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(o.toString(2).getBytes(StandardCharsets.UTF_8));
        }
        line("");
        line("wrote " + f.getAbsolutePath());
    }

    private void line(String s) {
        summary.append(s).append('\n');
        Log.i(TAG, s);
    }

    private byte[] challenge() {
        return randomBytes(16);
    }

    private byte[] randomBytes(int n) {
        byte[] c = new byte[n];
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
