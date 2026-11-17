package org.cesecore.keys.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.pkcs11.jacknji11.C;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKC;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;

public class Ed25519 {

    private final static Logger log = Logger.getLogger(Ed25519.class);

    /**
     * jacknji11's C class returns the PKCS#11 return code instead of throwing an exception.
     * Turns any return code other than CKR_OK into a CKRException so that failures are not ignored.
     */
    private static void check(final long rv, final String operation) {
        if (rv != CKR.OK) {
            throw new CKRException(operation + " returned " + CKR.L2S(rv), rv);
        }
    }

    // Holds HSM information (sessions, shared libraries, Token names, Name of the provider is used as key)
    private static HashMap<String,HsmInformation> hsmInfoCache = new HashMap<String,HsmInformation>();

    /**
     * Generates a keypair using C jacknji11 implementation
     *
     * @param keyAlias    key alias
     * @param providerName Name of the provider
     * @return X509Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws IOException
     */
    public X509Certificate generateEd25519(final String keyAlias, String providerName) throws InvalidKeyException, CertificateException, IOException{

        HsmInformation hsmInfo = hsmInfoCache.get(providerName);

        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        generateKeyPairEd25519(hsmInfo, pubKey, privKey, keyAlias);

        return generateSelfCertificate(pubKey, privKey, keyAlias, hsmInfo);
    }


    /**
     * Generates a public-key / private-key Ed25519 pair, creates new key objects.
     *
     * @param hsmInfo    HSM info cache
     * @param publicKey  handle of new public key
     * @param privateKey handle of new private key
     * @param keyalias alias for the new key
     */
    private void generateKeyPairEd25519(HsmInformation hsmInfo, LongRef publicKey, LongRef privateKey, String keyalias) {
        LongRef sessionRef = null;
        try {
            sessionRef = hsmInfo.getSession();
            // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms
            // Specification Version 2.40 section 2.3.3 - ECDSA public key objects
            /*
                * DER-encoding of an ANSI X9.62 Parameters, also known as
                * "EC domain parameters".
                */
            // We use a Ed25519 key, the oid 1.3.101.112 has DER encoding in Hex 06032b6570
            // In Utimaco, EC_PARAMS needs to have the value "edwards25519"

            CKA[] pubTempl = new CKA[] {
                            new CKA(CKA.EC_PARAMS, "edwards25519"),
                            new CKA(CKA.WRAP, false),
                            new CKA(CKA.ENCRYPT, false),
                            new CKA(CKA.VERIFY, true),
                            new CKA(CKA.VERIFY_RECOVER, false),
                            new CKA(CKA.TOKEN, true),
                            new CKA(CKA.LABEL, (keyalias + "-public").getBytes()),
                            new CKA(CKA.ID, keyalias.getBytes()),
            };
            CKA[] privTempl = new CKA[] {
                            new CKA(CKA.TOKEN, true),
                            new CKA(CKA.PRIVATE, true),
                            new CKA(CKA.SENSITIVE, true),
                            new CKA(CKA.SIGN, true),
                            new CKA(CKA.SIGN_RECOVER, false),
                            new CKA(CKA.DECRYPT, false),
                            new CKA(CKA.UNWRAP, false),
                            new CKA(CKA.EXTRACTABLE, false),
                            new CKA(CKA.LABEL, (keyalias + "-private").getBytes()),
                            new CKA(CKA.ID, keyalias.getBytes()),
            };



            C.GenerateKeyPair(sessionRef.value(), new CKM(CKM.ECDSA_KEY_PAIR_GEN), pubTempl, privTempl, publicKey, privateKey);
            
            if (publicKey.value() == 0 || privateKey.value() == 0) {
                throw new EJBException("Key pair generation failed: " + keyalias);
            }

        } catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Failed to generate Key Pair: " + keyalias, rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.info("Generated KeyPair with alias: " + keyalias);
        }
    }

    /**
     * Generates the EJBCA self certificate so keys can be recognized.
     *
     * @param pubKey Public key of the alias
     * @param privKey Private key of the alias
     * @param keyAlias Key Alias
     * @param hsmInfo Cache info
     * @return X509Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    private static X509Certificate generateSelfCertificate(LongRef pubKey, LongRef privKey, String keyAlias, HsmInformation hsmInfo) throws InvalidKeyException, IOException, CertificateException{
        LongRef sessionRef = null;
        try {
            sessionRef = hsmInfo.getSession();


            final long currentTime = new Date().getTime();
            final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
            final Date lastDate = new Date(currentTime + (long) (30 * 24 * 60 * 60 * 365) * 1000);
            final X500Name issuer = new X500Name("CN=Dummy certificate created by a CESeCore application");
            final BigInteger serno = BigInteger.valueOf(firstDate.getTime());


            Calendar expiry = Calendar.getInstance();
            int validity = (30 * 24 * 60 * 60 * 365) * 1000;
            expiry.add(Calendar.DAY_OF_YEAR, validity);

            // Certificate structure
            V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
            certGen.setSerialNumber(new ASN1Integer(serno));

            CKA[] templ = new CKA[]{
                new CKA(CKA.VALUE),
                new CKA(CKA.EC_POINT),
                new CKA(CKA.EC_PARAMS)
            };

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);


            final CKA ecPoint = templ[0];

            certGen.setIssuer(issuer);
            certGen.setSubject(issuer);
            certGen.setStartDate(new Time(firstDate));
            certGen.setEndDate(new Time(lastDate));
            certGen.setSubjectPublicKeyInfo(
                                    new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                                    ecPoint.getValue()));

            certGen.setSignature(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));

            // generate certificate
            TBSCertificate tbsCert = certGen.generateTBSCertificate();

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
            dOut.writeObject(tbsCert);

            byte[] certBlock = bOut.toByteArray();
            byte[] signature;


            // since the algorythm is Ed25519 there's no need to create a digest.
            C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());

            LongRef length = new LongRef();
            C.Sign(sessionRef.value(), certBlock, null, length);

            byte[] result = new byte[(int) length.value()];
            C.Sign(sessionRef.value(), certBlock, result, length);

            signature = resize(result, (int) length.value());


            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(tbsCert);
            v.add(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
            v.add(new DERBitString(signature));

            DERSequence der = new DERSequence(v);
            ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());

            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                            .generateCertificate(baos);

            LongRef certRef = new LongRef();

            CKA[] certTemplate = new CKA[] {
                new CKA(CKA.CLASS, CKO.CERTIFICATE),
                new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.LABEL, keyAlias),
                new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
                new CKA(CKA.ISSUER,cert.getSubjectX500Principal().getEncoded()),
                new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
                new CKA(CKA.ID, keyAlias),
                new CKA(CKA.VALUE, cert.getEncoded())
            };


            C.CreateObject(sessionRef.value(), certTemplate, certRef);

            updateKeypairCache(keyAlias, hsmInfo);

            return cert;

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't generate self signed certificate", rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.info("Generated self signed certifiate with key: " + keyAlias);
        }

    }
    
    /**
     * Signs and verifies data using the jacknji11 HSM interface.
     * Uses the Ed25519 algorithm to sign example data with the private key
     * and verify it with the corresponding public key.
     *
     * @param alias         Key alias in the HSM
     * @param providerName  HSM provider name
     * @return true if signature verification succeeds, false otherwise
     */
    public boolean validate_alias(String alias, String providerName) {
        final byte[] data = "Example data for signature validation".getBytes(StandardCharsets.UTF_8);
        try {
            final HsmInformation hsmInfo = hsmInfoCache.get(providerName);
            if (hsmInfo == null) {
                log.warn("HSM provider not initialized, cannot validate alias: " + alias);
                return false;
            }
            // Sign through the same code path, cached key handles and mechanism as certificate and CRL signing,
            // so the health check fails whenever production signing would fail.
            final byte[] signature = sign(alias, data, providerName);
            final byte[] publicKey = getPublicKeyValue(alias, hsmInfo);
            final Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.update(data, 0, data.length);
            if (verifier.verifySignature(signature)) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature verified successfully for alias: " + alias);
                }
                return true;
            }
            log.warn("Signature made by the HSM with alias " + alias + " does not verify with its public key.");
            return false;
        } catch (RuntimeException e) {
            log.warn("HSM signature test failed for alias: " + alias + ": " + e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("HSM signature test failure details", e);
            }
            return false;
        }
    }

    /** Reads the raw 32-byte Ed25519 public key (CKA_VALUE) of an alias from the HSM. */
    private static byte[] getPublicKeyValue(final String alias, final HsmInformation hsmInfo) {
        final KeyPairInfo keyPair = hsmInfo.getKeyPair(alias);
        final LongRef pubKey = keyPair != null ? keyPair.getPubKey() : getPublicKeyRef(alias, hsmInfo);
        final byte[] value = getAttribute(pubKey, CKA.VALUE, hsmInfo, "public key value of " + alias);
        if (value.length == 32) {
            return value;
        }
        // Some libraries return the point wrapped in a DER OCTET STRING
        if (value.length == 34 && value[0] == 0x04 && value[1] == 32) {
            final byte[] raw = new byte[32];
            System.arraycopy(value, 2, raw, 0, 32);
            return raw;
        }
        throw new EJBException("Unexpected Ed25519 public key length " + value.length + " for alias: " + alias);
    }

    /** Reads one attribute of an object, checking every PKCS#11 return code. */
    private static byte[] getAttribute(final LongRef object, final long type, final HsmInformation hsmInfo, final String what) {
        LongRef sessionRef = null;
        try {
            sessionRef = hsmInfo.getSession();
            final CKA[] templ = new CKA[] { new CKA(type) };
            check(C.GetAttributeValue(sessionRef.value(), object.value(), templ), "C_GetAttributeValue(" + what + ")");
            if (templ[0].ulValueLen < 0) {
                throw new CKRException("Attribute not available: " + what, CKR.ATTRIBUTE_TYPE_INVALID);
            }
            templ[0].pValue = new byte[(int) templ[0].ulValueLen];
            check(C.GetAttributeValue(sessionRef.value(), object.value(), templ), "C_GetAttributeValue(" + what + ")");
            final byte[] value = templ[0].getValue();
            if (value == null) {
                throw new CKRException("No value returned for " + what, CKR.GENERAL_ERROR);
            }
            return value;
        } catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            sessionRef = null;
            throw new EJBException("Couldn't read " + what + ": " + CKR.L2S(rv.getCKR()), rv);
        } finally {
            if (sessionRef != null) {
                hsmInfo.releaseSession(sessionRef);
            }
        }
    }




    /**
     * Signs data with C jacknji11 hsm implementation
     *
     * @param alias Key Alias
     * @param data data to sign
     * @param providerName Name of provider
     * @return byte[] signed data
     */

    public byte[] sign(String alias, byte[] data, String providerName){
        final HsmInformation hsmInfo = hsmInfoCache.get(providerName);
        // Defensive null check - this method only works with HSM providers
        if (hsmInfo == null) {
            throw new IllegalStateException(
                "HSM provider not initialized. The sign() method only works with HSM providers (e.g., Utimaco). " +
                "Provider '" + providerName + "' is not an HSM provider or has not been initialized via updateHsmInfoCache(). " +
                "Please ensure the HSM is properly configured and initialized before calling this method."
            );
        }
        final long generation = hsmInfo.getGeneration();
        try {
            return signOnce(alias, data, hsmInfo);
        } catch (RuntimeException e) {
            // After an HSM connection loss the sessions can be left in an error state that only closing them clears
            // (e.g. Utimaco R2: B90C0008 "session must be closed", reported as CKR_DEVICE_ERROR).
            // Re-open the sessions, log in again and retry once.
            log.warn("Signing with alias " + alias + " failed (" + e.getMessage() + "). Re-opening HSM sessions and retrying.");
            hsmInfo.resetIfGeneration(generation);
            return signOnce(alias, data, hsmInfo);
        }
    }

    private byte[] signOnce(final String alias, final byte[] data, final HsmInformation hsmInfo) {
        if (!hsmInfo.KeyPairCache.containsKey(alias)) {
            updateKeypairCache(alias, hsmInfo);
        }
        final LongRef privKey = hsmInfo.KeyPairCache.get(alias).getPrivKey();
        LongRef sessionRef = null;
        try {
            sessionRef = hsmInfo.getSession();
            // since the algorithm is Ed25519 there's no need to create a digest.
            check(C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value()), "C_SignInit(" + alias + ")");
            final LongRef length = new LongRef();
            check(C.Sign(sessionRef.value(), data, null, length), "C_Sign(" + alias + ")");
            byte[] result = new byte[(int) length.value()];
            check(C.Sign(sessionRef.value(), data, result, length), "C_Sign(" + alias + ")");
            if (length.value() <= 0) {
                throw new CKRException("Empty signature returned for alias " + alias, CKR.GENERAL_ERROR);
            }
            if (length.value() < result.length) {
                result = resize(result, (int) length.value());
            }
            log.info("Signed data with: " + alias);
            return result;
        } catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            sessionRef = null;
            throw new EJBException("Couldn't sign data with alias " + alias + ": " + CKR.L2S(rv.getCKR()), rv);
        } finally {
            if (sessionRef != null) {
                hsmInfo.releaseSession(sessionRef);
            }
        }
    }

    /**
     * Removes a keypair from HSM and Cache
     *
     * @param alias Key Alias
     * @param providerName Name of provider
     */
    public static synchronized void removeKeyPair(String alias, String providerName){

        LongRef sessionRef = null;
        HsmInformation hsmInfo = null;
        try {
            hsmInfo = hsmInfoCache.get(providerName);
            sessionRef = hsmInfo.getSession();


            if(!hsmInfo.KeyPairCache.containsKey(alias)){
                updateKeypairCache(alias,hsmInfo);
            }

            LongRef privateKey = hsmInfo.KeyPairCache.get(alias).getPrivKey();
            LongRef publicKey = hsmInfo.KeyPairCache.get(alias).getPubKey();
            LongRef certificate = hsmInfo.KeyPairCache.get(alias).getCertificate();

            C.DestroyObject(sessionRef.value(), privateKey.value());
            C.DestroyObject(sessionRef.value(), publicKey.value());
            C.DestroyObject(sessionRef.value(), certificate.value());

            hsmInfo.KeyPairCache.remove(alias);

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't remove KeyPair: " + alias , rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Removed KeyPair: " + alias);
        }
    }

    /**
     * Initializes and fills Token Cache as well as update password on change
     *
     * @param providerName Name of token provider
     * @param tokenName Name of the token
     * @param slotLabel slot of the token
     * @param authCode authentication code
     * @param sharedLibrary library path
     * @return Cache instance
     */
    public static synchronized HsmInformation updateHsmInfoCache(String providerName, String tokenName, String slotLabel, String authCode, String sharedLibrary){
        if(hsmInfoCache.containsKey(providerName)){
            HsmInformation hsmInf = hsmInfoCache.get(providerName);
            // (Re)activation always discards the cached sessions and key handles, opens a new session and logs in again.
            // Re-using the cached sessions made activation fail after an HSM connection loss.
            hsmInf.reset(authCode);
            if(!hsmInf.tokenName.contains(tokenName)){
                hsmInf.addTokenName(tokenName);
            }

            return hsmInf;
        }else{

            LongRef sessionRef = new LongRef();

            C.NATIVE = new org.pkcs11.jacknji11.jna.JNA(sharedLibrary);
            C.Initialize();

            check(C.OpenSession(Long.parseLong(slotLabel), CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef), "C_OpenSession");
            final long loginRv = C.Login(sessionRef.value, CKU.USER, authCode.getBytes());
            if (loginRv != CKR.OK && loginRv != CKR.USER_ALREADY_LOGGED_IN) {
                C.CloseSession(sessionRef.value);
                check(loginRv, "C_Login");
            }

            HsmInformation inf = new HsmInformation(authCode, slotLabel, tokenName, sessionRef, sharedLibrary);
            hsmInfoCache.put(providerName, inf);
            return inf;
        }
    }

    /**
     * Changes name of token in Cache
     *
     * @param providerName Name of current provider
     * @param oldTokenName Old Name
     * @param newTokenName New Name
     */
    public static synchronized void updateCachedName(String providerName, String oldTokenName, String newTokenName) {
        HsmInformation hsmInf = hsmInfoCache.get(providerName);
        if(!hsmInf.tokenName.contains(newTokenName)){
            hsmInf.tokenName.remove(oldTokenName);
            hsmInf.tokenName.add(newTokenName);
        }
    }

    /**
     * Removes a token from Cache
     *
     * @param providerName Name of provider
     * @param tokenName Name of the token
     */
    public static synchronized void removeTokenFromCache(String providerName, String tokenName){
        HsmInformation hsmInf = hsmInfoCache.get(providerName);

        if(hsmInf != null && hsmInf.tokenName != null && hsmInf.tokenName.contains(tokenName)){
            hsmInf.tokenName.remove(tokenName);
        }
        if(hsmInf != null && hsmInf.tokenName != null && hsmInf.tokenName.isEmpty()){
            hsmInfoCache.remove(providerName);
        }

    }

    /**
     * Updates the Cache with keypairs
     *
     * @param alias Key Alias
     * @param hsmCache Cache
     */
    public static synchronized void updateKeypairCache(String alias, HsmInformation hsmCache){
        if(!hsmCache.KeyPairCache.containsKey(alias)){
            LongRef privateKey = getPrivateKeyRef(alias, hsmCache);
            LongRef publicKey = getPublicKeyRef(alias, hsmCache);
            LongRef certificate = getCertificateRef(alias, hsmCache);

            KeyPairInfo keypair = new KeyPairInfo(publicKey, privateKey, certificate);
            hsmCache.addKeyPair(alias, keypair);
            if (log.isDebugEnabled()) {
                log.debug("Adding " + alias + " to cache.");
            }
        }
    }


    /**
     * Gets the LongRef of a Private Key through it's alias.
     * @param alias alias
     * @param hsmInfo HSM cache
     * @return LongRef of Private Key
     */
    public static LongRef getPrivateKeyRef(String alias, HsmInformation hsmInfo){
        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            LongRef objectCount = new LongRef();
            long[] result = new long[1];
            CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias + "-private" )};
            check(C.FindObjectsInit(sessionRef.value(), templ), "C_FindObjectsInit");
            check(C.FindObjects(sessionRef.value(), result, objectCount), "C_FindObjects");
            check(C.FindObjectsFinal(sessionRef.value()), "C_FindObjectsFinal");

            if (result[0] == 0) {
                throw new EJBException("Private key error for alias: " + alias);
            }

            LongRef privKey = new LongRef(result[0]);

            return privKey;
        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get private key: " + alias , rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got private key: " + alias);
        }
    }

    /**
     * Gets the LongRef of a Certificate through it's alias.
     * @param alias alias
     * @param hsmInfo HSM cache
     * @return LongRef of Certificate
     */
    public static LongRef getCertificateRef(String alias, HsmInformation hsmInfo){
        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            LongRef objectCount = new LongRef();
            long[] result = new long[1];
            CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias)};
            check(C.FindObjectsInit(sessionRef.value(), templ), "C_FindObjectsInit");
            check(C.FindObjects(sessionRef.value(), result, objectCount), "C_FindObjects");
            check(C.FindObjectsFinal(sessionRef.value()), "C_FindObjectsFinal");

            LongRef certificate = new LongRef(result[0]);

            return certificate;
        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get certificate: " + alias , rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got certificate: " + alias);
        }
    }

     /**
     * Gets the Id through public key LongRef.
     * @param LongRef pubKey
     * @param hsmInfo HSM cache
     * @return String id
     */
    public static String getID(LongRef pubKey, HsmInformation hsmInfo){
        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            CKA[] templ = new CKA[]{
                new CKA(CKA.ID),
            };

            check(C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ), "C_GetAttributeValue");
            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }
            check(C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ), "C_GetAttributeValue");
            final CKA id = templ[0];
            if (id.getValue() == null) {
                throw new CKRException("No value returned for key " + pubKey.value(), CKR.GENERAL_ERROR);
            }

            return id.getValueStr();

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get Id: ", rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got Id: " + pubKey.value());
        }
    }

    /**
     * Gets the LongRef of a Public Key through it's alias.
     * @param alias alias
     * @param hsmInfo HSM cache
     * @return LongRef of Public Key
     */
    public static LongRef getPublicKeyRef(String alias, HsmInformation hsmInfo){
        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            LongRef objectCount = new LongRef();
            long[] result = new long[1];
            CKA[] templ = new CKA[] {new CKA(CKA.LABEL, alias + "-public")};
            check(C.FindObjectsInit(sessionRef.value(), templ), "C_FindObjectsInit");
            check(C.FindObjects(sessionRef.value(), result, objectCount), "C_FindObjects");
            check(C.FindObjectsFinal(sessionRef.value()), "C_FindObjectsFinal");

            if (result[0] == 0) {
                throw new EJBException("Public key error for alias: " + alias);
            }

            LongRef pubKey = new LongRef(result[0]);

            return pubKey;

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get public key: " + alias, rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got public key: " + alias);
        }
    }

     /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param hsmInfo HSM cache
     * @return Algorithm
     */
    public static String getAlgo(LongRef pubKey, HsmInformation hsmInfo){
        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            CKA[] templ = new CKA[]{
                new CKA(CKA.KEY_TYPE),
            };

            check(C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ), "C_GetAttributeValue");
            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }
            check(C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ), "C_GetAttributeValue");

            final CKA algo = templ[0];
            if (algo.getValue() == null) {
                throw new CKRException("No value returned for key " + pubKey.value(), CKR.GENERAL_ERROR);
            }

            return CKK.L2S(algo.getValueLong());

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get algorithm for key: " + pubKey.value(), rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got algorithm for key: " + pubKey.value());
        }
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param hsmInfo HSM cache
     * @return ECDSA Parameters
     */
    public static String getECDSAparams(LongRef pubKey, HsmInformation hsmInfo){
        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            CKA[] templ = new CKA[]{
                new CKA(CKA.EC_PARAMS),
            };

            check(C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ), "C_GetAttributeValue");
            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }
            //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
            check(C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ), "C_GetAttributeValue");

            final CKA params = templ[0];
            if (params.getValue() == null) {
                throw new CKRException("No value returned for key " + pubKey.value(), CKR.GENERAL_ERROR);
            }

            return params.getValueStr();
        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get ECDSA params for key: " + pubKey.value(), rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got ECDSA params for key: " + pubKey.value());
        }
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param hsmInfo HSM cache
     * @return RSA Modulus
     */
    public static BigInteger getRsaModulus(LongRef pubKey, HsmInformation hsmInfo){
        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            CKA[] templ = new CKA[]{
                new CKA(CKA.MODULUS),
            };

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);

            final CKA mod = templ[0];

            return mod.getValueBigInt();
        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get RSA modulus for key: " + pubKey.value(), rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got RSA modulus for key: " + pubKey.value());
        }
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param hsmInfo HSM cache
     * @return RSA public exponent
     */
    public static BigInteger getRsaPublicExponent(LongRef pubKey, HsmInformation hsmInfo){

        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            CKA[] templ = new CKA[]{
                new CKA(CKA.PUBLIC_EXPONENT),
            };

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);

            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);

            final CKA exp = templ[0];

            return exp.getValueBigInt();

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get RSA public exponent for key: " + pubKey.value(), rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got RSA public exponent for key: " + pubKey.value());
        }
    }

    /**
     * Gets the key algorithm through public key LongRef.
     * @param LongRef pubKey
     * @param hsmInfo HSM cache
     * @return RSA Modulus Bits
     */
    public static Long getRsaModulusBits(LongRef pubKey, HsmInformation hsmInfo){

        LongRef sessionRef = null;

        try{
            sessionRef = hsmInfo.getSession();

            CKA[] templ = new CKA[]{
                new CKA(CKA.MODULUS_BITS),
            };

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);

            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);

            final CKA bits = templ[0];

            return bits.getValueLong();

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't get RSA modulus bits for key: " + pubKey.value(), rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Got RSA modulus bits for key: " + pubKey.value());
        }
    }


    /**
     * Resize buf to specified length. If buf already size 'newSize', then return buf, else return resized buf.
     * @param buf buf
     * @param newSize length to resize to
     * @return if buf already size 'newSize', then return buf, else return resized buf
     */
    private static byte[] resize(byte[] buf, int newSize) {
        if (buf == null || newSize >= buf.length) {
            return buf;
        }
        byte[] result = new byte[newSize];
        System.arraycopy(buf, 0, result, 0, result.length);
        return result;
    }

    static public class HsmInformation{
        private String authcode;
        private String slot;
        private List<String> tokenName;
        private final LinkedList<LongRef> idleSessions = new LinkedList<>();
        private final LinkedList<LongRef> activeSessions = new LinkedList<>();
        private String sharedLibrary;
        private HashMap<String,KeyPairInfo> KeyPairCache;
        private volatile long generation = 0;
        private final java.util.Set<LongRef> retiredSessions = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());


        public HsmInformation (String authcode, String slot, String tokenName, LongRef sessionRef, String sharedLibrary){
            this.authcode = authcode;
            this.slot = slot;
            this.tokenName = new ArrayList<String>();
            this.tokenName.add(tokenName);
            this.idleSessions.push(sessionRef);
            this.sharedLibrary = sharedLibrary;
            this.KeyPairCache = new HashMap<String,KeyPairInfo>();

        }

        public synchronized void releaseSession(LongRef sessionRef){
            if (sessionRef == null) {
                return;
            }
            // Only sessions that are still in use go back to the pool. Sessions that were closed or discarded
            // (after an error or a reset) must never be handed out again.
            if (activeSessions.remove(sessionRef)) {
                idleSessions.push(sessionRef);
            } else if (retiredSessions.remove(sessionRef)) {
                // Discarded by reset() while this thread was still using it; now it is safe to close it
                closeQuietly(java.util.Collections.singletonList(sessionRef));
            } else if (log.isDebugEnabled()) {
                log.debug("Not returning closed or discarded session to the pool: " + sessionRef.value());
            }
        }

        public synchronized LongRef getSession(){
            LongRef sessionRef;
            if(idleSessions.size() == 0){
                try{
                    sessionRef = openSession();
                    if(log.isDebugEnabled()){
                        log.debug("iddleSessions is empty, adding new session: " + sessionRef.value());
                    }
                }catch (CKRException rv){
                    throw new EJBException(rv);
                }
            }else{
                sessionRef = idleSessions.pop();
                if(log.isDebugEnabled()){
                    log.debug("Removing session from idle: " + sessionRef.value());
                }
            }
            activeSessions.push(sessionRef);
            return sessionRef;
        }

        private LongRef openSession() {
            final LongRef sessionRef = new LongRef();
            check(C.OpenSession(Long.parseLong(this.slot), CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null, sessionRef), "C_OpenSession");
            return sessionRef;
        }

        public long getGeneration() {
            return generation;
        }

        /** Resets the sessions unless another thread already did so since {@code expectedGeneration} was read. */
        public synchronized void resetIfGeneration(final long expectedGeneration) {
            if (generation == expectedGeneration) {
                reset(null);
            } else if (log.isDebugEnabled()) {
                log.debug("HSM sessions for slot " + slot + " were already re-opened by another thread.");
            }
        }

        /**
         * Discards all sessions and cached key handles, opens a new session and logs in again.
         * This is what deactivating and re-activating the crypto token used to achieve manually.
         */
        public synchronized void reset(final String newAuthcode) {
            generation++;
            if (newAuthcode != null) {
                this.authcode = newAuthcode;
            }
            // Idle sessions are closed below. Sessions still in use by other threads must NOT be closed now:
            // closing a session while another thread is inside a PKCS#11 call on it crashes the Utimaco R2
            // library (SIGSEGV). They are closed when their thread releases them.
            final List<LongRef> oldSessions = new ArrayList<>(idleSessions);
            final int inUse = activeSessions.size();
            retiredSessions.addAll(activeSessions);
            idleSessions.clear();
            activeSessions.clear();
            KeyPairCache.clear();
            // Open and log in a new session before closing the old ones, so the token is never left without a session
            final LongRef sessionRef;
            try {
                sessionRef = openSession();
            } catch (CKRException rv) {
                closeQuietly(oldSessions);
                throw new EJBException("Couldn't open a new HSM session for slot " + slot + ": " + CKR.L2S(rv.getCKR()), rv);
            }
            final long rv = C.Login(sessionRef.value(), CKU.USER, authcode.getBytes());
            if (rv != CKR.OK && rv != CKR.USER_ALREADY_LOGGED_IN) {
                closeQuietly(oldSessions);
                closeQuietly(java.util.Collections.singletonList(sessionRef));
                throw new EJBException("Couldn't log in to the HSM slot " + slot + ": " + CKR.L2S(rv), new CKRException(rv));
            }
            idleSessions.push(sessionRef);
            closeQuietly(oldSessions);
            log.info("Re-opened HSM sessions for slot " + slot + " (" + oldSessions.size() + " idle session(s) closed, "
                    + inUse + " in-use session(s) will be closed when released).");
        }

        private static void closeQuietly(final List<LongRef> sessions) {
            for (final LongRef session : sessions) {
                final long rv = C.CloseSession(session.value());
                if (rv != CKR.OK && log.isDebugEnabled()) {
                    log.debug("Ignoring " + CKR.L2S(rv) + " while closing HSM session " + session.value());
                }
            }
        }

        // Closing the last session causes the user to be logged out. A new iddle session will be created in this case to prevent logout.
        public synchronized void CloseSession(LongRef sessionRef){
            if (sessionRef == null) {
                return;
            }
            activeSessions.remove(sessionRef);
            idleSessions.remove(sessionRef);
            retiredSessions.remove(sessionRef);
            // Closing the last session logs the user out, so keep one session open
            if (idleSessions.isEmpty() && activeSessions.isEmpty()) {
                try {
                    idleSessions.push(openSession());
                } catch (CKRException rv) {
                    log.warn("Couldn't open a replacement HSM session for slot " + slot + ": " + CKR.L2S(rv.getCKR()));
                }
            }
            final long rv = C.CloseSession(sessionRef.value());
            if(log.isDebugEnabled()){
                log.debug("Closed Session: " + sessionRef.value() + (rv == CKR.OK ? "" : " (" + CKR.L2S(rv) + ")"));
            }
        }

        public void setAuthCode(String authcode) {
            this.authcode = authcode;
        }

        public String getAuthCode(){
            return this.authcode;
        }

        public List<String> getTokenNames(){
            return this.tokenName;
        }

        public void addTokenName(String tokenName){
            this.tokenName.add(tokenName);
        }

        public String getSlot(){
            return this.slot;
        }


        public String getSharedLibrary(){
            return this.sharedLibrary;
        }

        public void addKeyPair(String alias, KeyPairInfo keypair){
            KeyPairCache.put(alias, keypair);
        }

        public KeyPairInfo getKeyPair(String alias){
            return KeyPairCache.get(alias);
        }
    }

    static public class KeyPairInfo{
        private LongRef pubKey;
        private LongRef privKey;
        private LongRef certificate;

        public KeyPairInfo(LongRef pubkey, LongRef privKey, LongRef certificate){
            this.pubKey = pubkey;
            this.privKey = privKey;
            this.certificate = certificate;
        }

        public LongRef getPubKey(){
            return this.pubKey;
        }

        public LongRef getPrivKey(){
            return this.privKey;
        }

        public LongRef getCertificate(){
            return this.certificate;
        }

        public void setPubKey(LongRef pubKey){
            this.pubKey = pubKey;
        }

        public void setPrivKey(LongRef privKey){
            this.pubKey = privKey;
        }

        public void setCertificate(LongRef certificate){
            this.pubKey = certificate;
        }

    }

    /**
     * Fixes keys without certificate so they can be seen by EJBCA. The keys need to follow the format alias-private and alias-public for it to work.
     * @param providerName Name of the provider
     * @return
     */
    public static void noCertFix(String providerName){

        HsmInformation hsmInfo = null;
        LongRef sessionRef = null;

        try{
            hsmInfo = hsmInfoCache.get(providerName);
            sessionRef = hsmInfo.getSession();

            List<String> aliasList = new ArrayList<String>();

            LongRef objectCount = new LongRef();
            long[] found = new long[1024];

            CKA[] templ = new CKA[] {new CKA(CKA.CLASS, CKO.PUBLIC_KEY)};

            check(C.FindObjectsInit(sessionRef.value(), templ), "C_FindObjectsInit");
            check(C.FindObjects(sessionRef.value(), found, objectCount), "C_FindObjects");

            long count = objectCount.value();

            long[] result = new long[(int) count];
            System.arraycopy(found, 0, result, 0, result.length);

            check(C.FindObjectsFinal(sessionRef.value()), "C_FindObjectsFinal");

            for(long ref : result){
                LongRef tempRef = new LongRef(ref);

                CKA[] templ2 = new CKA[]{
                    new CKA(CKA.LABEL),
                };

                check(C.GetAttributeValue(sessionRef.value(), tempRef.value(), templ2), "C_GetAttributeValue(label)");

                // allocate memory and call again
                for (int i = 0; i < templ2.length; i++){
                    templ2[i].pValue = new byte[(int) templ2[i].ulValueLen];
                }

                check(C.GetAttributeValue(sessionRef.value(), tempRef.value(), templ2), "C_GetAttributeValue(label)");

                final CKA label = templ2[0];

                if (label.getValue() == null) {
                    throw new CKRException("No label returned for object " + ref, CKR.GENERAL_ERROR);
                }
                String s = label.getValueStr();
                String alias = s.substring(0, s.length() - 7);

                aliasList.add(alias);
            }

            for(String alias : aliasList){
                LongRef privateKey = getPrivateKeyRef(alias, hsmInfo);
                LongRef publicKey = getPublicKeyRef(alias, hsmInfo);
                String algo = getAlgo(publicKey, hsmInfo);
                LongRef certificate = getCertificateRef(alias, hsmInfo);

                if(algo.equals("EC")){

                    String ecParams = getECDSAparams(publicKey, hsmInfo);

                    if(ecParams.equals("edwards25519") && certificate.value == (long) 0 ){
                        String id = getID(publicKey, hsmInfo);

                        try {
                            generateSelfCertificateFix(publicKey, privateKey, alias, hsmInfo , id);
                        } catch (InvalidKeyException | CertificateException | IOException e) {
                            e.printStackTrace();
                        }
                    }

                }else if(algo.equals("RSA") && certificate.value == (long) 0 ){

                    String id = getID(publicKey, hsmInfo);

                    try {
                        generateSelfCertificateFixRsa(publicKey, privateKey, alias, hsmInfo , id);
                    } catch (InvalidKeyException | CertificateException | IOException e) {
                        e.printStackTrace();
                    }

                }
            }
        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't fix certificates", rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Fixed Certificates");
        }
    }

    /**
     * Copy of generateSelfCertificate above but used only for fixing certificates so it can have same IDs
     * @param pubKey Public key of the alias
     * @param privKey Private key of the alias
     * @param keyAlias Key Alias
     * @param hsmInfo Cache info
     * @param id public key ID
     * @return The X509 Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    private static X509Certificate generateSelfCertificateFix(LongRef pubKey, LongRef privKey, String keyAlias, HsmInformation hsmInfo, String id) throws InvalidKeyException, IOException, CertificateException{
        LongRef sessionRef = null;
        try {
            sessionRef = hsmInfo.getSession();

            final long currentTime = new Date().getTime();
            final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
            final Date lastDate = new Date(currentTime + (long) (30 * 24 * 60 * 60 * 365) * 1000);
            final X500Name issuer = new X500Name("CN=Dummy certificate created by a CESeCore application");
            final BigInteger serno = BigInteger.valueOf(firstDate.getTime());


            Calendar expiry = Calendar.getInstance();
                    int validity = (30 * 24 * 60 * 60 * 365) * 1000;
                    expiry.add(Calendar.DAY_OF_YEAR, validity);

            // Certificate structure
            V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
            certGen.setSerialNumber(new ASN1Integer(serno));

            CKA[] templ = new CKA[]{
                new CKA(CKA.VALUE),
                new CKA(CKA.EC_POINT),
                new CKA(CKA.EC_PARAMS)
            };

            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
            // allocate memory and call again
            for (int i = 0; i < templ.length; i++){
                templ[i].pValue = new byte[(int) templ[i].ulValueLen];
            }
            //templ[0].pValue = new byte[(int) templ[0].ulValueLen];
            C.GetAttributeValue(sessionRef.value(), pubKey.value(), templ);
            final CKA ecPoint = templ[0];

            certGen.setIssuer(issuer);
            certGen.setSubject(issuer);
            certGen.setStartDate(new Time(firstDate));
            certGen.setEndDate(new Time(lastDate));
            certGen.setSubjectPublicKeyInfo(
                                    new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                                    ecPoint.getValue()));

            certGen.setSignature(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));

            // generate certificate
            TBSCertificate tbsCert = certGen.generateTBSCertificate();

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
            dOut.writeObject(tbsCert);

            byte[] certBlock = bOut.toByteArray();

            // since the algorythm is Ed25519 there's no need to create a digest.
            C.SignInit(sessionRef.value(), new CKM(CKM.ECDSA), privKey.value());

            LongRef length = new LongRef();
            C.Sign(sessionRef.value(), certBlock, null, length);
            byte[] result = new byte[(int) length.value()];
            C.Sign(sessionRef.value(), certBlock, result, length);
            byte[] signature = resize(result, (int) length.value());

            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(tbsCert);
            v.add(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519));
            v.add(new DERBitString(signature));

            DERSequence der = new DERSequence(v);
            ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());

            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                            .generateCertificate(baos);

            LongRef certRef = new LongRef();

            CKA[] certTemplate = new CKA[] {
                new CKA(CKA.CLASS, CKO.CERTIFICATE),
                new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.LABEL, keyAlias),
                new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
                new CKA(CKA.ISSUER,cert.getSubjectX500Principal().getEncoded()),
                new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
                new CKA(CKA.ID, id),
                new CKA(CKA.VALUE, cert.getEncoded())
            };

            C.CreateObject(sessionRef.value(), certTemplate, certRef);

            updateKeypairCache(keyAlias, hsmInfo);

            return cert;

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't generate self signed certificate", rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Generated self signed certifiate with key: " + keyAlias);
        }
    }

        /**
     * Copy of generateSelfCertificate above but used only for fixing certificates so it can have same IDs. RSA version
     * @param pubKey Public key of the alias
     * @param privKey Private key of the alias
     * @param keyAlias Key Alias
     * @param hsmInfo Cache info
     * @param id public key ID
     * @return The X509 Certificate
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    private static X509Certificate generateSelfCertificateFixRsa(LongRef pubKey, LongRef privKey, String keyAlias, HsmInformation hsmInfo, String id) throws InvalidKeyException, IOException, CertificateException{
        LongRef sessionRef = null;
        try {
            sessionRef = hsmInfo.getSession();

            final long currentTime = new Date().getTime();
            final Date firstDate = new Date(currentTime - 24 * 60 * 60 * 1000);
            final Date lastDate = new Date(currentTime + (long) (30 * 24 * 60 * 60 * 365) * 1000);
            final X500Name issuer = new X500Name("CN=Dummy certificate created by a CESeCore application");
            final BigInteger serno = BigInteger.valueOf(firstDate.getTime());


            Calendar expiry = Calendar.getInstance();
                    int validity = (30 * 24 * 60 * 60 * 365) * 1000;
                    expiry.add(Calendar.DAY_OF_YEAR, validity);

            // Certificate structure
            V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();
            certGen.setSerialNumber(new ASN1Integer(serno));

            byte[] modulus = getRsaModulus(pubKey, hsmInfo).toByteArray();
            byte[] publicExponent =  getRsaPublicExponent(pubKey, hsmInfo).toByteArray();

            final BigInteger n = new BigInteger(1, modulus);
            final BigInteger e = new BigInteger(1, publicExponent);

            RSAPublicKey pk = new RSAPublicKey(n, e);


            certGen.setIssuer(issuer);
            certGen.setSubject(issuer);
            certGen.setStartDate(new Time(firstDate));
            certGen.setEndDate(new Time(lastDate));
            certGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), pk));

            certGen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));

            // generate certificate
            TBSCertificate tbsCert = certGen.generateTBSCertificate();

            //Sign certificate
            SHA1Digest digester = new SHA1Digest();
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ASN1OutputStream dOut = ASN1OutputStream.create(bOut);
            dOut.writeObject(tbsCert);
            byte[] certBlock = bOut.toByteArray();

            // first create digest
            digester.update(certBlock, 0, certBlock.length);
            byte[] hash = new byte[digester.getDigestSize()];
            digester.doFinal(hash, 0);

            DigestInfo dInfo = new DigestInfo( new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, null), hash);
            byte[] digest = dInfo.getEncoded();

            C.SignInit(sessionRef.value(), new CKM(CKM.SHA1_RSA_PKCS), privKey.value());

            LongRef length = new LongRef();
            C.Sign(sessionRef.value(), digest, null, length);
            byte[] result = new byte[(int) length.value()];
            C.Sign(sessionRef.value(), digest, result, length);
            byte[] signature = resize(result, (int) length.value());

            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(tbsCert);
            v.add(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE));
            v.add(new DERBitString(signature));

            DERSequence der = new DERSequence(v);
            ByteArrayInputStream baos = new ByteArrayInputStream(der.getEncoded());

            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                            .generateCertificate(baos);

            LongRef certRef = new LongRef();

            CKA[] certTemplate = new CKA[] {
                new CKA(CKA.CLASS, CKO.CERTIFICATE),
                new CKA(CKA.CERTIFICATE_TYPE, CKC.CKC_X_509),
                new CKA(CKA.TOKEN, true),
                new CKA(CKA.LABEL, keyAlias),
                new CKA(CKA.SUBJECT, cert.getSubjectX500Principal().getEncoded()),
                new CKA(CKA.ISSUER,cert.getSubjectX500Principal().getEncoded()),
                new CKA(CKA.SERIAL_NUMBER, cert.getSerialNumber().toByteArray()),
                new CKA(CKA.ID, id),
                new CKA(CKA.VALUE, cert.getEncoded())
            };
            C.CreateObject(sessionRef.value(), certTemplate, certRef);

            updateKeypairCache(keyAlias, hsmInfo);

            return cert;

        }catch (CKRException rv) {
            hsmInfo.CloseSession(sessionRef);
            throw new EJBException("Couldn't generate self signed certificate", rv);
        }finally{
            if(sessionRef != null){
                hsmInfo.releaseSession(sessionRef);
            }
            log.debug("Generated self signed certifiate with key: " + keyAlias);
        }
    }
}
