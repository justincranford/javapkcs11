package com.github.justincranford.pkcs11;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Integration test, not a unit test, because of external dependency on SoftHSM2 initialized token.
 * @author Justin Cranford
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)	// Run methods in fixed alphanumeric name order. Necesary for integration testing.
@SuppressWarnings({"static-method"})
public class ITPkcs11 {
	protected static final Logger LOG = Logger.getLogger(ITPkcs11.class.getCanonicalName());

	private static final byte[] CLEARBYTES = Pkcs11.getRandomBytes(128);
	private static final byte[] AES_IV     = Pkcs11.getRandomBytes(16); // AES-CBC requires IV length equal to AES block size (16 bytes)

	@edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="PATH_TRAVERSAL_IN", justification="Demonstration purposes only.")
	private static final String SOFTHSM2_LIBRARYPATH   = (Pkcs11.getEnv("SOFTHSM2_LIBRARYPATH",   "C:/SoftHSM2/lib/softhsm2-x64.dll")); 
	private static final String SOFTHSM2_LIBRARYNAME   = (Pkcs11.getEnv("SOFTHSM2_LIBRARYNAME",   "SoftHSM2"));
	private static final String SOFTHSM2_SLOTLISTINDEX = (Pkcs11.getEnv("SOFTHSM2_SLOTLISTINDEX", "0")); 
	private static final String SOFTHSM2_USERPIN       = (Pkcs11.getEnv("SOFTHSM2_USERPIN",       "0000")); 

	@Test public void test0001SuccessfulListKeys() throws Exception {
		final KeyStore keyStore = Pkcs11.loginSunPKCS11SoftHSM2(SOFTHSM2_LIBRARYNAME, SOFTHSM2_LIBRARYPATH, SOFTHSM2_SLOTLISTINDEX, SOFTHSM2_USERPIN.toCharArray());
		Pkcs11.listKeyStoreEntries(keyStore, SOFTHSM2_USERPIN.toCharArray());
	}

	@Test public void test0002SuccessfulAes256CbcGenerateEncryptDecrypt() throws Exception {
		final byte[] encryptedBytes = this.loginThenDeleteGenerateOrGetThenEncrypt("aes256", CLEARBYTES, false, true); // doDelete=false, doGenerate=true
		final byte[] decryptedBytes = this.loginGetDecrypt("aes256", encryptedBytes);
		Assert.assertArrayEquals(CLEARBYTES, decryptedBytes);
	}

	// ASSUMPTION: External utility requested generating a generic secret in the HSM with label "hmacSha256" before running this test.
	// SunPKCS11 lacks support for PKCS#11 mechanism GENERIC-SECRET-KEY-GEN. The generate request cannot be initiated within a Java application.
	@Test public void test0003SuccessfulHmacSha256MacVerifyNotGenerate() throws Exception {
		final byte[] macBytes    = this.loginThenDeleteGenerateOrGetThenMac("hmacSha256", CLEARBYTES, false, false); // doDelete=false, doGenerate=false
		final byte[] verifyBytes = this.loginThenDeleteGenerateOrGetThenMac("hmacSha256", CLEARBYTES, false, false); // doDelete=false, doGenerate=false
		Assert.assertArrayEquals(macBytes, verifyBytes);
	}

	// SoftHSM2:  GENERIC-SECRET-KEY-GEN (supported) and CKM_SHA256_HMAC (supported).
	// SunPKCS11: GENERIC-SECRET-KEY-GEN (missing!!)   and CKM_SHA256_HMAC (supported).
	// Oracle PKCS#11 developer guide only likes CKM_SHA256_HMAC, GENERIC-SECRET-KEY-GEN is missing.
	// https://docs.oracle.com/en/java/javase/11/security/pkcs11-reference-guide1.html#GUID-D3EF9023-7DDC-435D-9186-D2FD05674777
	@Test(expected=NoSuchAlgorithmException.class) // Message: java.security.NoSuchAlgorithmException: no such algorithm: RAW for provider SunPKCS11-SoftHSM2
	public void test0004HmacSha256GenerateFails() throws Exception {
		this.loginThenDeleteGenerateOrGetThenMac("doesnotexist", CLEARBYTES, true, true); // doDelete=true, doGenerate=true
	}

	private byte[] loginThenDeleteGenerateOrGetThenEncrypt(final String alias, final byte[] clearBytes, final boolean doDelete, final boolean doGenerate) throws Exception {
		final KeyStore keyStore = Pkcs11.loginSunPKCS11SoftHSM2(SOFTHSM2_LIBRARYNAME, SOFTHSM2_LIBRARYPATH, SOFTHSM2_SLOTLISTINDEX, SOFTHSM2_USERPIN.toCharArray());
		final SecretKey aes256SecretKey;
		if (doDelete) {
			keyStore.deleteEntry(alias); // Delete if exists
		}
		if (doGenerate) {
			aes256SecretKey = Pkcs11.generateKey(keyStore, alias, null, "AES", 256); // Generate new 256-bit
		} else {
			aes256SecretKey = Pkcs11.getKey(keyStore, alias, null); // Get existing
		}
		Assert.assertNotNull(aes256SecretKey);
		return Pkcs11.encrypt(keyStore.getProvider(), aes256SecretKey, new IvParameterSpec(AES_IV.clone()), "AES/CBC/PKCS5Padding", clearBytes);
	}
	private byte[] loginGetDecrypt(final String alias, final byte[] encryptedBytes) throws Exception {
		final KeyStore keyStore = Pkcs11.loginSunPKCS11SoftHSM2(SOFTHSM2_LIBRARYNAME, SOFTHSM2_LIBRARYPATH, SOFTHSM2_SLOTLISTINDEX, SOFTHSM2_USERPIN.toCharArray());
		final SecretKey aes256SecretKey = Pkcs11.getKey(keyStore, alias, null);
		Assert.assertNotNull(aes256SecretKey);
		return Pkcs11.decrypt(keyStore.getProvider(), aes256SecretKey, new IvParameterSpec(AES_IV.clone()), "AES/CBC/PKCS5Padding", encryptedBytes);
	}
	private byte[] loginThenDeleteGenerateOrGetThenMac(final String alias, final byte[] bytes, final boolean doDelete, final boolean doGenerate) throws Exception {
		final KeyStore keyStore = Pkcs11.loginSunPKCS11SoftHSM2(SOFTHSM2_LIBRARYNAME, SOFTHSM2_LIBRARYPATH, SOFTHSM2_SLOTLISTINDEX, SOFTHSM2_USERPIN.toCharArray());
		final SecretKey genericSecretKey;
		if (doDelete) {
			keyStore.deleteEntry(alias); // Delete if exists
		}
		if (doGenerate) {
			genericSecretKey = Pkcs11.generateKey(keyStore, alias, null, "GENERIC", 1000); // Generate new 1000-bit generic secret (Failed due to SunPKCS11 feature gap)
		} else {
			genericSecretKey = Pkcs11.getKey(keyStore, alias, null); // Get existing
		}
		Assert.assertNotNull(genericSecretKey);
		return Pkcs11.mac(keyStore.getProvider(), genericSecretKey, "HmacSHA256", bytes);
	}

	// Negative test to improve code coverage
	@Test(expected=Exception.class) public void test0010ExpectFailureNativeLibraryNotFound() throws Exception {
		Pkcs11.loginSunPKCS11SoftHSM2(SOFTHSM2_LIBRARYNAME, "does_not_exist.dll", SOFTHSM2_SLOTLISTINDEX, SOFTHSM2_USERPIN.toCharArray());
	}
}