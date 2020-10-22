package com.github.justincranford.pkcs11;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * Debug options:
 *  Provider only: -Djava.security.debug=sunpkcs11
 *  Keystore only: -Djava.security.debug=pkcs11keystore
 *  All:           -Djava.security.debug=all
 */
public class Pkcs11 {
	private static final Logger       LOG           = Logger.getLogger(Pkcs11.class.getCanonicalName());
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private Pkcs11() { /* prevent instantiation */ 	}

	// Validate SoftHSM library, config file, and environment variable.
	// Generate SunPKCS11 config file using these parameters.
	// Create SunPKCS11 provider (driver+slotlistindex), and login via KeyStore API (provider+hsmUserPin).
	// Keystore wraps a copy of Provider object, so we only need to return the keystore object.
	// See readme for examples of the config files.
	@SuppressWarnings("restriction")
	public static KeyStore loginSunPKCS11SoftHSM2(final String nativeLibraryName, final String nativeLibraryFilePath, final String slotListIndex, final char[] keyStorePassword) throws Exception {
		final File   nativeLibraryFile           = Pkcs11.verifySoftHsm2NativeLibraryExists(nativeLibraryFilePath);
		final String nativeLibraryConfigFilePath = Pkcs11.verifySoftHsm2ConfigEnvironmentVariableSet(nativeLibraryFile); // SunPKCS11 load softhsm2-x64.dll fails without env var
		Pkcs11.verifySoftHsm2ConfigExists(nativeLibraryConfigFilePath); // SunPKCS11 load softhsm2-x64.dll fails without config file
		final File providerConfigFile = Pkcs11.createSunPkcs11ConfigFileForSoftHsm2(nativeLibraryName, nativeLibraryFilePath, slotListIndex); // Non-sensitive. Java temp files cleaned at JVM exit

		@edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value="IICU_INCORRECT_INTERNAL_CLASS_USE", justification="This is how Java 8 did it. Later Java versions have a SunPKCS11 service API.")
		final Provider providerSunPKCS11SoftHSM2 = new sun.security.pkcs11.SunPKCS11(providerConfigFile.getCanonicalPath()); // NOSONAR
		LOG.log(Level.INFO, "provider:\n" + providerSunPKCS11SoftHSM2);

		final KeyStore keyStoreSunPKCS11SoftHSM = KeyStore.getInstance("PKCS11", providerSunPKCS11SoftHSM2);
		keyStoreSunPKCS11SoftHSM.load(null, keyStorePassword);  // login to configured slot
		LOG.log(Level.INFO, "keystore:\n" + keyStoreSunPKCS11SoftHSM);

		return keyStoreSunPKCS11SoftHSM; // keystore.getProvider() holds a copy of the provider, so only need to return the keystore
	}

	public static File verifySoftHsm2NativeLibraryExists(final String nativeLibraryFilePath) throws Exception {
		// Confirm SoftHSM2 native library exists.
		final File nativeLibraryFile = new File(nativeLibraryFilePath);
		if (nativeLibraryFile.isFile()) {
			LOG.log(Level.INFO, "File '" + nativeLibraryFile.getPath() + "' found and readable.");
		} else {
			LOG.log(Level.SEVERE, "File '" + nativeLibraryFile.getPath() + "' not found or not readable.");
			throw new Exception("File '" + nativeLibraryFile + "' not available.");	// EX: C:\SoftHSM2\lib\softhsm2-x64.dll
		}
		return nativeLibraryFile;
	}

	public static String verifySoftHsm2ConfigEnvironmentVariableSet(final File nativeLibraryFile) throws Exception {
		final String nativeLibraryConfigFilePath = Pkcs11.getEnv("SOFTHSM2_CONF", null);
		if (null == nativeLibraryConfigFilePath) {
			LOG.log(Level.WARNING, "ENV{'SOFTHSM2_CONF'} is null. Computing a guess via relative path of library file '" + nativeLibraryFile.getPath() + "'.");
			final File nativeLibraryHomeDirectory = nativeLibraryFile.getParentFile().getParentFile();
			final File nativeLibraryConfigFile2   = new File(nativeLibraryHomeDirectory, "etc/softhsm2.conf");
			throw new Exception("ENV{'SOFTHSM2_CONF'} is null. Set to " + nativeLibraryConfigFile2.getPath());
		}
		return nativeLibraryConfigFilePath;
	}

	public static void verifySoftHsm2ConfigExists(final String nativeLibraryConfigFilePath) throws Exception, IOException {
		// Confirm SoftHSM2 config file exists.
		final File nativeLibraryConfigFile = new File(nativeLibraryConfigFilePath);
		if (nativeLibraryConfigFile.isFile()) {
			LOG.log(Level.INFO, "File '" + nativeLibraryConfigFile.getPath() + "' found and readable.");
		} else {
			LOG.log(Level.SEVERE, "File '" + nativeLibraryConfigFile.getPath() + "' not found or not readable.");
			throw new Exception("File '" + nativeLibraryConfigFilePath + "' not available.");	// EX: C:\SoftHSM2\etc\softhsm2.conf
		}
		LOG.log(Level.INFO, "Native Library Config: " + nativeLibraryConfigFile.getPath() + "\n" + Pkcs11.readTextFile(nativeLibraryConfigFile));
	}

	public static File createSunPkcs11ConfigFileForSoftHsm2(final String nativeLibraryName, final String nativeLibraryFilePath, final String slotListIndex) throws IOException {
		// Create SunPKCS11 config file
		final File providerConfigFile = File.createTempFile("softhsm2-", ".cfg"); // C:\Users\cranfoj\AppData\Local\Temp\softhsm2-3360678726848364409.cfg
		Pkcs11.writeTextFile(providerConfigFile,
			new StringBuilder()
			.append("name=").append(nativeLibraryName).append('\n')
			.append("library=").append(nativeLibraryFilePath).append('\n')
			.append("slotListIndex=").append(slotListIndex).append('\n')
			.toString()
		);
		LOG.log(Level.INFO, "Provider Config: " + providerConfigFile.getPath() + "\n" + Pkcs11.readTextFile(providerConfigFile));
		return providerConfigFile;
	}

	public static void listKeyStoreEntries(final KeyStore keyStore, final char[] entryPassword) throws Exception {
		final Enumeration<String> aliases = keyStore.aliases();
		while (aliases.hasMoreElements()) {
			final String alias = aliases.nextElement();
			final Key    key   = keyStore.getKey(alias, entryPassword); // PrivateKeyEntry (RSA/EC) or SecretKey (AES/Generic)
			LOG.log(Level.INFO, "Alias: " + alias + ", entry: " + key);
		}
	}

	public static SecretKey getKey(final KeyStore keyStore, final String alias, final char[] entryPassword) throws Exception {
		return (SecretKey) keyStore.getKey(alias, entryPassword);
	}

	public static SecretKey generateKey(final KeyStore keyStore, final String alias, final char[] entryPassword, final String algorithm, final int keySizeBits) throws Exception {
		final Provider     providerObj  = keyStore.getProvider(); // ASSUME: authenticated KeyStore contains our SunPKCS11-SoftHSM2 provider instance 
		final KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, providerObj); // generate ephemeral key inside the HSM
		keyGenerator.init(keySizeBits);
		final SecretKey key = keyGenerator.generateKey();
		keyStore.setKeyEntry(alias, key, entryPassword, null); // persist the key, chain=null
		return key;
	}

	public static byte[] encrypt(final Provider providerObj, final SecretKey key, final AlgorithmParameterSpec algorithmParametersSpec, final String transformation, final byte[] clearBytes) throws Exception {
		final Cipher cipher = Cipher.getInstance(transformation, providerObj);
		cipher.init(Cipher.ENCRYPT_MODE, key, algorithmParametersSpec);
		return cipher.doFinal(clearBytes);
	}

	public static byte[] decrypt(final Provider providerObj, final SecretKey key, final AlgorithmParameterSpec algorithmParametersSpec, final String transformation, final byte[] clearBytes) throws Exception {
		final Cipher cipher = Cipher.getInstance(transformation, providerObj);
		cipher.init(Cipher.DECRYPT_MODE, key, algorithmParametersSpec);
		return cipher.doFinal(clearBytes);
	}

	public static byte[] mac(final Provider providerObj, final SecretKey secretKey, final String algorithm, final byte[] clearBytes) throws Exception {
		final Mac mac = Mac.getInstance(algorithm, providerObj); // Example: HmacSHA256
		mac.init(secretKey); // generic secret key (any length >1)
		return mac.doFinal(clearBytes);
	}

	public static String readTextFile(final File file) throws IOException {
		return new String(Pkcs11.readBinaryFile(file), StandardCharsets.UTF_8);
	}
	public static byte[] readBinaryFile(final File file) throws IOException {
		try (final BufferedInputStream bis = new BufferedInputStream(java.nio.file.Files.newInputStream(file.toPath()))) {
			try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				int byteRead;
				while (-1 != (byteRead = bis.read())) {
					baos.write((byte)byteRead);
				}
				return baos.toByteArray();
			}
		}
	}

	public static void writeTextFile(final File file, final String text) throws IOException {
		Pkcs11.writeBinaryFile(file, text.getBytes(StandardCharsets.UTF_8));
	}
	public static void writeBinaryFile(final File file, final byte[] bytes) throws IOException {
		try (final BufferedOutputStream bos = new BufferedOutputStream(java.nio.file.Files.newOutputStream(file.toPath()))) {
			bos.write(bytes);
		}
	}

	public static byte[] getRandomBytes(final int length) {
		final byte[] randomBytes = new byte[length];
		SECURE_RANDOM.nextBytes(randomBytes);
		return randomBytes;
	}

	public static String getEnv(final String name, final String defaultValue) {
		final String value = System.getenv(name);
		if (null == value) {
			return defaultValue;
		}
		return value;
	}
}