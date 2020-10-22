package com.github.justincranford.pkcs11;

import java.io.File;
import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit test, because not external dependencies.
 * @author Justin Cranford
 */
@SuppressWarnings({"static-method"})
public class TestPkcs11 {
	protected static final Logger LOG = Logger.getLogger(TestPkcs11.class.getCanonicalName());

	@Test public void testGetRandomBytes() throws Exception {
		final byte[] randomBytes1 = Pkcs11.getRandomBytes(128);
		final byte[] randomBytes2 = Pkcs11.getRandomBytes(128);
		Assert.assertEquals(128, randomBytes1.length);
		Assert.assertEquals(128, randomBytes2.length);
		Assert.assertFalse(Arrays.equals(randomBytes1, randomBytes2));
	}

	@Test public void testAssertSoftHsm2ConfigEnvironmentVariable() throws Exception {
		final String nativeLibraryConfigFilePath = Pkcs11.verifySoftHsm2ConfigEnvironmentVariableSet(new File("SoftHSM2/lib/libsofthsm2-64.dll")); // SunPKCS11 load softhsm2-x64.dll fails without env var
		Pkcs11.verifySoftHsm2ConfigExists(nativeLibraryConfigFilePath); // SunPKCS11 load softhsm2-x64.dll fails without config file
	}

	// Negative test to improve code coverage
	@Test public void testReturnFallbackValueDueToMissingEnvVariable() throws Exception {
		String fallbackValue = "Fallback value";
		Assert.assertEquals(fallbackValue, Pkcs11.getEnv("Does not exist", fallbackValue));
	}
}