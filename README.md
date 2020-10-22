# Demonstrate SunPKCS11 on Windows with SoftHSM2 for AES and HMAC.

Requirements:
- Windows 10
- JDK 8u265+: https://adoptopenjdk.net/releases.html?variant=openjdk8&jvmVariant=hotspot
- Maven 3.6.3+: https://maven.apache.org/download.cgi
- SoftHSM v2.5.0+: https://github.com/disig/SoftHSM2-for-Windows/releases
- OpenSC v0.21+: https://github.com/OpenSC/OpenSC/releases

References:
- https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html#ALG

Initialize SoftHSM2 token in slot index 0:
- "C:\SoftHSM2\bin\softhsm2-util.exe" --delete-token --token Token-0 --so-pin 0000
- "C:\SoftHSM2\bin\softhsm2-util.exe" --init-token --slot 0 --label Token-0 --pin 0000 --so-pin 0000
- "C:\SoftHSM2\bin\softhsm2-util.exe" --show-slots

Verify SoftHSM2 is working via OpenSC utility pkcs11-tool
- "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" --module C:\SoftHSM2\lib\softhsm2-x64.dll  --show-info --list-slots --list-token-slots --list-mechanisms --test

Generate SoftHSM2 generic secret via request from OpenSC utility pkcs11-tool
- "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe" --module C:\SoftHSM2\lib\softhsm2-x64.dll --slot-index 0 --pin 0000 --login --label hmacSha256 --keygen --key-type generic:125 --mechanism GENERIC-SECRET-KEY-GEN

Run SunPKCS11 integration test
- export JAVA_HOME=C:\JDK8
- mvn clean verify

Debug options for SunPKCS11 (Java debug logs only)
- Provider only: -Djava.security.debug=sunpkcs11
- Keystore only: -Djava.security.debug=pkcs11keystore
- All: -Djava.security.debug=all

Debug options for SoftHSM2 (Native library debug logs only)
- Edit log.level in the config file.
- Logs can be viewed in Windows event viewer.

# Example SoftHSM2 environment variable (mandatory for SunPKCS11 to load libsofthsm2-x64.dll)
SOFTHSM2_CONF = C:\SoftHSM2\etc\softhsm2.conf

# Example SoftHSM2 config file (C:\SoftHSM2\etc\softhsm2.conf)
directories.tokendir = C:\SoftHSM2\var\softhsm2\tokens\
objectstore.backend = file
log.level = INFO

# Example generated SunPKCS11 file (C:\Users\winuser\AppData\Local\Temp\softhsm2-3360678726848364409.cfg
name=SoftHSM2
library=C:\SoftHSM2\lib\softhsm2-x64.dll
slotListIndex=0
