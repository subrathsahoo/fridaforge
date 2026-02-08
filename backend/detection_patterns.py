# MASSIVE DETECTION PATTERNS - Comprehensive Security Check Keywords

## Root Detection Patterns (100+ patterns)
ROOT_DETECTION_PATTERNS = [
    # Common root check methods
    "isRooted", "isDeviceRooted", "checkRoot", "detectRoot", "hasRoot",
    "checkRootMethod", "isRootAvailable", "checkRooted", "verifyRoot",
    
    # Su binary checks
    "checkSu", "checkSuExists", "findSuBinary", "detectSu", "suExists",
    "checkForBinaries", "which su", "whereis su", "su --version",
    
    # Root management apps
    "Superuser", "SuperSU", "Magisk", "KingRoot", "KingoRoot", "OneClickRoot",
    "eu.chainfire.supersu", "com.topjohnwu.magisk", "com.noshufou.android.su",
    "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su",
    
    # Build properties
    "test-keys", "BUILD.TAGS", "ro.build.tags", "ro.secure", "ro.debuggable",
    "ro.build.selinux", "ro.build.type", "ro.build.user",
    
    # System paths
    "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
    "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
    "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
    
    # System commands
    "busybox", "which", "whereis", "getprop", "setprop",
    
    # Root detection libraries
    "RootBeer", "RootTools", "RootCloak", "RootCheck", "RootDetector",
    "checkRootManagementApps", "checkPotentiallyDangerousApps",
    
    # Native root checks
    "checkRootNative", "nativeCheckRoot", "Java_.*_checkRoot",
    "isRootedNative", "detectRootNative",
    
    # Advanced checks
    "checkForRWPaths", "checkSuBinary", "checkForDangerousProps",
    "checkForBusyBoxBinary", "checkForMagiskBinary", "checkRootCloaking"
]

## SSL Pinning Patterns (80+ patterns)
SSL_PINNING_PATTERNS = [
    # OkHttp pinning
    "CertificatePinner", "okhttp3.CertificatePinner", "com.squareup.okhttp.CertificatePinner",
    "CertificatePinner.Builder", "add(String, String...)", "certificatePinner",
    
    # TrustManager
    "TrustManager", "X509TrustManager", "checkServerTrusted", "checkClientTrusted",
    "getAcceptedIssuers", "TrustManagerFactory", "TrustManagerImpl",
    "com.android.org.conscrypt.TrustManagerImpl",
    
    # SSL Context
    "SSLContext", "SSLContext.init", "SSLSocketFactory", "createSSLSocketFactory",
    "setSSLSocketFactory", "SSLSocket", "SSLSession",
    
    # Hostname verification
    "HostnameVerifier", "verify(String, SSLSession)", "OkHostnameVerifier",
    "setHostnameVerifier", "ALLOW_ALL_HOSTNAME_VERIFIER", "STRICT_HOSTNAME_VERIFIER",
    
    # Network Security Config
    "NetworkSecurityConfig", "network_security_config", "network-security-config.xml",
    "cleartextTrafficPermitted", "pin-set", "trust-anchors",
    
    # Certificate pinning libraries
    "TrustKit", "com.datatheorem.android.trustkit", "TrustKitConfiguration",
    "SSLPinning", "PinningTrustManager", "PinningSSLSocketFactory",
    
    # Custom implementations
    "pinTrustedCertificatePublicKey", "checkCertificate", "verifyCertificate",
    "validateCertificateChain", "compareCertificates", "getCertificateFingerprint",
    
    # Public key pinning
    "PublicKeyPinning", "pinPublicKey", "publicKeyHash", "SubjectPublicKeyInfo",
    
    # Certificate exceptions
    "CertificateException", "SSLHandshakeException", "SSLPeerUnverifiedException",
    "CertPathValidatorException",
    
    # Conscrypt
    "com.android.org.conscrypt", "ConscryptEngineSocket", "ConscryptFileDescriptorSocket"
]

## Emulator Detection Patterns (60+ patterns)
EMULATOR_DETECTION_PATTERNS = [
    # Build properties
    "Build.FINGERPRINT", "Build.MODEL", "Build.MANUFACTURER", "Build.BRAND",
    "Build.DEVICE", "Build.PRODUCT", "Build.HARDWARE", "Build.HOST",
    "Build.BOARD", "Build.BOOTLOADER",
    
    # QEMU detection
    "qemu", "QEMU", "ro.kernel.qemu", "ro.kernel.android.qemu", "qemu.sf.fake_camera",
    "qemu.hw.mainkeys", "qemu.sf.lcd_density",
    
    # Emulator identifiers
    "generic", "goldfish", "ranchu", "sdk", "emulator", "vbox", "genymotion",
    "android-x86", "nox", "bluestacks", "memu", "ldplayer",
    
    # System properties
    "ro.product.device", "ro.product.model", "ro.product.brand", "ro.hardware",
    "ro.build.product", "ro.build.fingerprint",
    
    # Files
    "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
    
    # Methods
    "isEmulator", "checkEmulator", "detectEmulator", "isRunningOnEmulator",
    "checkVirtualEnvironment", "isVirtualDevice", "detectVirtualMachine"
]

## Anti-Debugging Patterns (90+ patterns)
ANTI_DEBUGGING_PATTERNS = [
    # Android Debug
    "Debug.isDebuggerConnected", "isDebuggerConnected", "ApplicationInfo.FLAG_DEBUGGABLE",
    "debuggable", "waitingForDebugger", "waitForDebugger",
    
    # Native debugging
    "ptrace", "PTRACE_TRACEME", "PTRACE_ATTACH", "PTRACE_DETACH", "anti_ptrace",
    
    # Frida detection
    "frida", "frida-server", "frida-agent", "frida-gadget", "gum-js-loop",
    "LIBFRIDA", "detectFrida", "checkFrida", "isFridaRunning", "findFrida",
    "frida_rpc", "27042", "27043",  # Default Frida ports
    
    # Xposed detection
    "de.robv.android.xposed", "XposedBridge", "XposedHelpers", "isXposedActive",
    "detectXposed", "checkXposed", "findXposedBridge",
    
    # Substrate detection
    "com.saurik.substrate", "CydiaSubstrate", "MSHookFunction",
    
    # Debug detection methods
    "getDebuggable", "checkDebuggable", "isDebugging", "hasDebugger",
    
    # TracerPid check
    "TracerPid", "/proc/self/status", "grep TracerPid", "readProcStatus",
    
    # Debug ports
    "debugPort", "5005", "8000", "android.os.Debug",
    
    # Hook detection
    "detectHook", "isHooked", "checkHook", "antiHook", "findHook",
    "checkMethodHook", "detectInstrumentation", "isInstrumented",
    
    # Debuggerd
    "Debuggerd", "tombstone", "debuggerd", "crash_dump",
    
    # Native anti-debug
    "anti_debug", "antiDebug", "checkDebug", "isNativeDebug",
    "Java_.*_checkDebug", "nativeCheckDebug"
]

## Integrity Check Patterns (70+ patterns)
INTEGRITY_CHECK_PATTERNS = [
    # Signature verification
    "verifySignature", "checkSignature", "validateSignature", "getSignature",
    "PackageInfo.signatures", "GET_SIGNATURES", "GET_SIGNING_CERTIFICATES",
    "SigningInfo", "hasMultipleSigners", "getApkContentsSigners",
    
    # Package info
    "getPackageInfo", "PackageManager.GET_SIGNATURES", "getInstallerPackageName",
    "checkPackageSignature", "compareSignatures",
    
    # Checksum validation
    "checksum", "CRC32", "MD5", "SHA1", "SHA256", "SHA512",
    "calculateChecksum", "verifyChecksum", "computeHash",
    
    # Tampering detection
    "tampered", "isTampered", "checkTamper", "detectTamper",
    "modifiedApp", "isModified", "checkModification",
    
    # Integrity services
    "PlayIntegrity", "SafetyNet", "attestation", "integrityToken",
    "isDeviceSecure", "verifyIntegrity", "checkIntegrity",
    
    # DEX integrity
    "checkDex", "verifyDex", "compareDex", "dexChecksum",
    "classes.dex", "validateDex",
    
    # Installer verification
    "checkInstaller", "verifyInstaller", "getInstallerPackage",
    "com.android.vending", "isFromPlayStore",
    
    # Code verification
    "validateCode", "checkCodeIntegrity", "verifyAPK", "checkAPK"
]

## Native/JNI Patterns (50+ patterns)
NATIVE_JNI_PATTERNS = [
    # Library loading
    "System.loadLibrary", "System.load", "Runtime.loadLibrary", "dlopen", "dlsym",
    
    # JNI methods
    "JNI_OnLoad", "JNI_OnUnload", "RegisterNatives", "FindClass",
    "GetMethodID", "CallStaticMethod", "NewStringUTF",
    
    # Native checks
    "Java_.*_check", "Java_.*_verify", "Java_.*_detect", "Java_.*_is",
    "nativeCheck", "nativeVerify", "nativeDetect", "nativeIs",
    
    # Native anti-debug
    "native_anti_debug", "nativeAntiDebug", "checkDebugNative",
    
    # Native root
    "native_check_root", "nativeCheckRoot", "isRootedNative",
    
    # SO libraries
    ".so", "lib*.so", "libnative", "libsecurity", "libprotect",
    
    # NDK
    "android_getNativeLibraryDirectories", "nativeGetRuntime"
]

## Flutter/React Native Patterns (40+ patterns)
FLUTTER_RN_PATTERNS = [
    # Flutter
    "MethodChannel", "EventChannel", "BasicMessageChannel",
    "io.flutter", "flutter.embedding", "FlutterActivity",
    "FlutterEngine", "FlutterPlugin", "PlatformChannel",
    
    # React Native
    "ReactNative", "ReactContext", "NativeModule", "ReactMethod",
    "com.facebook.react", "ReactApplicationContext", "ReactPackage",
    "JSBridge", "Hermes", "JSIModule",
    
    # Security checks
    "platformMethodCall", "securityCheck", "integrityCheck",
    "deviceCheck", "rootCheck"
]

## Obfuscation Indicators (30+ patterns)
OBFUSCATION_PATTERNS = [
    # ProGuard/R8
    "a.b.c", "o.O.o", "Il", "II", "ll", "O0", "oo", "OO",
    
    # Single letter packages
    "^[a-z]\\.[a-z]\\.", "^[a-zA-Z]\\.[a-zA-Z]\\.",
    
    # DexGuard
    "StringFog", "Bangcle", "SecShell", "Qihoo", "Tencent"
]

## Self-Learning Patterns
# When AI encounters new protection patterns, they get added here
# Format: {"pattern": "newKeyword", "type": "protection_type", "confidence": 0.95}
LEARNED_PATTERNS = []
