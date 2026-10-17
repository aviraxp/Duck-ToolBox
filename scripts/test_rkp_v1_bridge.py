"""Exercise the actual Java bridge against a host AIDL fixture (no HAL or network)."""
import pathlib
import struct
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "crates/duck-rkp-device/bridge/RkpV1Bridge.java"
STUBS = {
    "android/os/IBinder.java": "package android.os; public interface IBinder {}",
    "android/os/ServiceSpecificException.java": """
package android.os;
public class ServiceSpecificException extends RuntimeException {
    public final int errorCode;
    public ServiceSpecificException(int code) { super("HAL rejected request"); errorCode = code; }
} """,
    "android/os/ServiceManager.java": """
package android.os;
public class ServiceManager {
    public static IBinder checkService(String name) {
        if (!name.equals("android.hardware.security.keymint.IRemotelyProvisionedComponent/default"))
            throw new AssertionError("wrong service");
        return Boolean.getBoolean("test.missing") ? null : new IBinder() {};
    }
} """,
    "android/hardware/security/keymint/RpcHardwareInfo.java": """
package android.hardware.security.keymint;
public class RpcHardwareInfo { public int supportedEekCurve = Integer.getInteger("test.curve", 2); }
""",
    "android/hardware/security/keymint/MacedPublicKey.java": """
package android.hardware.security.keymint;
public class MacedPublicKey { public byte[] macedKey; }
""",
    "android/hardware/security/keymint/DeviceInfo.java": """
package android.hardware.security.keymint;
public class DeviceInfo { public byte[] deviceInfo; }
""",
    "android/hardware/security/keymint/ProtectedData.java": """
package android.hardware.security.keymint;
public class ProtectedData { public byte[] protectedData; }
""",
    "android/hardware/security/keymint/IRemotelyProvisionedComponent.java": """
package android.hardware.security.keymint;
public interface IRemotelyProvisionedComponent {
    RpcHardwareInfo getHardwareInfo();
    byte[] generateCertificateRequest(boolean testMode, MacedPublicKey[] keys,
            byte[] eek, byte[] challenge, DeviceInfo di, ProtectedData pd);
    public static class Stub {
        public static IRemotelyProvisionedComponent asInterface(android.os.IBinder binder) {
            if (binder == null) throw new AssertionError("null binder");
            return new Proxy();
        }
    private static class Proxy implements IRemotelyProvisionedComponent {
    public RpcHardwareInfo getHardwareInfo() { return new RpcHardwareInfo(); }
    public byte[] generateCertificateRequest(boolean testMode, MacedPublicKey[] keys,
            byte[] eek, byte[] challenge, DeviceInfo di, ProtectedData pd) {
        int error = Integer.getInteger("test.error", 0);
        if (error != 0) throw new android.os.ServiceSpecificException(error);
        if (testMode || keys.length != 1 || keys[0].macedKey[0] != 42 || challenge[0] != 7)
            throw new AssertionError("incorrect production request");
        if (eek[0] != Integer.getInteger("test.curve", 2))
            throw new AssertionError("wrong EEK selected");
        di.deviceInfo = new byte[] {11, 12};
        pd.protectedData = new byte[] {21, 22, 23};
        if (Boolean.getBoolean("test.nullDevice")) di.deviceInfo = null;
        if (Boolean.getBoolean("test.emptyDevice")) di.deviceInfo = new byte[0];
        if (Boolean.getBoolean("test.largeProtected")) pd.protectedData = new byte[0xa001];
        if (Boolean.getBoolean("test.nullMac")) return null;
        return new byte[Boolean.getBoolean("test.shortMac") ? 31 : 32];
    }
    }
    }
}
""",
}


def frame(value):
    return struct.pack(">i", len(value)) + value


class BridgeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="rkp-v1-bridge-test-")
        cls.root = pathlib.Path(cls.temporary.name)
        cls.classes = cls.root / "classes"
        cls.classes.mkdir()
        sources = [str(BRIDGE)]
        for relative, source in STUBS.items():
            path = cls.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
            sources.append(str(path))
        subprocess.run(["javac", "--release", "8", "-d", str(cls.classes), *sources], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_bridge(self, properties=(), request=None):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            exchange = pathlib.Path(directory)
            if request is None:
                request = b"".join(frame(value) for value in [b"\x07", b"\x2a", b"\x01", b"\x02"])
            (exchange / "request.bin").write_bytes(request)
            subprocess.run(["java", *properties, "-cp", str(self.classes),
                            "duck.rkp.RkpV1Bridge", directory], check=True, timeout=10)
            return (exchange / "reply.bin").read_bytes()

    def test_matching_proxy_receives_production_request_and_hardware_curve(self):
        for curve in [1, 2]:
            with self.subTest(curve=curve):
                response = self.run_bridge([f"-Dtest.curve={curve}"])
                self.assertEqual(response, struct.pack(">i", 0) + frame(bytes(32))
                                 + frame(bytes([11, 12])) + frame(bytes([21, 22, 23])))

    def test_aidl_exception_preserves_service_error_code(self):
        for error in [2, 6, -40]:
            with self.subTest(error=error):
                response = self.run_bridge([f"-Dtest.error={error}"])
                self.assertEqual(struct.unpack(">ii", response[:8]), (1, error))
                self.assertIn(b"HAL rejected request", response)

    def test_unavailable_service_and_unsupported_curve_are_transport_errors(self):
        for property in ["-Dtest.missing=true", "-Dtest.curve=0"]:
            with self.subTest(property=property):
                response = self.run_bridge([property])
                self.assertEqual(struct.unpack(">i", response[:4])[0], 2)

    def test_invalid_hal_results_have_the_invalid_response_status(self):
        for property in ["shortMac", "nullMac", "nullDevice", "emptyDevice", "largeProtected"]:
            with self.subTest(property=property):
                response = self.run_bridge([f"-Dtest.{property}=true"])
                self.assertEqual(struct.unpack(">i", response[:4])[0], 3)

    def test_malformed_input_is_rejected_before_the_hal_call(self):
        valid = b"".join(frame(value) for value in [b"\x07", b"\x2a", b"\x01", b"\x02"])
        for request in [valid[:-1], valid + b"x", struct.pack(">i", -1),
                        struct.pack(">i", 0xa001), frame(bytes(65)) + valid[5:],
                        frame(b"") + valid[5:]]:
            response = self.run_bridge(["-Dtest.error=99"], request)
            self.assertEqual(struct.unpack(">i", response[:4])[0], 2)

    def test_missing_hardware_curve_chain_is_rejected_before_issuance(self):
        request = b"".join(frame(value) for value in [b"\x07", b"\x2a", b"\x01", b""])
        response = self.run_bridge(["-Dtest.error=99"], request)
        self.assertEqual(struct.unpack(">i", response[:4])[0], 2)
        self.assertIn(b"no EEK chain for curve 2", response)


if __name__ == "__main__":
    unittest.main()
