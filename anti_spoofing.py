import hmac
import hashlib
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

KEY = b"BCS703-SECRET-KEY"
last_sequence = 0


def make_hmac(src, dest, seq, msg):
    data = f"{src}|{dest}|{seq}|{msg}".encode()
    return hmac.new(KEY, data, hashlib.sha256).hexdigest()


def verify(packet):
    global last_sequence

    expected = make_hmac(
        packet["src"],
        packet["dest"],
        packet["seq"],
        packet["msg"]
    )

    auth = hmac.compare_digest(expected, packet["mac"])
    sequence = packet["seq"] > last_sequence

    if auth:
        print("✓ Authentication verified")
        print("✓ Packet integrity verified")
    else:
        print("✗ Authentication failed")
        print("✗ Packet integrity verification failed")

    if sequence:
        print("✓ Sequence number valid")
    else:
        print("✗ Replay attack detected")

    if auth and sequence:
        last_sequence = packet["seq"]
        print("\n✓✓ PACKET ACCEPTED ✓✓")
    else:
        print("\n✗✗ PACKET REJECTED ✗✗")

    return {
        "auth": auth,
        "sequence": sequence,
        "accepted": auth and sequence,
        "expected_mac": expected
    }


def reset_sequence():
    global last_sequence
    last_sequence = 0


def packet(src, dest, seq, msg):
    return {
        "src": src,
        "dest": dest,
        "seq": seq,
        "msg": msg,
        "mac": make_hmac(src, dest, seq, msg)
    }


if __name__ == "__main__":
    print("=" * 55)
    print("       ANTI-SPOOFING PACKET VERIFICATION")
    print("=" * 55)

    src = input("\nEnter Sender IP [192.168.1.10]: ").strip()
    dest = input("Enter Receiver IP [192.168.1.20]: ").strip()
    msg = input("Enter Packet Message [Hello Receiver]: ").strip()

    src = src or "192.168.1.10"
    dest = dest or "192.168.1.20"
    msg = msg or "Hello Receiver"

    # 1. Genuine packet
    print("\n" + "=" * 55)
    print("                 GENUINE PACKET")
    print("=" * 55)

    p = packet(src, dest, 1001, msg)

    print("\n----- SENDER SIDE -----")
    print("Source IP      :", src)
    print("Destination IP :", dest)
    print("Message        :", msg)
    print("HMAC generated ✓")

    print("\n----- RECEIVER SIDE -----")
    print("Verifying packet...")
    verify(p)

    # 2. Modification attack
    print("\n" + "=" * 55)
    print("            PACKET MODIFICATION ATTACK")
    print("=" * 55)

    p2 = p.copy()
    p2["seq"] = 1002
    p2["msg"] = "Transfer Rs.50000 to attacker"

    print("\nOriginal Message :", msg)
    print("Modified Message :", p2["msg"])
    print("Attacker keeps original HMAC")

    print("\n----- RECEIVER SIDE -----")
    verify(p2)

    # 3. Spoofing attack
    print("\n" + "=" * 55)
    print("             SOURCE IP SPOOFING ATTACK")
    print("=" * 55)

    p3 = p.copy()
    p3["seq"] = 1003
    p3["src"] = "10.0.0.99"

    print("\nOriginal Source IP :", src)
    print("Spoofed Source IP  :", p3["src"])
    print("Attacker keeps original HMAC")

    print("\n----- RECEIVER SIDE -----")
    verify(p3)

    # 4. Replay attack
    print("\n" + "=" * 55)
    print("                  REPLAY ATTACK")
    print("=" * 55)

    print("\nAttacker captures the genuine packet.")
    print("Sequence Number :", p["seq"])
    print("Attacker sends the same packet again.")

    print("\n----- RECEIVER SIDE -----")
    verify(p)

    # Summary
    print("\n" + "=" * 55)
    print("              DEMONSTRATION SUMMARY")
    print("=" * 55)

    print("\n✓ Genuine packet      → ACCEPTED")
    print("✗ Modified packet     → REJECTED")
    print("✗ Spoofed source IP   → REJECTED")
    print("✗ Replay packet       → REJECTED")

    print("\n" + "=" * 55)
    print("       ANTI-SPOOFING SIMULATION COMPLETE")
    print("=" * 55)