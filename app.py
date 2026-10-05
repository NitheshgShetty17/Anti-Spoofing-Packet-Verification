import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from flask import Flask, render_template, request, jsonify
import hmac
import hashlib
import anti_spoofing


# ============================================================
# FLASK APPLICATION
# Explicitly define templates and static folders for deployment
# ============================================================

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates"
)


# Shared Secret Key from existing anti_spoofing.py
SECRET_KEY = anti_spoofing.KEY


# ============================================================
# HOME PAGE
# ============================================================

@app.route("/")
def home():
    """Renders the Anti-Spoofing Virtual Laboratory portal."""
    return render_template("index.html")


# ============================================================
# CREATE PACKET
# ============================================================

@app.route("/api/create_packet", methods=["POST"])
def create_packet():
    """Generates an authentic packet using HMAC-SHA256."""

    data = request.get_json() or {}

    src = data.get("src", "192.168.1.10").strip() or "192.168.1.10"
    dest = data.get("dest", "192.168.1.20").strip() or "192.168.1.20"

    try:
        seq = int(data.get("seq", 1001))
    except (ValueError, TypeError):
        seq = 1001

    msg = data.get("msg", "Hello Receiver").strip() or "Hello Receiver"

    mac = anti_spoofing.make_hmac(
        src,
        dest,
        seq,
        msg
    )

    return jsonify({
        "src": src,
        "dest": dest,
        "seq": seq,
        "msg": msg,
        "mac": mac,
        "mac_preview": mac[:16] + "..." + mac[-8:]
    })


# ============================================================
# VERIFY PACKET
# ============================================================

@app.route("/api/verify", methods=["POST"])
def verify_packet():
    """
    Verifies packet authenticity, integrity,
    source identity and replay protection.
    """

    data = request.get_json() or {}

    scenario_type = data.get("scenario", "custom")

    src = data.get("src") or data.get("source_ip") or ""
    dest = data.get("dest") or data.get("destination_ip") or ""

    try:
        seq = int(
            data.get("seq")
            or data.get("sequence")
            or 0
        )
    except (ValueError, TypeError):
        seq = 0

    msg = data.get("msg") or data.get("payload") or ""

    received_mac = (
        data.get("mac") or ""
    ).strip()


    # Generate expected HMAC
    expected_mac = anti_spoofing.make_hmac(
        src,
        dest,
        seq,
        msg
    )


    # --------------------------------------------------------
    # 1. Authentication + Integrity Check
    # --------------------------------------------------------

    auth = hmac.compare_digest(
        expected_mac,
        received_mac
    )


    # --------------------------------------------------------
    # 2. Replay Attack Protection
    # --------------------------------------------------------

    current_last_seq = anti_spoofing.last_sequence

    sequence_valid = seq > current_last_seq


    # --------------------------------------------------------
    # Final Decision
    # --------------------------------------------------------

    accepted = auth and sequence_valid


    if accepted:
        anti_spoofing.last_sequence = seq


    # --------------------------------------------------------
    # Reason for Verdict
    # --------------------------------------------------------

    if accepted:

        reason = "All checks passed. Packet accepted."

    elif not sequence_valid:

        reason = "Old packet was sent again."

    elif scenario_type == "spoofed" or src != "192.168.1.10":

        reason = "Source identity could not be verified."

    elif scenario_type == "modified" or msg != "Hello Receiver":

        reason = "Packet information was modified."

    else:

        reason = "Authentication and integrity verification failed."


    return jsonify({

        "accepted": accepted,

        "authentication":
            "PASS" if auth else "FAIL",

        "integrity":
            "PASS" if auth else "FAIL",

        "sequence_valid":
            "VALID" if sequence_valid else "FAIL",

        "expected_mac": expected_mac,

        "received_mac": received_mac,

        "mac_preview":
            received_mac[:16]
            + "..."
            + received_mac[-8:]
            if received_mac
            else "",

        "previous_sequence":
            current_last_seq,

        "current_sequence":
            anti_spoofing.last_sequence,

        "verdict":
            "PACKET ACCEPTED"
            if accepted
            else "PACKET REJECTED",

        "reason":
            reason
    })


# ============================================================
# ATTACK / DEMONSTRATION SCENARIOS
# ============================================================

@app.route("/api/scenario/<scenario>")
def scenario(scenario):
    """
    Provides packet values for classroom demonstration.
    """

    src = "192.168.1.10"
    dest = "192.168.1.20"
    seq = 1001
    msg = "Hello Receiver"


    genuine_mac = anti_spoofing.make_hmac(
        src,
        dest,
        seq,
        msg
    )


    # --------------------------------------------------------
    # GENUINE PACKET
    # --------------------------------------------------------

    if scenario == "genuine":

        return jsonify({

            "scenario":
                "genuine",

            "title":
                "Genuine Packet",

            "packet": {

                "src":
                    src,

                "dest":
                    dest,

                "seq":
                    seq,

                "msg":
                    msg,

                "mac":
                    genuine_mac,

                "scenario":
                    "genuine"
            },

            "highlight_field":
                None,

            "expected_verdict":
                "PACKET ACCEPTED"
        })


    # --------------------------------------------------------
    # PACKET MODIFICATION ATTACK
    # --------------------------------------------------------

    elif scenario in [
        "modified",
        "modification"
    ]:

        tampered_msg = (
            "Transfer Rs.50000 to attacker"
        )


        return jsonify({

            "scenario":
                "modified",

            "title":
                "Packet Modification Attack",

            "original_msg":
                msg,

            "modified_msg":
                tampered_msg,

            "packet": {

                "src":
                    src,

                "dest":
                    dest,

                "seq":
                    seq,

                "msg":
                    tampered_msg,

                # Attacker keeps original HMAC
                "mac":
                    genuine_mac,

                "scenario":
                    "modified"
            },

            "highlight_field":
                "msg",

            "expected_verdict":
                "PACKET REJECTED",

            "reason":
                "Packet information was modified."
        })


    # --------------------------------------------------------
    # SOURCE IP SPOOFING ATTACK
    # --------------------------------------------------------

    elif scenario in [
        "spoofed",
        "spoofing"
    ]:

        spoofed_src = "10.0.0.99"


        return jsonify({

            "scenario":
                "spoofed",

            "title":
                "Source IP Spoofing Attack",

            "original_src":
                src,

            "spoofed_src":
                spoofed_src,

            "packet": {

                "src":
                    spoofed_src,

                "dest":
                    dest,

                "seq":
                    seq,

                "msg":
                    msg,

                # Attacker keeps original HMAC
                "mac":
                    genuine_mac,

                "scenario":
                    "spoofed"
            },

            "highlight_field":
                "src",

            "expected_verdict":
                "PACKET REJECTED",

            "reason":
                "Source identity could not be verified."
        })


    # --------------------------------------------------------
    # REPLAY ATTACK
    # --------------------------------------------------------

    elif scenario in [
        "replay",
        "replayed"
    ]:

        return jsonify({

            "scenario":
                "replay",

            "title":
                "Replay Attack",

            "packet": {

                "src":
                    src,

                "dest":
                    dest,

                "seq":
                    seq,

                "msg":
                    msg,

                "mac":
                    genuine_mac,

                "scenario":
                    "replay"
            },

            "highlight_field":
                "seq",

            "expected_verdict":
                "PACKET REJECTED",

            "reason":
                "Old packet was sent again."
        })


    return jsonify({
        "error":
            "Invalid scenario name"
    }), 400


# ============================================================
# RESET SIMULATION
# ============================================================

@app.route("/api/reset", methods=["POST"])
def reset():
    """Reset sequence tracker."""

    anti_spoofing.reset_sequence()

    return jsonify({

        "status":
            "success",

        "message":
            "Simulation state reset successfully.",

        "last_sequence":
            anti_spoofing.last_sequence
    })


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "ANTI-SPOOFING PACKET VERIFICATION VIRTUAL LAB"
    )

    print(
        "Server running at: http://127.0.0.1:5000"
    )

    print("=" * 60)

    app.run(
        debug=True,
        port=5000
    )
