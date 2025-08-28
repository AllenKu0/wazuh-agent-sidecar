from flask import Flask, request, jsonify, Response, make_response
import base64
import json
import logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

WAZUH_IMAGE = os.getenv("WAZUH_SIDECAR_IMAGE", "kennyopennix/wazuh-agent:latest")
WAZUH_GROUPS = os.getenv("WAZUH_GROUPS", "default")
JOIN_MANAGER = os.getenv("JOIN_MANAGER", "10.1.0.39")
JOIN_MANAGER_PORT = os.getenv("JOIN_MANAGER_PORT", "1514")
JOIN_MANAGER_PROTOCOL = os.getenv("JOIN_MANAGER_PROTOCOL", "https")
JOIN_MANAGER_API_PORT = os.getenv("JOIN_MANAGER_API_PORT", "55000")

wazuh_sidecar = {
    "name": "wazuh-agent",
    "image": WAZUH_IMAGE,
    "securityContext": {"runAsUser": 0},
    "env": [
        {"name": "JOIN_MANAGER", "value": JOIN_MANAGER},
        {"name": "JOIN_MANAGER_PORT", "value": JOIN_MANAGER_PORT},
        {"name": "JOIN_MANAGER_PROTOCOL", "value": JOIN_MANAGER_PROTOCOL},
        {"name": "JOIN_MANAGER_API_PORT", "value": JOIN_MANAGER_API_PORT},
        {"name": "WAZUH_GROUPS", "value": WAZUH_GROUPS},
        # Secret-based credentials
        {
            "name": "JOIN_MANAGER_USER",
            "valueFrom": {"secretKeyRef": {"name": "wazuh-manager-credentials", "key": "JOIN_MANAGER_USER"}}
        },
        {
            "name": "JOIN_MANAGER_PASSWORD",
            "valueFrom": {"secretKeyRef": {"name": "wazuh-manager-credentials", "key": "JOIN_MANAGER_PASSWORD"}}
        },
        {
            "name": "NODE_NAME",
            "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}
        },
    ],
    "volumeMounts": [
        {"name": "app-logs", "mountPath": "/var/log/app"},
        {"name": "suricata-logs", "mountPath": "/var/log/suricata"}
    ]
}

wazuh_volumes = [
    {"name": "app-logs", "emptyDir": {}},
    {"name": "suricata-logs", "emptyDir": {}}
]

def build_response(uid: str, allowed: bool, patch=None, message: str | None = None):
    resp = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": uid,
            "allowed": allowed
        }
    }
    if message:
        resp["response"]["status"] = {"message": message}
    if patch:
        patch_b64 = base64.b64encode(json.dumps(patch).encode()).decode()
        resp["response"].update({
            "patch": patch_b64,
            "patchType": "JSONPatch"
        })
    return resp


@app.route("/healthz", methods=["GET"])  # simple liveness/readiness endpoint
def health():
    return "ok", 200


@app.route("/mutate", methods=["POST"])
def mutate():
    try:
        if not request.is_json:
            logging.error("Request content-type not application/json: %s", request.content_type)
            # apiserver still expects an AdmissionReview wrapper even on error; uid may be unknown
            return jsonify(build_response(uid="", allowed=False, message="invalid content-type"))

        request_info = request.get_json(force=True, silent=False)
        logging.debug("=== Incoming AdmissionReview ===\n%s", json.dumps(request_info, indent=2))

        # Defensive parsing
        req_obj = request_info.get("request") or {}
        uid = req_obj.get("uid", "")
        pod = req_obj.get("object") or {}
        pod_spec = pod.get("spec") or {}

        patch = []

        # Only mutate Pod creations; if missing required pieces just allow without changes
        if not uid or pod.get("kind") not in (None, "Pod"):
            logging.warning("Unexpected object kind or missing uid; returning allow without mutation")
            return jsonify(build_response(uid=uid, allowed=True))

        # Add sidecar container
        if "containers" not in pod_spec:
            patch.append({"op": "add", "path": "/spec/containers", "value": [wazuh_sidecar]})
        else:
            patch.append({"op": "add", "path": "/spec/containers/-", "value": wazuh_sidecar})

        # Add volumes (idempotent)
        existing_vols = pod_spec.get("volumes", [])
        if not existing_vols:
            patch.append({"op": "add", "path": "/spec/volumes", "value": wazuh_volumes})
        else:
            for vol in wazuh_volumes:
                if all(v.get("name") != vol["name"] for v in existing_vols):
                    patch.append({"op": "add", "path": "/spec/volumes/-", "value": vol})

        resp = build_response(uid=uid, allowed=True, patch=patch if patch else None)
        logging.debug("=== Response AdmissionReview ===\n%s", json.dumps(resp, indent=2))
        response = make_response(json.dumps(resp), 200)
        response.headers["Content-Type"] = "application/json"
        return response

    except Exception as e:
        logging.exception("Exception in mutate")
        uid = ""
        try:
            uid = (request.get_json() or {}).get("request", {}).get("uid", "")
        except Exception:  # pragma: no cover - best effort
            pass
        error_resp = build_response(uid=uid, allowed=False, message=str(e))
        return jsonify(error_resp)

        
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443, ssl_context=("/tls/tls.crt", "/tls/tls.key"),debug=True)
