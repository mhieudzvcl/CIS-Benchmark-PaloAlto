"""PAN-OS XML API minimal client. Credentials/API key never written to disk."""
import time

import requests
from lxml import etree


class PanOSAPIError(RuntimeError):
    pass


class PanOSClient:
    def __init__(self, host, verify_tls=True):
        self.host = host
        self.url = f"https://{host}/api/"
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update({"Cache-Control": "no-store"})

    def request(self, data, timeout=40):
        response = self.session.post(self.url, data=data, timeout=timeout)
        response.raise_for_status()
        root = etree.fromstring(response.content, parser=etree.XMLParser(
            resolve_entities=False, no_network=True, huge_tree=False
        ))
        if root.tag != "response" or root.get("status") != "success":
            error = (root.findtext("./msg/line") or root.findtext("./msg") or
                     root.findtext("./result/msg") or "Unexpected API response")
            raise PanOSAPIError(error)
        return root

    def authenticate(self, username, password):
        root = self.request({"type": "keygen", "user": username, "password": password})
        key = root.findtext("./result/key")
        if not key:
            raise PanOSAPIError("API key not returned")
        self.session.headers["X-PAN-KEY"] = key

    def get_config(self, action="show"):
        if action not in ("show", "get"):
            raise ValueError("Invalid config read action")
        root = self.request({"type": "config", "action": action, "xpath": "/config"})
        element = root.find("./result/config")
        if element is None:
            raise PanOSAPIError("<config> not present in API response")
        return element

    def get_ha_state(self):
        return self.request({"type": "op", "cmd":
            "<show><high-availability><state></state></high-availability></show>"})

    def set_element(self, xpath, xml_element):
        if not xpath.startswith("/config/"):
            raise ValueError("Unexpected XPath")
        return self.request({"type": "config", "action": "set", "xpath": xpath,
                             "element": xml_element})

    def commit_own_changes(self, username):
        from xml.sax.saxutils import escape
        cmd = ("<commit><partial><admin><member>" + escape(username) +
               "</member></admin></partial></commit>")
        root = self.request({"type": "commit", "action": "partial", "cmd": cmd}, timeout=90)
        job = root.findtext("./result/job")
        if job is None:
            msg = " ".join(root.xpath("./msg//text()"))
            if "no pending changes" in msg.lower():
                raise PanOSAPIError("No pending changes to commit")
            raise PanOSAPIError(f"No commit job id returned: {msg[:250]}")
        return job

    def wait_for_commit(self, jobid, timeout=240, interval=3):
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            root = self.request({"type": "op", "cmd":
                f"<show><jobs><id>{int(jobid)}</id></jobs></show>"})
            job = root.find("./result/job")
            if job is not None and job.findtext("./status") == "FIN":
                result = (job.findtext("./result") or "").upper()
                if result != "OK":
                    detail = " ".join(job.xpath("./details//text()"))
                    raise PanOSAPIError(f"Commit finished with {result}: {detail[:300]}")
                return
            time.sleep(interval)
        raise TimeoutError(f"Commit job {jobid} did not finish in {timeout}s")

    def close(self):
        self.session.close()
