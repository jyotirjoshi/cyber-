"""Private, destructive-but-self-cleaning DefectDojo acceptance probe.

Run only inside the Cynux scanner worker, whose environment contains the private URL and
Secret Manager-provisioned service token.  The script never prints credentials or raw
provider responses.  It creates a uniquely named product and engagement, exercises import,
read, reimport, and closure, then deletes the product in ``finally``.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import uuid

from app.core.config import get_settings
from app.db.enums import Severity
from app.integrations.defectdojo import DefectDojoClient


OPEN_PORT_SCAN = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 192.0.2.10" start="1792713600">
  <host><status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="cynux-dd-test.invalid" type="user"/></hostnames>
    <ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
      <service name="https" product="Cynux acceptance fixture" version="1.0"/>
    </port></ports>
  </host>
  <runstats><finished time="1792713601"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""

CLOSED_PORT_SCAN = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV 192.0.2.10" start="1792713660">
  <host><status state="up" reason="syn-ack"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="cynux-dd-test.invalid" type="user"/></hostnames>
    <ports></ports>
  </host>
  <runstats><finished time="1792713661"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


async def main() -> None:
    client = DefectDojoClient(get_settings())
    product_id: int | None = None
    results: dict[str, object] = {}
    suffix = uuid.uuid4().hex[:12]
    today = dt.date.today().isoformat()
    try:
        health = await client._require().get_json("/api/v2/users/", params={"limit": 1})
        results["authenticated"] = isinstance(health, dict) and "results" in health

        product = await client.ensure_product(
            f"cynux-live-acceptance-{suffix}",
            description="Temporary Cynux DefectDojo connector acceptance record.",
        )
        product_id = product.id
        results["product_created"] = product.id > 0

        engagement = await client.ensure_engagement(
            product_id=product.id,
            name=f"connector-test-{suffix}",
            target_start=today,
            target_end=today,
            description="Temporary connector acceptance engagement.",
            tags=["cynux", "acceptance-test"],
        )
        results["engagement_created"] = engagement.id > 0

        imported = await client.import_scan(
            engagement_id=engagement.id,
            scan_type="Nmap Scan",
            file=OPEN_PORT_SCAN,
            filename="cynux-acceptance-nmap.xml",
            scan_date=today,
            test_title=f"Cynux connector acceptance {suffix}",
            minimum_severity=Severity.INFO,
            tags=["cynux", "acceptance-test"],
        )
        results["import_test_id"] = imported.test_id
        results["import_created"] = imported.findings_created
        first_findings = await client.list_findings(test_id=imported.test_id)
        results["findings_read"] = len(first_findings)

        reimported = await client.reimport_scan(
            test_id=imported.test_id,
            engagement_id=engagement.id,
            scan_type="Nmap Scan",
            file=CLOSED_PORT_SCAN,
            filename="cynux-acceptance-nmap-closed.xml",
            scan_date=today,
            minimum_severity=Severity.INFO,
            tags=["cynux", "acceptance-test"],
        )
        results["reimport_test_id_matches"] = reimported.test_id == imported.test_id
        after_findings = await client.list_findings(test_id=imported.test_id)
        results["active_after_reimport"] = sum(item.active for item in after_findings)

        await client.close_engagement(engagement.id)
        results["engagement_closed"] = True
    finally:
        if product_id is not None:
            response = await client._require().request(
                "DELETE", f"/api/v2/products/{product_id}/"
            )
            results["cleanup_status"] = response.status_code
        await client.aclose()

    results["passed"] = bool(
        results.get("authenticated")
        and results.get("product_created")
        and results.get("engagement_created")
        and isinstance(results.get("import_test_id"), int)
        and results.get("reimport_test_id_matches")
        and results.get("engagement_closed")
        and results.get("cleanup_status") in {200, 202, 204}
    )
    print(json.dumps(results, sort_keys=True))
    if not results["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
