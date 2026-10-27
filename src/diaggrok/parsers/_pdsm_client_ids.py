# diaggrok-provenance: re
"""PDSM client_id whitelist shared by the CGPS/PDSM log family.

Several CGPS/PDSM logs carry the PDSM client handle in their header:

  0x1378  [0:2]  u16    LOG_CGPS_PDSM_GET_POSITION_C
  0x137A  [0:2]  u16
  0x1380  [0:4]  u32    ("subsystem_tag")
  0x1383  [1:5]  u32
  0x1482  [1:3]  u16    ("subtype")

The value was first read as an opaque "0xA30D family magic". It is the PDSM
client_id: on the EG25-G cold start the only co-temporal PDSM F3 site prints
``loc_pd_ext_event_cb ... client_id 3491`` and 3491 == 0x0DA3.
The handle is fixed per firmware stack, so it differs between vendors. Gating
on 3491 alone silently dropped every record from the other stacks: about
3,200 records on 0x1378 + 0x1482 in a corpus-wide runtime census.

Extend this set, don't relax it to "any value". Each code's other structural
gates are weak on their own, so the client_id is still a useful foreign-payload
filter. A new stack shows up as a NEW drop in the runtime census.
"""
from __future__ import annotations

PDSM_CLIENT_IDS: frozenset[int] = frozenset({
    1001,  # 0x03E9  Foxconn T99W175 (SDX55)
    3491,  # 0x0DA3  Quectel / Sierra MDM9x30+ / Telit (most of the fleet)
    5001,  # 0x1389  SIMCom SIM7600NA (MDM9607)
    9001,  # 0x2329  Sierra MC7700 (MDM9200, SWI9200X)
})
