# D3FEND: File Carving

<a id="file-carving"></a>

D3FEND tactic: Detect  
Digital artifacts: File Transfer Network Traffic  

Identifying and extracting files from network application protocols through the use of network stream reassembly software.

## ATT&CK techniques countered (2)

- [T1071.002: File Transfer Protocols](/mitre/techniques/T1071-002.md): analyzes. Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic.
- [T1570: Lateral Tool Transfer](/mitre/techniques/T1570.md): analyzes. Adversaries may transfer tools or other files between systems in a compromised environment.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 2 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 2 of these techniques
- [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), which also counters 2 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 2 of these techniques
- [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), which also counters 2 of these techniques
- [Per Host Download-Upload Ratio Analysis](/mitre/d3fend/per-host-download-upload-ratio-analysis.md), which also counters 2 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [File Types and Extensions Reference](/FILE_TYPES_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
