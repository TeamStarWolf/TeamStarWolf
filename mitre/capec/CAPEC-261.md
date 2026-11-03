# CAPEC-261: Fuzzing for garnering other adjacent user/sensitive data

<a id="capec-261"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Draft  

An adversary who is authorized to send queries to a target sends variants of expected queries in the hope that these modified queries might return information (directly or indirectly through error logs) beyond what the expected set of queries should provide.

## Related CWE (1)

- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- The server must assume that the queries it receives follow specific templates and/or have fields or attributes that follow specific procedures. The server must process queries that it receives without adequately checking or sanitizing queries to ensure they follow these templates.

## Related pages

- [CAPEC-3: Using Leading 'Ghost' Character Sequences to Bypass Input Filters](/mitre/capec/CAPEC-3.md), also related to CWE-20
- [CAPEC-7: Blind SQL Injection](/mitre/capec/CAPEC-7.md), also related to CWE-20
- [CAPEC-8: Buffer Overflow in an API Call](/mitre/capec/CAPEC-8.md), also related to CWE-20
- [CAPEC-9: Buffer Overflow in Local Command-Line Utilities](/mitre/capec/CAPEC-9.md), also related to CWE-20
- [CAPEC-10: Buffer Overflow via Environment Variables](/mitre/capec/CAPEC-10.md), also related to CWE-20
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-20
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
