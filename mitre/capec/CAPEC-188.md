# CAPEC-188 — Reverse Engineering

<a id="capec-188"></a>

**Abstraction:** Meta  
**Typical severity:** Low  
**Likelihood:** Low  
**Status:** Stable  

An adversary discovers the structure, function, and composition of an object, resource, or system by using a variety of analysis techniques to effectively determine how the analyzed entity was constructed or operates. The goal of reverse engineering is often to duplicate the function, or a part of the function, of an object in order to duplicate or "back engineer" some aspect of its functioning. Reverse engineering techniques can be applied to mechanical objects, electronic devices, or software, although the methodology and techniques involved in each type of analysis differ widely.

## Related CWE (1)

- [CWE-1278 — Missing Protection Against Hardware Reverse Engineering Using Integrated Circuit (IC) Imaging Techniques](https://cwe.mitre.org/data/definitions/1278.html) — Information stored in hardware may be recovered by an attacker with the capability to capture and analyze images of the integrated circuit using techniques such as scanning electron microscopy.

## Prerequisites

- Access to targeted system, resources, and information.

## Skills required

- [High] Understanding of low level programming languages or technologies can be very helpful. For example, when reverse engineering a binary file, an understanding of assembly languages can help to determine the purpose and inner-workings of the code. Another example is reverse engineering an application that relies on networking. Here, an understanding networking protocols can provide insight into application details.

## Mitigations

- Employ code obfuscation techniques to prevent the adversary from reverse engineering the targeted entity.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
