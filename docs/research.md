# Research behind Bayora

Sources were collected and read on 19 November 2026 with [TinyFish](https://tinyfish.ai) (Search, Fetch and Monitor). Every claim below has an ID (C1 to C13) that matches [`research/sources.yaml`](../research/sources.yaml), where each source records **how much of it was read**: `full`, `section`, `abstract`, `searched` (searched for terms only) or `snippet` (a search excerpt, not read). Treat `snippet` sources as leads, not evidence.

The sources are fingerprinted and sealed in a Merkle log (`bayora research collect` then `seal`), and the console's **Research** page verifies that seal in the browser.

## 1. Why verifiable red-team evidence matters now

- **C1.** EU AI Act Article 55(1)(a) requires providers of general-purpose AI models with systemic risk to perform model evaluation "including conducting and documenting adversarial testing" (`eu-art55`, read in full). Bayora produces the documentation half of that sentence.
- **C2.** The Commission's AI Office held a workshop on 15 July 2026 on qualification and independence requirements for external evaluators. It wants evaluators "free from the provider's managerial, financial or operational influence" so that evaluations are reliable (`eu-evaluators`, page read in full; the downloadable report was not). This is the regulatory version of Bayora's question: *can the result be checked without trusting the party that produced it?*
- **C13.** The GPAI Code of Practice (published 10 July 2025) has a Safety and Security chapter for providers of Article 55 models. Its official page lists 22 signatories plus xAI for that chapter only, as of its 7 October 2026 update (`eu-gpai-code`, read in full). This is regulatory context. **It is not evidence of customer demand**: we have run no interviews.

## 2. The cache side channel is real, current, and its fix can fail

| | Finding | Source (read) |
|---|---|---|
| C3 | Sharing the KV cache between tenants lets an attacker reconstruct other users' prompts (PromptPeek, NDSS 2025). A later NDSS 2026 paper shows inversion, collision and injection attacks on the KV cache and proposes a defence. | `ndss25-promptpeek` (abstract), `ndss26-shadow` (abstract) |
| C4 | Global prompt-cache sharing across users was detected in **seven** API providers, including OpenAI (ICML 2025). | `gu25-auditing` (abstract) |
| C5 | vLLM documents the prefix-cache timing channel as **CVE-2025-46570** and names per-tenant `cache_salt` as the mitigation. It says the salt must be treated as a secret: random and long (it suggests 256 bits), because a guessable salt still allows the attack. | `vllm-security` (section) |
| C6 | The mitigation has failed silently in a release. Advisory GHSA-935w-9g4m-p28p (28 Sep 2026): on one code path in vLLM up to 0.25.1, tool-continuation requests dropped `cache_salt`, so another tenant could read exact cached-token counts. Fixed in 0.30.0. Rated Low severity. | `vllm-ghsa` (full) |

**What this means for Bayora.** C6 is the strongest argument for Bayora's design choice: *test the endpoint, do not trust the configuration.* A setting that says "salted" proved wrong on a real code path. Bayora's cache audit measures what an attacker can actually recover, shared versus salted, before a run is trusted. Related timing-side-channel work (`song-early-bird`, `inputsnatch`, `prefixwall`) is listed as snippet-only: leads we have not read.

## 3. Evaluation environments leak information

- **C7.** AISI ran an open-source coding agent inside one of its own evaluation sandboxes and asked it to learn about its environment. It identified the organisation (domain names in TLS certificates), inferred an employee's full name (a username in DNS settings), the cloud provider, parts of the internal architecture, and a timeline of research activity. After AISI hardened the sandbox, the agent kept finding other routes; one bypassed a proxy to read certificates directly (`aisi-env`, full). AISI's concern: an agent that knows it is being evaluated may change its behaviour, which threatens the validity of the result.
- **Bayora does not test for this.** Our isolation probes check network, file and write paths between zones. They do not check whether an agent in a zone can learn who is running the evaluation. This is now listed as a gap in the [threat model](threat-model.md).

## 4. What exists, and the gap

- **C8.** Inspect's sandboxing provisions containers in which tools, agents and scorers run code (`inspect-sandboxing`). garak is a vulnerability scanner with probes, PyRIT and promptfoo are red-teaming tools.
- We searched Inspect's sandboxing page and the READMEs of garak, PyRIT and promptfoo for *tamper, audit, attest, receipt, witness, merkle, provenance, canary*. **None of those words appear.** That supports the claim that they do not describe tamper-evident, third-party-checkable audit of the evaluation itself.
- **How far this goes.** It is evidence about those four documents only. PyRIT's and promptfoo's READMEs are short and point to other documentation we did not read. garak does mention "data leakage", as something to probe a model for, which is a different problem from leakage *between* the teams of an evaluation. We therefore say "the documents we searched do not describe it", not "none of these tools can do it".

## 5. Bayora against the standards it follows

| | Standard | Bayora | Checked against |
|---|---|---|---|
| C9 | RFC 9162 Merkle tree: leaf `H(0x00 ‖ d)`, node `H(0x01 ‖ l ‖ r)`, split at the largest power of two below n | Matches | `rfc9162` (searched for the definitions) |
| C10 | in-toto Statement v1 (`_type`, `subject` with digest, `predicateType`, `predicate`) | Matches | `intoto-statement` (full) |
| C10 | DSSE envelope (`payload`, `payloadType`, `signatures`) and PAE `"DSSEv1" SP len(type) SP type SP len(body) SP body` | Matches. The spec's own test vector is now a test | `dsse-envelope`, `dsse-protocol` (full) |
| C11 | C2SP tlog-cosignature (Ed25519): signs `cosignature/v1`, a `time` line, origin, size and root | **Differs.** Ours signs a plain `cosig` prefix plus origin, size and root: no domain string, no timestamp. This is why witness cosignatures are not C2SP-compatible. The spec also recommends ML-DSA-44 for new deployments, and says Ed25519 cosignatures do not commit to the cosigner's name | `c2sp-cosignature` (full) |

## 6. What the research changed in the code

1. **The verifier rejects an unsupported DSSE `payloadType`.** The protocol says to reject unknown types; Bayora's verifier checked the signature against whatever type the receipt claimed and never refused one.
2. **The verifier accepts URL-safe and unpadded base64.** DSSE says verifiers "MUST accept either". Ours accepted only the standard alphabet. Done in both `bayora verify` and the in-browser verifier.
3. **The browser verifier reads the receipt from the bytes it verified.** DSSE says an implementation must not re-parse the envelope after verification. The browser previously read the receipt contents from a copy the server had decoded.
4. **A DSSE test vector in the test suite** (`tests/test_conformance.py`), taken from the spec, not from our own code.
5. **Salt guidance.** Bayora's emulated salt is a per-run `secrets.token_hex(8)`, **64 random bits**, never shared with the attacker. vLLM recommends 256 bits for a real deployment. We have not changed it, because that would mean re-running the cache test; a production salt should follow vLLM's advice.

## 7. Limits of this research

- Read depth varies by source, and the manifest says how much. Six sources were snippet-only at the time of writing.
- We read the abstracts of the cache-attack papers, not the papers. We rely on the vLLM documentation for the claim that the timing signal is distinguishable at very short prefix lengths and do not attribute the figure to a paper.
- Nothing here establishes demand for Bayora. The regulatory sources show that independent, documented evaluation is an obligation, not that anyone will buy a tool for it.
- Search results and fetched pages are third-party content. We cite what a page says, not whether it is right.

## 8. Reproduce and keep it current

```bash
export TINYFISH_API_KEY=...                   # create one at https://agent.tinyfish.ai/api-keys
bayora research collect                       # fetch every source with TinyFish, fingerprint it
bayora research seal                          # sign the list into a Merkle log (research/seal.json)
bayora research verify                        # anyone can run this: re-hashes the log and the cached pages
bayora research watch                         # run the TinyFish monitors; changed pages go to research/drift.jsonl
```

Three TinyFish Monitors (`research/monitors.json`) check the Article 55 page, the AI Office evaluator-requirements page and the GPAI Code page every Monday at 06:00 UTC. A page whose text changes appears on the console's Research page as "changed".
