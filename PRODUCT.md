# Proofpacket

Proofpacket helps an engineer review an agent's completion claims using evidence that survives the chat. Its first useful job is answering: “Which command ran against which files, and is that evidence still current?”

A reviewer opens a packet for a document-sharing change. “Guests cannot reshare” links to a passing targeted test. “All access paths are covered” has no linked check and remains unverified. After the authorization source changes, the formerly passing test is visibly stale. The packet never equates a linked passing test with proof that a behavior claim is true.

The v0.1 artifact contains a task, author-written claims and assumptions, selected source fingerprints, actual command results, and a static Markdown review report. A local wrapper executes only a command the user explicitly supplies. Evidence records preserve argv, working directory, observation time, exit code, output excerpts, and before/after source fingerprints. Claim-to-check relevance is explicitly asserted by the author, not inferred by the program.

The boundary is evidence capture and freshness. Git diff inference, CI import, automatic test discovery, security attestations, and semantic claim verification are deferred. Keeping selected file scope visible is essential: an unchanged selected set says nothing about untracked inputs, environment changes, or dependencies.

Success should be tested on real review tasks with misleading and accurate completion claims. Compare review time, consequential defects caught, stale checks noticed, and recording effort against a normal diff plus test output. A pretty packet or faster approval alone does not validate the product.
