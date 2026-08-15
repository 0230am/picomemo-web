# Third-party notices

The distributed Worker/WASM artifact contains code from the following locked sources. Complete applicable license texts are shipped in `LICENSES/`.

- picomemo 1.2.1, downstream commit `ff75cfc41b9ea8e27e4fe961c08dd2bd8b922317`, tree `81f38825f67a4d3819f823be9e2821624047ba96`: ISC; Copyright 2024 mierenhoop. The Mbed TLS driver additionally carries Copyright 2026 mierenhoop.
- picomemo's pinned HACL*/KaRaMeL amalgamation: MIT (also offered under Apache-2.0); Copyright INRIA, CMU, Microsoft Corporation, and HACL* contributors.
- Mbed TLS 3.6.4: Apache-2.0 selected from its Apache-2.0 or GPL-2.0-or-later dual license.
- Emscripten 6.0.4: MIT and University of Illinois/NCSA.
- Emscripten's linked musl/emmalloc runtime: MIT-compatible and file-specific terms reproduced in `LICENSES/musl-COPYRIGHT.txt`.

No OpenSSL or picomemo `c25519.c` code is compiled into this artifact. Python interoperability dependencies are test-only and are not distributed.

