<!-- SPDX-License-Identifier: Apache-2.0 -->
<!--
Copyright (C) 2026 Nero Duality, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Release

Source code release only — from annotated `v*` tags. Pushing a tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml) on that commit
(source tarball + GitHub Release). Release body and download details
are in [`.github/release-notes.md`](.github/release-notes.md) (`@TAG@` / `@VERSION@`
substituted by CI). Edit the GitHub Release description after CI if you need extra notes.

## Tag a release

1. Merge to **`main`**.
2. Tag and push:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Preview release notes or build source assets before tagging:

```bash
TAG=v0.1.0 bash .github/scripts/release-render-notes.sh
TAG=v0.1.0 bash .github/scripts/release-build-source.sh
ls -l dist/
```
