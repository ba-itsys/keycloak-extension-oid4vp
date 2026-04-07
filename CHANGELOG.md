# Changelog

## [0.5.2](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.5.1...v0.5.2) (2026-04-07)


### Bug Fixes

* check LoTEType and Service Type when evaluating trust lists ([5af450a](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/5af450a957eac449a03bbb5d6310f2cabb57a670))
* docs and flaky test ([164b9b5](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/164b9b506681e21c05f21a584b2bc6031d4c00d6))
* kid-based signing cert lookup/https statuslist tests ([cdec021](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/cdec021d56643f37dee89af6ecd944bade4c2be6))
* parse nested json claim values in mDoc credentials ([e3edaa2](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/e3edaa2652e3f9ef5a4720232309617ad1c7c674))
* support a single credential type in vp_token ([0f7851e](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/0f7851e003d0626e3f476bf02a915b4f6f8f3a75))


### Dependencies

* **deps-dev:** bump org.apache.maven.plugins:maven-compiler-plugin ([9827b50](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/9827b501d54cb8f7c30d3f972f6726d762cfa827))
* **deps-dev:** bump org.apache.maven.plugins:maven-failsafe-plugin ([6f8048e](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/6f8048e5e970f9c62c24ffc8e69de3f3a7faca00))
* **deps-dev:** bump testcontainers.version from 2.0.3 to 2.0.4 ([c921e93](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/c921e9329675c6cc47aec7344a9fab7221882e7b))
* **deps:** bump org.projectlombok:lombok from 1.18.42 to 1.18.44 ([981f976](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/981f976e6c39c54680873e9186fc1a0f0e24e9a5))


### Documentation

* clarify issuer allow-list scope ([b435a02](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/b435a02dd8868ae31eb0bc66ecde01b8852e5cfc))

## [0.5.1](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.5.0...v0.5.1) (2026-03-19)


### Bug Fixes

* birth_place dcql query for mDoc ([e9cfd55](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/e9cfd55681e8f11820668b69a73c9d846e0b9512))
* do not include identifying claim in dcql if doNotStoreUsers is active ([9759ae6](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/9759ae6cd3ad4c2091a7b6c17b9bf9ab13c4d375))

## [0.5.0](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.4.2...v0.5.0) (2026-03-19)


### Features

* move tests to message bundle ([cb41ba0](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/cb41ba0b0c63f50ba08b604378ac821650d1ab5a))


### Bug Fixes

* build uber-jar that packages dependencies for easier installation ([f5deae1](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/f5deae1076d03ef2762431a283f5efb87dc2582f))
* cancel SSE if session is gone ([900ec80](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/900ec809aa91a718258629d37d395ebeac500e46))
* map unresolved sub-claims to null instead of {} ([3aef48e](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/3aef48ed26b91619c2407543557a032671d9f8b9))
* remove unused scripts, simplify sse client-side ([05c0c7b](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/05c0c7b709dc4ef0a09d33db1b4cfaf1daca179d))
* session mapper didnt work correctly ([f82b5e2](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/f82b5e2c0745fdff57488c447030ef5dfdfeef22))
* use our own template to remove startSessionPolling ([128d936](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/128d936aa2d61b83b2fb310aec6545f83e7e1829))
* wallet should not be shown as alternate provider in wallet login ([2a66c72](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/2a66c723b089cc0bd8dc8178ad92bf58b4357ecf))

## [0.4.2](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.4.1...v0.4.2) (2026-03-18)


### Bug Fixes

* update to keycloak 26.5.5 ([475f8a8](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/475f8a8599f2b9f20af8d9365f9dfe9a0cbef83d))

## [0.4.1](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.4.0...v0.4.1) (2026-03-18)


### Bug Fixes

* dcql for array disclosures ([1f6be96](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/1f6be966b2b322306444b3af8afc77aa48eed503))

## [0.4.0](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.3.0...v0.4.0) (2026-03-17)


### Features

* enable transient wallet logins ([671c29a](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/671c29afc6681c36fdcf8a4a940de6278df82948))


### Dependencies

* **deps-dev:** bump net.bytebuddy:byte-buddy-agent ([098bb84](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/098bb844681b0f54dddef18014989c981dfbdce6))
* **deps-dev:** bump org.apache.maven.plugins:maven-surefire-plugin ([ab4e197](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/ab4e197e6874c78295fa75c212e05c79f8dcf886))
* **deps-dev:** bump org.mockito:mockito-core from 5.22.0 to 5.23.0 ([44368f6](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/44368f6d21156297237cb0e7f178a24dfc8ccd66))
* **deps:** bump org.sonatype.central:central-publishing-maven-plugin ([0adb663](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/0adb663cd5374d9d1a1e348b7d23fafecb1e7d63))

## [0.3.0](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.2.0...v0.3.0) (2026-03-11)


### Features

* update request handling, browser flows, and conformance coverage ([089b214](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/089b214f57327b3c692c9728e370b9a5643fe627))


### Bug Fixes

* require auth session cookie matching the request handle for login ([0bfa675](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/0bfa675d4724434313e6fad4e0128725f7fc0323))
* tighten HAIP validation and shared flow cleanup ([711cc3b](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/711cc3b1dbfa104c8fba78de269f2f7f58abd20e))


### Dependencies

* **deps-dev:** bump com.diffplug.spotless:spotless-maven-plugin ([a5f0046](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/a5f0046ac92e472fa5244993665daabc0f32fd7c))
* **deps-dev:** bump org.apache.httpcomponents.client5:httpclient5 ([a69e660](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/a69e66055d5061424d6545a3cbcfaee8c5db0122))
* **deps-dev:** bump org.junit.jupiter:junit-jupiter ([e87eca2](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/e87eca2388507a292709df0713a09dcc503fb517))
* **deps-dev:** bump org.mockito:mockito-core from 5.21.0 to 5.22.0 ([2cd08ac](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/2cd08ac99040e7fb93cc4482435ced89c9220cd3))

## [0.2.0](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.1.1...v0.2.0) (2026-03-05)


### Features

* add SIOPv2 support ([a9c9d54](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/a9c9d5486ae69997fb00966664969877dcd9792e))
* add trusted_authorities to dcql optionally ([6d18d60](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/6d18d60e27dc1a97394432233a4b4dfc868ca288))


### Bug Fixes

* advocate all allowed cred signing algs ([0aad724](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/0aad724ef0d6814f310ce9e74f0dd717a18f6f4b))
* trust list verification, cert validity checks, haip in tests ([76ecb6f](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/76ecb6f8793abde0c32f6e4a606cb8f2c40c7ef9))
* use stale trust list (max age configurable), if fetch fails ([2c7ae90](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/2c7ae90688a1dd3b5a8d88bb39bad2c93606204b))

## [0.1.1](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.1.0...v0.1.1) (2026-03-04)


### Bug Fixes

* javadoc ([50aa0c5](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/50aa0c55ad15cf72fa8d02665b5cdc8aeb0f73fd))

## [0.1.0](https://github.com/ba-itsys/keycloak-extension-oid4vp/compare/v0.0.1...v0.1.0) (2026-03-03)


### Features

* add DCQL query builder for auto-generation from mappers ([a6ec703](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/a6ec70357ba29b4ecbf27b5c18d32b1820cb5f10))
* add dev script with sandbox and oid4vc-dev support ([cf34a2f](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/cf34a2fb6465403490eaf303a0924479f4fd92cb))
* add docker-compose and ngrok for local testing ([427819a](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/427819a7168257c1589b1efdc4490ee50780d953))
* add E2E integration tests with testcontainers-oid4vc ([be9016b](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/be9016bc9a6c280d49eb312697bb869b5b243b26))
* add login form template and use Keycloak BOM for dependency management ([976634b](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/976634bf8c4a5acc10fe11dd269397582c1b26a4))
* add mDoc verification ([8ab7155](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/8ab71552635a4855d3cf57b52ead32d000a192f4))
* add OID4VP identity provider configuration model ([9c3ea79](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/9c3ea79bf3a6ddc9b1b87adc4bfd36e32199e93a))
* add OID4VP identity provider mappers ([4174b81](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/4174b81e05fa67f805cf1691b69bc2d01d736d93))
* add request object generation, storage, and QR code service ([45d6f31](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/45d6f31d013854d547a429810033e6514a934aca))
* add SD-JWT verification and VP token processing ([d86535d](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/d86535db0d1cacf6479b3139e1dba9824cff9cd4))
* add status list verification and sandbox fixes ([78caeec](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/78caeec9299085fb726fd6deb8da6d54e90082d8))
* add trust list verification and improve signature validation ([89dbda1](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/89dbda17350b0ee1c0cb48f596e99b050fd85572))
* enforce HAIP ([2d79b64](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/2d79b6473e0bb1f96a97dd90295e5436ade91b3a))
* harden security and simplify configuration ([6b4b6da](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/6b4b6da732332b26aeeb334ef8a3e234e9c01d32))
* implement core identity provider, callback endpoint, x509 auth and verifier info ([78c03f6](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/78c03f6c90603ffe7c60f9af65fda7f28cc94f9a))
* project setup with dependencies and directory structure ([cc8b920](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/cc8b92068504ad2986309b8b1a17898b2acfe061))
* support wallet_metadata / request obj enc ([00f3ecc](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/00f3ecc0e67a91349fcd96670c0803a3075b40ba))


### Bug Fixes

* multi value disclosure, cred/status list sig validation ([07be979](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/07be97925723f73f40fddaae8e446ae0b42a975e))
* review findings ([e08bf8f](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/e08bf8fc32624aedffc5ccbf045b6f6f2ad10c9a))
* session transcript validation (mdoc) ([54d3270](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/54d32700d7859bf8da2d80d9c6a8230bcc436225))
* use theme fragments and remove deprecated SSE timeout ([9beae80](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/9beae801977fc3467a32df67d8f4743c45daecb8))


### Documentation

* add README with configuration reference ([704f0ec](https://github.com/ba-itsys/keycloak-extension-oid4vp/commit/704f0ec11aedc8dab106e20d489918953ef4d2e6))

## 0.0.1 (2025-12-11)


### Miscellaneous Chores

* **ci:** initial setup ([167b97e](https://github.com/ba-itsys/keycloak-extension-wallet/commit/167b97e4392c7090c9b1ef3a25fc6d6d21c27fbf))
