## [0.4.1] - 2026-07-29

### 🚀 Features

- *(Packet)* Add "is_secured" getter
## [0.4.0] - 2026-07-24

### 🚀 Features

- [**breaking**] Remove wildcard imports for ETSI/ IEEE standards
- *(en302636_4_1)* Add method to create `HeaderType` from `ExtendedHeader`
- *(OER)* Encode BIT STRINGs as plain bool vectors

### 🚜 Refactor

- *(standard)* Move tests to definitions
- Use arbitrary ints for reserved values
- *(decode)* Replace BitVec with plain bool vectors
- *(encode)* Replace BitVec with plain bool vectors
## [0.3.0] - 2026-07-21

### 🚀 Features

- *(ci)* Add publishing workflow
- *(Packet)* Add more getters
- *(en302636_4_1)* Build Lifetime from milliseconds
- *(en302636_4_1)* Add convenience constructors
- *(Packet)* Add getter for the payload
- *(en302636_4_1)* Implement `Display` trait for Error type
- *(CommonHeader)* Reduce flags to used value
- *(prepare-release.sh)* Always stage Cargo.toml
- *(tools)* Ignore release candidates in changelog

### 🐛 Bug Fixes

- *(validate)* Move brainpool validation away from openSSL
- *(ci)* Remove irrelevant step from job
- *(docs)* Use correct link syntax in readme.md
- *(Packet)* Add lifetime specifier to payload getters
- *(Packet)* Typo in `btp_payload` function name

### 🚜 Refactor

- Move message types from standard to own module

### 📚 Documentation

- *(validate)* Follow clippy recommendation
- Refactor and extend rust docs

### ⚙️ Miscellaneous Tasks

- Remove openssl dependency checks
- Generate first changelog
- *(ci)* Update dependencies
- Fix clippy recommendation
## [0.2.1] - 2026-01-30

### 🚀 Features

- *(test)* Don't compare JSON as strings
- *(ci)* Add basic PR pipeline

### 🐛 Bug Fixes

- Make sure individual features build

### 💼 Other

- Workaround for generic-array deprecation warning

### ⚙️ Miscellaneous Tasks

- Fix markdown formatting in doc comments
- Apply some clippy recommendations
- Fix formatting
- Bump version number
## [0.2.0] - 2025-09-19

### 🚜 Refactor

- Make UnsecuredHeader work without json feature
- Fix documentation comments

### 📚 Documentation

- *(README)* Update installation to crates.io-based install
- Fix typo in README
- *(Readme)* Remove explicit version
- Update author list

### ⚙️ Miscellaneous Tasks

- Add links for crates.io publishing
- Update dependencies
## [0.1.0] - 2024-01-09

### ⚙️ Miscellaneous Tasks

- Initial commit
