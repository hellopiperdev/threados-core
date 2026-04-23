# ThreadOS Core

**The vertical-agnostic trust layer of ThreadOS.**

ThreadOS is a privacy-first growth operating system with a modular architecture. Core handles identity, consent, events, loyalty, and audit as universal infrastructure. Vertical modules (Auto, Hospitality, and more) plug in on top to handle domain-specific integrations and workflows.

This repository contains ThreadOS Core.

## Getting Started

### Using GitHub Codespaces (Recommended)

The development environment is fully configured for GitHub Codespaces. No local installation required.

1. Click the green **Code** button at the top of this page
2. Select the **Codespaces** tab
3. Click **Create codespace on main**
4. Wait 2–3 minutes while the environment builds

When setup completes, you'll see a confirmation message in the terminal indicating the database is ready. The Codespace comes pre-configured with:

- Node.js 18
- PostgreSQL 15 (running locally, database: `threados_dev`)
- VS Code extensions for JavaScript, SQL, and formatting

### Local Development

Local development is not the recommended path for this project. Codespaces provides a consistent, fully configured environment that eliminates "works on my machine" issues. If you have a specific reason to develop locally, the `.devcontainer/setup.sh` script documents what the environment needs.

## Repository Structure

```
threados-core/
├── .devcontainer/         # Codespaces configuration
│   ├── devcontainer.json  # Environment specification
│   └── setup.sh           # One-time setup script
├── .gitignore             # Files Git should not track
├── README.md              # This file
└── THREADOS_BIBLE.md      # Foundational reference document
```

## The ThreadOS Bible

The [ThreadOS Bible](./THREADOS_BIBLE.md) is the authoritative reference for this project. It contains:

- Project vision and thesis
- Complete architectural overview
- All foundational decisions with reasoning
- Architectural principles
- Roadmap and strategic ideas
- Glossary and decision log

**Read the Bible before making architectural changes.** It captures not just what was decided, but why — and those "whys" matter.

## Status

**Current phase:** Foundation setup. The development environment is configured; core implementation has not yet begun.

## Contributing

This project is in early development. Contribution guidelines will be added as the project matures.

## License

Copyright © ThreadOS. All rights reserved.
