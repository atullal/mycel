# Mycel documentation

Mycel is experimental and unaudited. These documents describe what the code
does today, and say where something has only been tested in simulation or on
one kind of device.

## Using Mycel

| Document | What it covers |
|---|---|
| [User guide](USER_GUIDE.md) | installing the app, adding contacts, messages, files, calls, troubleshooting |
| [Platforms](PLATFORMS.md) | what works on each system, how it was tested, building each app |
| [Configuration](CONFIGURATION.md) | the `mycel` command and every setting |

## How it works

| Document | What it covers |
|---|---|
| [Architecture](ARCHITECTURE.md) | the layers, the vocabulary, the design decisions, status and limitations |
| [Security specification](TRUST.md) | the threat model, keys, membership, encryption formats, limits, what is not defended |
| [Routing](ROUTING.md) | how devices reach each other without a direct link, and the prior work the design draws on |

## Building on Mycel

| Document | What it covers |
|---|---|
| [Runtime API](RUNTIME_API.md) | the commands, events and types an app uses, from Rust, Tauri, HTTP and TypeScript |
| [Rules ABI](RULES_ABI.md) | writing validation rules in WebAssembly |
| [`@mycel/sdk`](../packages/sdk/README.md) | the TypeScript client and React hooks |

## Working on Mycel

| Document | What it covers |
|---|---|
| [Contributing](../CONTRIBUTING.md) | setting up, the checks to run, how changes land |
| [Testing](TESTING.md) | what CI runs, what each suite covers, results of manual and hardware tests |
| [Simulation](SIMULATION.md) | the simulator: method, models, scenarios and findings |
| [Benchmarks](BENCHMARKS.md) | store-and-forward delivery against The ONE's routers on real contact traces |
| [Changelog](../CHANGELOG.md) | what each version contains |
| [Security policy](../SECURITY.md) | reporting a vulnerability |

## Conventions

Section numbers in the security specification, the simulation report and the
benchmark report are stable, because comments in the code cite them
(`TRUST.md §6`). The other documents are linked by heading.

Spelling is British. A figure with a date beside it is a measurement taken on
that date; a figure without one is a constant in the code.
