# **Fossil Cryptic by Fossil Logic**

**Fossil Cryptic** is a lightweight, portable cryptography library written in pure C with zero external dependencies. Designed for maximum portability and security, Fossil Cryptic provides a suite of cryptographic primitives, hash functions, and secure utilities suitable for embedded, trust-critical, and cross-platform applications. Its minimal footprint and audit-friendly codebase make it ideal for developers needing reliable, verifiable cryptography in constrained or security-sensitive environments.

### Key Features

- **Cross-Platform Support**  
  Runs seamlessly on Windows, macOS, Linux, and embedded systems without modification.

- **Zero External Dependencies**  
  Written entirely in clean, portable C to maximize auditability and ease of integration.

- **Robust Cryptographic Primitives**  
  Includes secure hash algorithms, keyed hashes, encryption helpers, and authentication mechanisms.

- **Lightweight and Efficient**  
  Optimized for minimal resource usage, making it ideal for embedded and low-power devices.

- **Self-Contained & Auditable**  
  All cryptographic operations are fully transparent and easy to review for correctness and security.

- **Modular Design**  
  Easily extendable and customizable to fit your project’s specific cryptographic requirements.

## ***Prerequisites***

To get started, ensure you have the following installed:

- **Meson Build System**: If you don’t have Meson `1.8.0` or newer installed, follow the installation instructions on the official [Meson website](https://mesonbuild.com/Getting-meson.html).
- **Conan Package Manager**: If you prefer using Conan, ensure it is installed by following the instructions on the official [Conan website](https://docs.conan.io/en/latest/installation.html).

### Adding Dependency

#### Adding via Meson Git Wrap

To add a git-wrap, place a `.wrap` file in `subprojects` with the Git repo URL and revision, then use `dependency('fossil-cryptic')` in `meson.build` so Meson can fetch and build it automatically.

#### Adding via Conan GitHub repository

 packages directly from a GitHub repository if it contains a valid `conanfile.py`.

```bash
conan install git+https://github.com/fossillogic/fossil-cryptic.git#v0.1.1 --name fossil_cryptic --build=missing
```

#### Integrate the Dependency:

Add the `fossil-cryptic.wrap` file in your `subprojects` directory and include the following content:

```ini
[wrap-git]
url = https://github.com/fossillogic/fossil-cryptic.git
revision = v0.1.1

[provide]
dependency_names = fossil-cryptic
```

**Note**: For the best experience, always use the latest releases. Visit the [releases](https://github.com/fossillogic/fossil-cryptic/releases) page for the latest versions.

## Build Configuration Options

Customize your build with the following Meson options:
	•	Enable Tests
To run the built-in test suite, configure Meson with:

```sh
meson setup builddir -Dwith_test=enabled
```

### Tests Double as Samples

The project is designed so that **test cases serve two purposes**:

- ✅ **Unit Tests** – validate the framework’s correctness.  
- 📖 **Usage Samples** – demonstrate how to use these libraries through test cases.  

This approach keeps the codebase compact and avoids redundant “hello world” style examples.  
Instead, the same code that proves correctness also teaches usage.  

This mirrors the **Meson build system** itself, which tests its own functionality by using Meson to test Meson.  
In the same way, Fossil Logic validates itself by demonstrating real-world usage in its own tests via Fossil Test.  

```bash
meson test -C builddir -v
```

Running the test suite gives you both verification and practical examples you can learn from.

## Contributing and Support

For those interested in contributing, reporting issues, or seeking support, please open an issue on the project repository or visit the [Fossil Logic Docs](https://fossillogic.com/docs) for more information. Your feedback and contributions are always welcome.