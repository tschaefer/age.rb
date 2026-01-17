<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo_white.svg">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
        <img alt="The age logo, a wireframe of St. Peters dome in Rome, with the text: age, file encryption" width="600" src="https://github.com/FiloSottile/age/blob/main/logo/logo.svg">
    </picture>
</p>

# age.rb: Ruby bindings for age

[![Gem Version](https://badge.fury.io/rb/age.rb.svg)](https://badge.fury.io/rb/age.rb)
[![Ruby Reference](https://img.shields.io/badge/ruby-reference-orange)](https://age.rb.tschaefer.org)
[![Contributors](https://img.shields.io/github/contributors/tschaefer/age.rb)](https://github.com/tschaefer/age.rb/graphs/contributors)
[![License](https://img.shields.io/github/license/tschaefer/age.rb)](./LICENSE)

Ruby bindings for [age](https://github.com/FiloSottile/age) using a CGO shared
library with FFI bindings.

Age is a simple, modern, and secure file encryption tool, format, and Go
library. This gem provides a Ruby interface to age's encryption and decryption
capabilities.

## Features

- **Encrypt and decrypt data** using age public/private key pairs, passphrase, and SSH keys
- **Encrypt and decrypt files** directly
- **Generate age keypairs** programmatically, optionally with post-quantum keys
- **Multiple recipients and identies** support for encryption and decryption
- **ASCII armor format** support for text-safe encrypted output
- **FFI-based** integration with Go's age implementation
- **Binary data** handling with proper encoding

## Requirements

- Go >= 1.25 (for building the Go extension)
- Ruby >= 3.2.3
- libffi-dev (for FFI support)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'age.rb'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install age.rb
```

### Building from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/tschaefer/age.rb.git
   cd age.rb
   ```

2. Install dependencies:
   ```bash
   bundle install
   ```

3. Build and install:
   ```bash
   bundle exec rake install
   ```

## Usage

```ruby
require 'age'

keypair = Age.generate_keypair(postquantum: true)
# => { public_key: "age1pq1...", private_key: "AGE-SECRET-KEY-PQ..." }

encrypted = Age.encrypt('Hello, Age!', [keypair[:public_key]], armor: true)
# => ASCII armored encrypted string

Age.decrypt(encrypted, keypair[:private_key], armor: true)
# => "Hello, Age!"
```

For further API documentation generate with YARD:

```bash
yard doc --main .index.md
```

## Development

After checking out the repo, run the following to set up your development
environment:

```bash
# Install Ruby dependencies
bundle install

# Build the Go shared library
cd ext
make
cd ..

# Start a console for experimentation
bundle exec rake console
```

### Running Tests

```bash
# Run all tests
bundle exec rake rspec
```

### Code Style

This project uses RuboCop for code style enforcement. Run:

```bash
bundle exec rake rubocop
```

## Architecture

This gem uses FFI (Foreign Function Interface) to call functions from a Go
shared library (`age.so`). The Go code wraps the
[filippo.io/age](https://filippo.io/age) package and exposes C-compatible
functions for:

- Encrypting data with age public keys, passphrases, and SSH keys (binary and ASCII armor formats)
- Decrypting data with age private keys, passphrases, and SSH keys (binary and ASCII armor formats)
- Generating age keypairs
- Memory management

The Ruby code provides a clean, idiomatic interface to these functions with
proper error handling and memory cleanup. SSH key support is provided by the
[filippo.io/age/agessh](https://pkg.go.dev/filippo.io/age/agessh) package.
ASCII armor support is provided by the
[filippo.io/age/armor](https://pkg.go.dev/filippo.io/age/armor) package.

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/tschaefer/age.rb

## License

The gem is available as open source under the terms of the
[BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause).

## Credits

- [age](https://github.com/FiloSottile/age) - The underlying encryption tool by Filippo Valsorda
- [filippo.io/age](https://filippo.io/age) - The Go age library
