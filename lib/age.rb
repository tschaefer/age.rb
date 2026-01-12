# frozen_string_literal: true

require 'ffi'

require 'age/bindings'
require 'age/errors'
require 'age/version'

##
# Ruby bindings for [age](https://github.com/FiloSottile/age) using a CGO shared
# library with FFI bindings.
#
# Age is a simple, modern, and secure file encryption tool, format, and Go
# library. This gem provides a Ruby interface to age's encryption and decryption
# capabilities.
#
# Features:
#
# - Encrypt and decrypt data using age public/private key pairs
# - Encrypt and decrypt files directly
# - Generate age keypairs programmatically
# - Multiple recipients support for encryption
# - ASCII armor format support for text-safe encrypted output
# - FFI-based integration with Go's age implementation
# - Binary data handling with proper encoding
module Age
  class << self
    ##
    # Encrypts plain data using the provided age public keys.
    #
    # @param pubkeys [Array<String>] List of age public keys.
    # @param plain [Bytes] Plain data to encrypt.
    # @param armor [Boolean] Whether to armor the output.
    #
    # @return [Bytes] Encrypted data.
    def encrypt(pubkeys, plain, armor: false)
      pubkeys = pubkeys.join(',') if pubkeys.is_a?(Array)
      perform_encryption(plain) do |input, output|
        Age::Bindings.encrypt(pubkeys, input, output, armor ? 1 : 0)
      end
    end

    ## Encrypts plain data using the provided passphrase.
    #
    # @param passphrase [String] Passphrase to use for encryption.
    # @param plain [Bytes] Plain data to encrypt.
    # @param armor [Boolean] Whether to armor the output.
    #
    # @return [Bytes] Encrypted data.
    def encrypt_with_passphrase(passphrase, plain, armor: false)
      perform_encryption(plain) do |input, output|
        Age::Bindings.encrypt_with_passphrase(passphrase, input, output, armor ? 1 : 0)
      end
    end

    ##
    # Encrypts plain data using the provided SSH public keys.
    #
    # @param ssh_pubkeys [Array<String>] List of SSH public keys (ssh-rsa, ssh-ed25519).
    # @param plain [Bytes] Plain data to encrypt.
    # @param armor [Boolean] Whether to armor the output.
    #
    # @return [Bytes] Encrypted data.
    def encrypt_with_ssh_keys(ssh_pubkeys, plain, armor: false)
      ssh_pubkeys = ssh_pubkeys.join(',') if ssh_pubkeys.is_a?(Array)
      perform_encryption(plain) do |input, output|
        Age::Bindings.encrypt_with_ssh_keys(ssh_pubkeys, input, output, armor ? 1 : 0)
      end
    end

    ##
    # Decrypts encrypted data using the provided age private keys.
    #
    # @param privkeys [Array<String>] List of age private keys.
    # @param encrypted [Bytes] Encrypted data to decrypt.
    # @param armor [Boolean] Whether the input is armored.
    #
    # @return [Bytes] Decrypted plain data.
    def decrypt(privkeys, encrypted, armor: false)
      privkeys = privkeys.join(',') if privkeys.is_a?(Array)
      perform_decryption(encrypted) do |input, output|
        Age::Bindings.decrypt(privkeys, input, output, armor ? 1 : 0)
      end
    end

    ##
    # Decrypts encrypted data using the provided passphrase.
    #
    # @param passphrase [String] Passphrase to use for decryption.
    # @param encrypted [Bytes] Encrypted data to decrypt.
    # @param armor [Boolean] Whether the input is armored.
    #
    # @return [Bytes] Decrypted plain data.
    def decrypt_with_passphrase(passphrase, encrypted, armor: false)
      perform_decryption(encrypted) do |input, output|
        Age::Bindings.decrypt_with_passphrase(passphrase, input, output, armor ? 1 : 0)
      end
    end

    ##
    # Decrypts encrypted data using the provided SSH private keys.
    #
    # @param ssh_privkeys [Array<String>] List of SSH private keys (ssh-rsa, ssh-ed25519).
    # @param encrypted [Bytes] Encrypted data to decrypt.
    # @param armor [Boolean] Whether the input is armored.
    #
    # @return [Bytes] Decrypted plain data.
    def decrypt_with_ssh_keys(ssh_privkeys, encrypted, armor: false)
      ssh_privkeys = ssh_privkeys.join(',') if ssh_privkeys.is_a?(Array)
      perform_decryption(encrypted) do |input, output|
        Age::Bindings.decrypt_with_ssh_keys(ssh_privkeys, input, output, armor ? 1 : 0)
      end
    end

    ## Encrypts a file using the provided age public keys.
    #
    # @param pubkeys [Array<String>] List of age public keys.
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path. If nil, appends `.age` to infile.
    # @param armor [Boolean] Whether to armor the output.
    #
    # @return [void]
    def encrypt_file(pubkeys, infile, outfile = nil, armor: false)
      perform_file_encryption(infile, outfile) do |plain|
        encrypt(pubkeys, plain, armor:)
      end
    end

    ##
    # Encrypts a file using the provided passphrase.
    #
    # @param passphrase [String] Passphrase to use for encryption.
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path. If nil, appends `.age` to infile.
    # @param armor [Boolean] Whether to armor the output.
    #
    # @return [void]
    def encrypt_file_with_passphrase(passphrase, infile, outfile = nil, armor: false)
      perform_file_encryption(infile, outfile) do |plain|
        encrypt_with_passphrase(passphrase, plain, armor:)
      end
    end

    ##
    # Encrypts a file using the provided SSH public keys.
    #
    # @param ssh_pubkeys [Array<String>] List of SSH public keys (ssh-rsa, ssh-ed25519).
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path. If nil, appends `.age` to infile.
    # @param armor [Boolean] Whether to armor the output.
    #
    # @return [void]
    def encrypt_file_with_ssh_keys(ssh_pubkeys, infile, outfile = nil, armor: false)
      perform_file_encryption(infile, outfile) do |plain|
        encrypt_with_ssh_keys(ssh_pubkeys, plain, armor:)
      end
    end

    ## Decrypts a file using the provided age private keys.
    #
    # @param privkeys [Array<String>] List of age private keys.
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path. If nil, removes `.age` from infile.
    #
    # @return [void]
    def decrypt_file(privkeys, infile, outfile = nil)
      perform_file_decryption(infile, outfile) do |encrypted, armor|
        decrypt(privkeys, encrypted, armor:)
      end
    end

    ##
    # Decrypts a file using the provided passphrase.
    #
    # @param passphrase [String] Passphrase to use for decryption.
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path. If nil, removes `.age` from infile.
    #
    # @return [void]
    def decrypt_file_with_passphrase(passphrase, infile, outfile = nil)
      perform_file_decryption(infile, outfile) do |encrypted, armor|
        decrypt_with_passphrase(passphrase, encrypted, armor:)
      end
    end

    ##
    # Decrypts a file using the provided SSH private keys.
    #
    # @param ssh_privkeys [Array<String>] List of SSH private keys (ssh-rsa, ssh-ed25519).
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path. If nil, removes `.age` from infile.
    #
    # @return [void]
    def decrypt_file_with_ssh_keys(ssh_privkeys, infile, outfile = nil)
      perform_file_decryption(infile, outfile) do |encrypted, armor|
        decrypt_with_ssh_keys(ssh_privkeys, encrypted, armor:)
      end
    end

    ##
    # Generates a new age key pair.
    #
    # @param postquantum [Boolean] Whether to generate a post-quantum key pair.
    #
    # @return [Hash{Symbol => String}] A hash containing :public_key and :private_key.
    def generate_keypair(postquantum: false)
      pubkey_ptr = FFI::MemoryPointer.new(:pointer)
      privkey_ptr = FFI::MemoryPointer.new(:pointer)
      keypair = Age::Bindings::AgeKeyPair.new
      keypair[:public_key] = pubkey_ptr
      keypair[:private_key] = privkey_ptr

      err_ptr = Age::Bindings.generate_keypair(keypair, postquantum ? 1 : 0)
      unless err_ptr.null?
        err_msg = read_string_from_pointer(err_ptr)
        raise GenerateKeyPairError, err_msg
      end

      pubkey = read_string_from_pointer(pubkey_ptr.read_pointer)
      privkey = read_string_from_pointer(privkey_ptr.read_pointer)

      { public_key: pubkey, private_key: privkey }
    end

    ##
    # Performs encryption operation with common FFI setup.
    #
    # @param plain [Bytes] Plain data to encrypt.
    # @yield [input, output] Block that performs the actual encryption call.
    #
    # @return [Bytes] Encrypted data.
    def perform_encryption(plain)
      plain = plain.b if plain.respond_to?(:b)

      plain_ptr = FFI::MemoryPointer.new(:char, plain.bytesize)
      plain_ptr.put_bytes(0, plain)

      input = Age::Bindings::AgeInput.new
      input[:data] = plain_ptr
      input[:length] = plain.bytesize

      encrypted_ptr = FFI::MemoryPointer.new(:pointer)
      encrypted_len_ptr = FFI::MemoryPointer.new(:int)

      output = Age::Bindings::AgeOutput.new
      output[:data] = encrypted_ptr
      output[:length] = encrypted_len_ptr

      err_ptr = yield(input, output)
      unless err_ptr.null?
        err_msg = read_string_from_pointer(err_ptr)
        raise EncryptionError, err_msg
      end

      bytes = read_bytes_from_pointer(encrypted_ptr.read_pointer, encrypted_len_ptr.read_int)
      bytes.force_encoding('BINARY')
    end

    ##
    # Performs decryption operation with common FFI setup.
    #
    # @param encrypted [Bytes] Encrypted data to decrypt.
    # @yield [input, output] Block that performs the actual decryption call.
    #
    # @return [Bytes] Decrypted plain data.
    def perform_decryption(encrypted)
      encrypted = encrypted.b if encrypted.respond_to?(:b)

      encrypted_ptr = FFI::MemoryPointer.new(:char, encrypted.bytesize)
      encrypted_ptr.put_bytes(0, encrypted)

      input = Age::Bindings::AgeInput.new
      input[:data] = encrypted_ptr
      input[:length] = encrypted.bytesize

      plain_ptr = FFI::MemoryPointer.new(:pointer)
      plain_len_ptr = FFI::MemoryPointer.new(:int)

      output = Age::Bindings::AgeOutput.new
      output[:data] = plain_ptr
      output[:length] = plain_len_ptr

      err_ptr = yield(input, output)
      unless err_ptr.null?
        err_msg = read_string_from_pointer(err_ptr)
        raise DecryptionError, err_msg
      end

      bytes = read_bytes_from_pointer(plain_ptr.read_pointer, plain_len_ptr.read_int)
      bytes.force_encoding('BINARY')
    end

    ##
    # Performs file encryption with common file handling.
    #
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path.
    # @yield [plain] Block that performs the actual encryption.
    #
    # @return [void]
    def perform_file_encryption(infile, outfile)
      outfile ||= "#{infile}.age"
      plain = File.binread(infile)
      encrypted = yield(plain)
      File.binwrite(outfile, encrypted)
    end

    ##
    # Performs file decryption with common file handling and armor detection.
    #
    # @param infile [String] Input file path.
    # @param outfile [String, nil] Output file path.
    # @yield [encrypted, armor] Block that performs the actual decryption.
    #
    # @return [void]
    def perform_file_decryption(infile, outfile)
      outfile ||= File.basename(infile, '.*')
      encrypted = File.binread(infile)
      armor = detect_armor_format?(encrypted)
      plain = yield(encrypted, armor)
      File.binwrite(outfile, plain)
    end

    ##
    # Detects if the encrypted data is in armor format.
    #
    # @param encrypted [String] Encrypted data.
    #
    # @return [Boolean] True if armored, false otherwise.
    def detect_armor_format?(encrypted)
      encrypted.start_with?('-----BEGIN AGE ENCRYPTED FILE-----') &&
        encrypted.end_with?("-----END AGE ENCRYPTED FILE-----\n")
    end

    ##
    # Reads a string from a pointer and frees the memory.
    #
    # @param ptr [FFI::Pointer] Pointer to the string.
    #
    # @return [String, nil] The string read from the pointer, or nil.
    def read_string_from_pointer(ptr)
      return nil if ptr.null?

      str = ptr.read_string
      Age::Bindings.free_memory(ptr)

      str
    end

    ##
    # Reads bytes from a pointer and frees the memory.
    #
    # @param ptr [FFI::Pointer] Pointer to the bytes.
    # @param length [Integer] Length of the bytes to read.
    #
    # @return [String, nil] The bytes read from the pointer, or nil.
    def read_bytes_from_pointer(ptr, length)
      return nil if ptr.null? || length.zero?

      bytes = ptr.read_bytes(length)
      Age::Bindings.free_memory(ptr)

      bytes
    end

    private :perform_encryption, :perform_decryption, :perform_file_encryption,
            :perform_file_decryption, :detect_armor_format?,
            :read_string_from_pointer, :read_bytes_from_pointer
  end
end
