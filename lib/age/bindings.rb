# frozen_string_literal: true

require 'ffi'

module Age
  ##
  # FFI bindings for the age cgo library.
  module Bindings
    extend FFI::Library

    ffi_lib File.expand_path('../../age.so', __dir__)

    ##
    # Struct for input data to encryption/decryption functions.
    class AgeInput < FFI::Struct
      layout :data, :pointer,
             :length, :int
    end

    ##
    # Struct for output data from encryption/decryption functions.
    class AgeOutput < FFI::Struct
      layout :data, :pointer,
             :length, :pointer
    end

    ##
    # Struct for age key pairs.
    class AgeKeyPair < FFI::Struct
      layout :public_key, :pointer,
             :private_key, :pointer
    end

    attach_function :encrypt, [:string, AgeInput.by_ref, AgeOutput.by_ref, :int], :pointer
    attach_function :decrypt, [:string, AgeInput.by_ref, AgeOutput.by_ref, :int], :pointer
    attach_function :encrypt_with_passphrase, [:string, AgeInput.by_ref, AgeOutput.by_ref, :int], :pointer
    attach_function :decrypt_with_passphrase, [:string, AgeInput.by_ref, AgeOutput.by_ref, :int], :pointer
    attach_function :encrypt_with_ssh_keys, [:string, AgeInput.by_ref, AgeOutput.by_ref, :int], :pointer
    attach_function :decrypt_with_ssh_keys, [:string, AgeInput.by_ref, AgeOutput.by_ref, :int], :pointer
    attach_function :generate_keypair, [AgeKeyPair.by_ref, :int], :pointer
    attach_function :free_memory, [:pointer], :void
  end
end
