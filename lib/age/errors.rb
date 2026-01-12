# frozen_string_literal: true

module Age
  ##
  # Custom error class for encryption errors.
  class EncryptionError < StandardError
    ##
    # @return [String, nil] reason for the encryption error
    attr_reader :reason

    def initialize(reason = nil)
      @reason = reason
      super('Encryption failed.')
    end
  end

  ##
  # Custom error class for decryption errors.
  class DecryptionError < StandardError
    ##
    # @return [String, nil] reason for the decryption error
    attr_reader :reason

    def initialize(reason = nil)
      @reason = reason
      super('Decryption failed.')
    end
  end

  ##
  # Custom error class for generate key pair errors.
  class GenerateKeyPairError < StandardError
    ##
    # @return [String, nil] reason for the key pair generation error
    attr_reader :reason

    def initialize(reason = nil)
      @reason = reason
      super('Generation key pair failed.')
    end
  end
end
