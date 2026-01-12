# frozen_string_literal: true

require 'tempfile'
require 'fileutils'

require 'age'

RSpec.describe Age do
  describe '.generate_keypair' do
    it 'returns a hash with public and private keys' do
      keypair = described_class.generate_keypair
      expect(keypair).to be_a(Hash)
      expect(keypair).to have_key(:public_key)
      expect(keypair).to have_key(:private_key)
      expect(keypair[:public_key]).to be_a(String)
      expect(keypair[:private_key]).to be_a(String)
      expect(keypair[:public_key]).not_to be_empty
      expect(keypair[:private_key]).not_to be_empty
    end
  end

  describe '.encrypt' do
    context 'with invalid recipient' do
      it 'raises an error' do
        expect { described_class.encrypt('invalid_recipient', 'Hello, World!') }
          .to raise_error(Age::EncryptionError, 'Encryption failed.')
      end
    end

    context 'with valid recipient' do
      let(:recipient) { described_class.generate_keypair[:public_key] }
      let(:plain_text) { 'Hello, World!' }

      it 'returns encrypted text' do
        encrypted = described_class.encrypt(recipient, plain_text)
        expect(encrypted).not_to eq(plain_text)
        expect(encrypted).to be_a(String)
      end
    end

    context 'with empty plain text' do
      let(:recipient) { described_class.generate_keypair[:public_key] }

      it 'returns encrypted empty string' do
        encrypted = described_class.encrypt(recipient, '')
        expect(encrypted).to be_a(String)
        expect(encrypted).not_to be_empty
      end
    end

    context 'with multiple valid recipients' do
      let(:recipients) do
        keys = []
        3.times { keys << described_class.generate_keypair[:public_key] }

        keys
      end
      let(:plain_text) { 'Hello, Multi-Recipient!' }

      it 'returns encrypted text' do
        encrypted = described_class.encrypt(recipients, plain_text)
        expect(encrypted).not_to eq(plain_text)
        expect(encrypted).to be_a(String)
      end
    end

    context 'when armored is requested' do
      let(:recipient) { described_class.generate_keypair[:public_key] }
      let(:plain_text) { 'Hello, Armored!' }

      it 'returns armored encrypted text' do
        encrypted = described_class.encrypt(recipient, plain_text, armor: true)
        expect(encrypted).to be_a(String)
        expect(encrypted).to start_with('-----BEGIN AGE ENCRYPTED FILE-----')
        expect(encrypted).to end_with("-----END AGE ENCRYPTED FILE-----\n")
      end
    end
  end

  describe '.decrypt' do
    context 'with invalid private key' do
      let(:recipient) { described_class.generate_keypair[:public_key] }
      let(:plain_text) { 'Hello, World!' }
      let(:encrypted_text) { described_class.encrypt(recipient, plain_text) }

      it 'raises an error' do
        expect { described_class.decrypt('invalid_private_key', encrypted_text) }
          .to raise_error(Age::DecryptionError, 'Decryption failed.')
      end
    end

    context 'with valid private key' do
      let(:keypair) { described_class.generate_keypair }
      let(:plain_text) { 'Hello, World!' }
      let(:encrypted_text) { described_class.encrypt(keypair[:public_key], plain_text) }

      it 'returns the original plain text' do
        decrypted = described_class.decrypt(keypair[:private_key], encrypted_text)
        expect(decrypted).to eq(plain_text)
      end
    end

    context 'when armored encrypted text is provided and armor is not requested' do
      let(:keypair) { described_class.generate_keypair }
      let(:plain_text) { 'Hello, Armored!' }
      let(:encrypted_text) do
        described_class.encrypt(keypair[:public_key], plain_text, armor: true)
      end

      it 'raises an error' do
        expect { described_class.decrypt(keypair[:private_key], encrypted_text, armor: false) }
          .to raise_error(Age::DecryptionError, 'Decryption failed.')
      end
    end

    context 'when armored encrypted text is provided and armor is requested' do
      let(:keypair) { described_class.generate_keypair }
      let(:plain_text) { 'Hello, Armored!' }
      let(:encrypted_text) do
        described_class.encrypt(keypair[:public_key], plain_text, armor: true)
      end

      it 'returns the original plain text' do
        decrypted = described_class.decrypt(keypair[:private_key], encrypted_text, armor: true)
        expect(decrypted).to eq(plain_text)
      end
    end
  end

  describe '.encrypt_file' do
    let(:recipient) { described_class.generate_keypair[:public_key] }
    let(:plain_text) { 'Hello, File!' }
    let(:input_file_path) { Tempfile.new.path }
    let(:output_file_path) { Tempfile.new.path }

    before do
      File.write(input_file_path, plain_text)
    end

    after do
      FileUtils.rm_f(input_file_path)
      FileUtils.rm_f(output_file_path)
    end

    it 'creates an encrypted file' do
      described_class.encrypt_file(recipient, input_file_path, output_file_path)
      expect(File).to exist(output_file_path)
      encrypted_content = File.read(output_file_path)
      expect(encrypted_content).not_to eq(plain_text)
    end

    it 'creates an armored encrypted file when requested' do
      described_class.encrypt_file(recipient, input_file_path, output_file_path, armor: true)
      expect(File).to exist(output_file_path)
      encrypted_content = File.read(output_file_path)
      expect(encrypted_content).to start_with('-----BEGIN AGE ENCRYPTED FILE-----')
      expect(encrypted_content).to end_with("-----END AGE ENCRYPTED FILE-----\n")
    end
  end

  describe '.decrypt_file' do
    let(:keypair) { described_class.generate_keypair }
    let(:plain_text) { 'Hello, File!' }
    let(:input_file_path) { Tempfile.new.path }
    let(:encrypted_file_path) { Tempfile.new.path }
    let(:decrypted_file_path) { Tempfile.new.path }

    before do
      File.write(input_file_path, plain_text)
      described_class.encrypt_file(keypair[:public_key], input_file_path, encrypted_file_path)
    end

    after do
      FileUtils.rm_f(input_file_path)
      FileUtils.rm_f(encrypted_file_path)
      FileUtils.rm_f(decrypted_file_path)
    end

    it 'creates a decrypted file with original content' do
      described_class.decrypt_file(keypair[:private_key], encrypted_file_path, decrypted_file_path)
      expect(File).to exist(decrypted_file_path)
      decrypted_content = File.read(decrypted_file_path)
      expect(decrypted_content).to eq(plain_text)
    end

    it 'creates a decrypted file from armored encrypted file' do
      armored_encrypted_file_path = Tempfile.new.path
      described_class.encrypt_file(keypair[:public_key], input_file_path, armored_encrypted_file_path, armor: true)

      described_class.decrypt_file(keypair[:private_key], armored_encrypted_file_path, decrypted_file_path)
      expect(File).to exist(decrypted_file_path)
      decrypted_content = File.read(decrypted_file_path)
      expect(decrypted_content).to eq(plain_text)

      FileUtils.rm_f(armored_encrypted_file_path)
    end
  end

  describe '.encrypt_with_passphrase' do
    let(:passphrase) { 'test-passphrase-123' }
    let(:plain_text) { 'Hello, Passphrase World!' }

    context 'with valid passphrase' do
      it 'returns encrypted text' do
        encrypted = described_class.encrypt_with_passphrase(passphrase, plain_text)
        expect(encrypted).not_to eq(plain_text)
        expect(encrypted).to be_a(String)
      end
    end

    context 'with empty plain text' do
      it 'returns encrypted empty string' do
        encrypted = described_class.encrypt_with_passphrase(passphrase, '')
        expect(encrypted).to be_a(String)
        expect(encrypted).not_to be_empty
      end
    end

    context 'when armored is requested' do
      it 'returns armored encrypted text' do
        encrypted = described_class.encrypt_with_passphrase(passphrase, plain_text, armor: true)
        expect(encrypted).to be_a(String)
        expect(encrypted).to start_with('-----BEGIN AGE ENCRYPTED FILE-----')
        expect(encrypted).to end_with("-----END AGE ENCRYPTED FILE-----\n")
      end
    end
  end

  describe '.decrypt_with_passphrase' do
    let(:passphrase) { 'test-passphrase-123' }
    let(:plain_text) { 'Hello, Passphrase World!' }
    let(:encrypted_text) { described_class.encrypt_with_passphrase(passphrase, plain_text) }

    context 'with correct passphrase' do
      it 'returns the original plain text' do
        decrypted = described_class.decrypt_with_passphrase(passphrase, encrypted_text)
        expect(decrypted).to eq(plain_text)
      end
    end

    context 'with incorrect passphrase' do
      it 'raises an error' do
        expect { described_class.decrypt_with_passphrase('wrong-passphrase', encrypted_text) }
          .to raise_error(Age::DecryptionError)
      end
    end

    context 'when armored encrypted text is provided and armor is not requested' do
      let(:encrypted_text) do
        described_class.encrypt_with_passphrase(passphrase, plain_text, armor: true)
      end

      it 'raises an error' do
        expect { described_class.decrypt_with_passphrase(passphrase, encrypted_text, armor: false) }
          .to raise_error(Age::DecryptionError)
      end
    end

    context 'when armored encrypted text is provided and armor is requested' do
      let(:encrypted_text) do
        described_class.encrypt_with_passphrase(passphrase, plain_text, armor: true)
      end

      it 'returns the original plain text' do
        decrypted = described_class.decrypt_with_passphrase(passphrase, encrypted_text, armor: true)
        expect(decrypted).to eq(plain_text)
      end
    end
  end

  describe '.encrypt_file_with_passphrase' do
    let(:passphrase) { 'test-passphrase-123' }
    let(:plain_text) { 'Hello, File Passphrase!' }
    let(:input_file_path) { Tempfile.new.path }
    let(:output_file_path) { Tempfile.new.path }

    before do
      File.write(input_file_path, plain_text)
    end

    after do
      FileUtils.rm_f(input_file_path)
      FileUtils.rm_f(output_file_path)
    end

    it 'creates an encrypted file' do
      described_class.encrypt_file_with_passphrase(passphrase, input_file_path, output_file_path)
      expect(File).to exist(output_file_path)
      encrypted_content = File.read(output_file_path)
      expect(encrypted_content).not_to eq(plain_text)
    end

    it 'creates an armored encrypted file when requested' do
      described_class.encrypt_file_with_passphrase(passphrase, input_file_path, output_file_path, armor: true)
      expect(File).to exist(output_file_path)
      encrypted_content = File.read(output_file_path)
      expect(encrypted_content).to start_with('-----BEGIN AGE ENCRYPTED FILE-----')
      expect(encrypted_content).to end_with("-----END AGE ENCRYPTED FILE-----\n")
    end
  end

  describe '.decrypt_file_with_passphrase' do
    let(:passphrase) { 'test-passphrase-123' }
    let(:plain_text) { 'Hello, File Passphrase!' }
    let(:input_file_path) { Tempfile.new.path }
    let(:encrypted_file_path) { Tempfile.new.path }
    let(:decrypted_file_path) { Tempfile.new.path }

    before do
      File.write(input_file_path, plain_text)
      described_class.encrypt_file_with_passphrase(passphrase, input_file_path, encrypted_file_path)
    end

    after do
      FileUtils.rm_f(input_file_path)
      FileUtils.rm_f(encrypted_file_path)
      FileUtils.rm_f(decrypted_file_path)
    end

    it 'creates a decrypted file with original content' do
      described_class.decrypt_file_with_passphrase(passphrase, encrypted_file_path, decrypted_file_path)
      expect(File).to exist(decrypted_file_path)
      decrypted_content = File.read(decrypted_file_path)
      expect(decrypted_content).to eq(plain_text)
    end

    it 'creates a decrypted file from armored encrypted file' do
      armored_encrypted_file_path = Tempfile.new.path
      described_class.encrypt_file_with_passphrase(
        passphrase, input_file_path, armored_encrypted_file_path, armor: true
      )

      described_class.decrypt_file_with_passphrase(passphrase, armored_encrypted_file_path, decrypted_file_path)
      expect(File).to exist(decrypted_file_path)
      decrypted_content = File.read(decrypted_file_path)
      expect(decrypted_content).to eq(plain_text)

      FileUtils.rm_f(armored_encrypted_file_path)
    end
  end

  describe '.encrypt_with_ssh_keys' do
    let(:ssh_pubkey) { 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINxXMNV7RGU62tGtORsJVxPOawPET3lpnXd2KnFOkpxL test@age.rb' }
    let(:plain_text) { 'Hello, SSH World!' }

    context 'with valid SSH public key' do
      it 'returns encrypted text' do
        encrypted = described_class.encrypt_with_ssh_keys(ssh_pubkey, plain_text)
        expect(encrypted).not_to eq(plain_text)
        expect(encrypted).to be_a(String)
      end
    end

    context 'with empty plain text' do
      it 'returns encrypted empty string' do
        encrypted = described_class.encrypt_with_ssh_keys(ssh_pubkey, '')
        expect(encrypted).to be_a(String)
        expect(encrypted).not_to be_empty
      end
    end

    context 'with multiple SSH public keys' do
      let(:ssh_pubkeys) { [ssh_pubkey, ssh_pubkey] }

      it 'returns encrypted text' do
        encrypted = described_class.encrypt_with_ssh_keys(ssh_pubkeys, plain_text)
        expect(encrypted).not_to eq(plain_text)
        expect(encrypted).to be_a(String)
      end
    end

    context 'when armored is requested' do
      it 'returns armored encrypted text' do
        encrypted = described_class.encrypt_with_ssh_keys(ssh_pubkey, plain_text, armor: true)
        expect(encrypted).to be_a(String)
        expect(encrypted).to start_with('-----BEGIN AGE ENCRYPTED FILE-----')
        expect(encrypted).to end_with("-----END AGE ENCRYPTED FILE-----\n")
      end
    end
  end

  describe '.decrypt_with_ssh_keys' do
    let(:ssh_pubkey) { 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINxXMNV7RGU62tGtORsJVxPOawPET3lpnXd2KnFOkpxL test@age.rb' }
    let(:ssh_privkey) do
      <<~PRIVKEY
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACDcVzDVe0RlOtrRrTkbCVcTzmsDxE95aZ13dipxTpKcSwAAAJDHMBVlxzAV
        ZQAAAAtzc2gtZWQyNTUxOQAAACDcVzDVe0RlOtrRrTkbCVcTzmsDxE95aZ13dipxTpKcSw
        AAAEDcAH56aVYt4HW/WCyhhvd7xhMX7CCgCjnwjHk+m10N8dxXMNV7RGU62tGtORsJVxPO
        awPET3lpnXd2KnFOkpxLAAAAC3Rlc3RAYWdlLnJiAQI=
        -----END OPENSSH PRIVATE KEY-----
      PRIVKEY
    end
    let(:plain_text) { 'Hello, SSH World!' }
    let(:encrypted_text) { described_class.encrypt_with_ssh_keys(ssh_pubkey, plain_text) }

    context 'with valid SSH private key' do
      it 'returns the original plain text' do
        decrypted = described_class.decrypt_with_ssh_keys(ssh_privkey, encrypted_text)
        expect(decrypted).to eq(plain_text)
      end
    end

    context 'when armored encrypted text is provided and armor is not requested' do
      let(:encrypted_text) do
        described_class.encrypt_with_ssh_keys(ssh_pubkey, plain_text, armor: true)
      end

      it 'raises an error' do
        expect { described_class.decrypt_with_ssh_keys(ssh_privkey, encrypted_text, armor: false) }
          .to raise_error(Age::DecryptionError)
      end
    end

    context 'when armored encrypted text is provided and armor is requested' do
      let(:encrypted_text) do
        described_class.encrypt_with_ssh_keys(ssh_pubkey, plain_text, armor: true)
      end

      it 'returns the original plain text' do
        decrypted = described_class.decrypt_with_ssh_keys(ssh_privkey, encrypted_text, armor: true)
        expect(decrypted).to eq(plain_text)
      end
    end
  end

  describe '.encrypt_file_with_ssh_keys' do
    let(:ssh_pubkey) { 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINxXMNV7RGU62tGtORsJVxPOawPET3lpnXd2KnFOkpxL test@age.rb' }
    let(:plain_text) { 'Hello, SSH File!' }
    let(:input_file_path) { Tempfile.new.path }
    let(:output_file_path) { Tempfile.new.path }

    before do
      File.write(input_file_path, plain_text)
    end

    after do
      FileUtils.rm_f(input_file_path)
      FileUtils.rm_f(output_file_path)
    end

    it 'creates an encrypted file' do
      described_class.encrypt_file_with_ssh_keys(ssh_pubkey, input_file_path, output_file_path)
      expect(File).to exist(output_file_path)
      encrypted_content = File.read(output_file_path)
      expect(encrypted_content).not_to eq(plain_text)
    end

    it 'creates an armored encrypted file when requested' do
      described_class.encrypt_file_with_ssh_keys(ssh_pubkey, input_file_path, output_file_path, armor: true)
      expect(File).to exist(output_file_path)
      encrypted_content = File.read(output_file_path)
      expect(encrypted_content).to start_with('-----BEGIN AGE ENCRYPTED FILE-----')
      expect(encrypted_content).to end_with("-----END AGE ENCRYPTED FILE-----\n")
    end
  end

  describe '.decrypt_file_with_ssh_keys' do
    let(:ssh_pubkey) { 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINxXMNV7RGU62tGtORsJVxPOawPET3lpnXd2KnFOkpxL test@age.rb' }
    let(:ssh_privkey) do
      <<~PRIVKEY
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACDcVzDVe0RlOtrRrTkbCVcTzmsDxE95aZ13dipxTpKcSwAAAJDHMBVlxzAV
        ZQAAAAtzc2gtZWQyNTUxOQAAACDcVzDVe0RlOtrRrTkbCVcTzmsDxE95aZ13dipxTpKcSw
        AAAEDcAH56aVYt4HW/WCyhhvd7xhMX7CCgCjnwjHk+m10N8dxXMNV7RGU62tGtORsJVxPO
        awPET3lpnXd2KnFOkpxLAAAAC3Rlc3RAYWdlLnJiAQI=
        -----END OPENSSH PRIVATE KEY-----
      PRIVKEY
    end
    let(:plain_text) { 'Hello, SSH File!' }
    let(:input_file_path) { Tempfile.new.path }
    let(:encrypted_file_path) { Tempfile.new.path }
    let(:decrypted_file_path) { Tempfile.new.path }

    before do
      File.write(input_file_path, plain_text)
      described_class.encrypt_file_with_ssh_keys(ssh_pubkey, input_file_path, encrypted_file_path)
    end

    after do
      FileUtils.rm_f(input_file_path)
      FileUtils.rm_f(encrypted_file_path)
      FileUtils.rm_f(decrypted_file_path)
    end

    it 'creates a decrypted file with original content' do
      described_class.decrypt_file_with_ssh_keys(ssh_privkey, encrypted_file_path, decrypted_file_path)
      expect(File).to exist(decrypted_file_path)
      decrypted_content = File.read(decrypted_file_path)
      expect(decrypted_content).to eq(plain_text)
    end

    it 'creates a decrypted file from armored encrypted file' do
      armored_encrypted_file_path = Tempfile.new.path
      described_class.encrypt_file_with_ssh_keys(ssh_pubkey, input_file_path, armored_encrypted_file_path, armor: true)

      described_class.decrypt_file_with_ssh_keys(ssh_privkey, armored_encrypted_file_path, decrypted_file_path)
      expect(File).to exist(decrypted_file_path)
      decrypted_content = File.read(decrypted_file_path)
      expect(decrypted_content).to eq(plain_text)

      FileUtils.rm_f(armored_encrypted_file_path)
    end
  end
end
