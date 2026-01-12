# frozen_string_literal: true

require 'mkmf'

# Check if Go is installed
go_bin = find_executable('go')
abort 'Go is required to build this gem. Please install Go from https://golang.org/dl/' unless go_bin

# Build the CGO shared library
puts 'Building CGO shared library...'
Dir.chdir(__dir__) do
  abort 'age.go not found in ext directory. The gem source files may be corrupted.' unless File.exist?('age.go')

  output_path = File.join('..', 'age.so')
  unless system(go_bin, 'build', '-o', output_path, '-buildmode=c-shared', 'age.go')
    abort 'Failed to build CGO shared library. Ensure Go is properly installed and dependencies are available.'
  end
end

# Create a dummy Makefile since we've already built the library
File.write('Makefile', <<~MAKEFILE)
  .PHONY: install clean

  install:
  \t@echo "Shared library already built"

  clean:
  \t@echo "Nothing to clean"
MAKEFILE
