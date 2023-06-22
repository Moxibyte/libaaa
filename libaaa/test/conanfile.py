from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain

class LibAAA_Test(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    def requirements(self):
        self.requires("gtest/cci.20210126")

    def configure(self):
        self.options["gtest"].no_main = False

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
