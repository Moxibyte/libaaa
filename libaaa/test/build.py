import subprocess

if __name__ == "__main__":
    subprocess.run((
        "conan", "build", ".",
        "-of", "./build",
        "-b", "missing",
    ))

