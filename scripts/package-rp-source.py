#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Package locked RP dependency sources and their original legal notices."""

import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.request
import xml.etree.ElementTree as ET


SUPPLEMENTS = {
    "codespan-reporting-0.11.1": ("brendanzab/codespan", "fd389a13f5bb6d625b71e2e4694b26e127f393f9", "LICENSE", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"),
    "cortex-m-rt-0.7.5": ("rust-embedded/cortex-m", "91772718fec2e07b0ccabeb019e509a53d3eecda", "LICENSE-APACHE", "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2"),
    "cortex-m-rt-macros-0.7.5": ("rust-embedded/cortex-m", "91772718fec2e07b0ccabeb019e509a53d3eecda", "LICENSE-APACHE", "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2"),
    "defmt-parser-1.0.0": ("knurling-rs/defmt", "4a8cdb44891ed57b8ff5a023b6bec7137c48708f", "LICENSE-APACHE", "8173d5c29b4f956d532781d2b86e4e30f83e6b7878dce18c919451d6ba707c90"),
    "defmt-rtt-1.3.0": ("knurling-rs/defmt", "9087a689a32aaae57c7ec2058d15d9c98c12bc81", "LICENSE-APACHE", "8173d5c29b4f956d532781d2b86e4e30f83e6b7878dce18c919451d6ba707c90"),
    "panic-probe-1.0.0": ("knurling-rs/defmt", "f6decae6e09d1216aff052aa0733a6b5e632a100", "LICENSE-APACHE", "8173d5c29b4f956d532781d2b86e4e30f83e6b7878dce18c919451d6ba707c90"),
    "usbd-hid-descriptors-0.10.0": ("twitchyliquid64/usbd-hid", "e107c099ff2e988baa31720bd6d684d5469ee8c8", "LICENSE", "4cec2a3c5484bbe8af8cc2cf73ef0b6c810e1a1f88f31ca84848705427450e40"),
    "usbd-hid-macros-0.10.0": ("twitchyliquid64/usbd-hid", "e107c099ff2e988baa31720bd6d684d5469ee8c8", "LICENSE", "4cec2a3c5484bbe8af8cc2cf73ef0b6c810e1a1f88f31ca84848705427450e40"),
    "void-1.0.2": ("reem/rust-void", "a6e061227f47ba8798b7e828ed0ac4e25382eb15", "LICENSE-MIT", "cdc52ff9219a75ecc314567c862e31a369afe276ee75884f4211cf8cbacd2667"),
}
PERMITTED = {
    "MIT", "Apache-2.0", "BSD-3-Clause", "MIT OR Apache-2.0", "Apache-2.0 OR MIT",
    "MIT/Apache-2.0", "Apache-2.0/MIT", "Apache-2.0 / MIT", "Unlicense OR MIT",
    "Unlicense/MIT", "BSD-3-Clause OR MIT OR Apache-2.0", "BSD-2-Clause OR Apache-2.0 OR MIT",
    "Zlib OR Apache-2.0 OR MIT", "(MIT OR Apache-2.0) AND Unicode-3.0",
}


def run(*args, cwd):
    return subprocess.check_output(args, cwd=cwd)


def legal(path):
    return path.name.upper().startswith(("LICENSE", "LICENCE", "NOTICE", "COPYING", "COPYRIGHT", "AUTHORS"))


def main():
    package, target, features, toolchain = sys.argv[1:]
    root = Path(__file__).resolve().parents[1]
    output = Path(package)
    if run("git", "status", "--porcelain", "--untracked-files=no", cwd=root).strip():
        raise SystemExit("Source packaging requires a clean committed source tree")
    revision = run("git", "rev-parse", "HEAD", cwd=root).decode().strip()
    metadata = json.loads(run(
        "cargo", "+" + toolchain, "metadata", "--locked",
        "--format-version", "1", "--filter-platform", target,
        "--no-default-features", "--features", features, cwd=root / "ports/rp",
    ))
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    pending = [metadata["resolve"]["root"]]
    selected = set()
    while pending:
        identity = pending.pop()
        if identity in selected:
            continue
        selected.add(identity)
        pending.extend(dep["pkg"] for dep in nodes[identity]["deps"]
                       if any(kind["kind"] != "dev" for kind in dep["dep_kinds"]))
    dependencies = sorted((item for item in metadata["packages"]
                           if item["id"] in selected and item["source"]),
                          key=lambda item: (item["name"], item["version"]))
    locked = {(item["name"], item["version"], item.get("source")): item.get("checksum")
              for item in tomllib.loads((root / "Cargo.lock").read_text())["package"]}
    records = []
    notices = []
    sysroot = Path(run("rustc", "+" + toolchain, "--print", "sysroot", cwd=root).decode().strip())
    rust_notices = sysroot / "share/doc/rust"
    shutil.copytree(rust_notices / "licenses", output / "rust-library-notices/licenses", dirs_exist_ok=True)
    shutil.copyfile(rust_notices / "COPYRIGHT-library.html", output / "rust-library-notices/COPYRIGHT-library.html")
    with tarfile.open(output / "dependency-source.tar.gz", "w:gz") as archive:
        for item in dependencies:
            directory = Path(item["manifest_path"]).parent
            name = item["name"] + "-" + item["version"]
            if item["source"].startswith("registry+"):
                crate = directory.parents[2] / "cache" / directory.parent.name / (name + ".crate")
                if hashlib.sha256(crate.read_bytes()).hexdigest() != locked[(item["name"], item["version"], item["source"])]:
                    raise SystemExit("Registry archive identity mismatch: " + name)
                files = []
                with tarfile.open(crate) as original:
                    for member in original.getmembers():
                        if member.isdir():
                            continue
                        relative = Path(member.name)
                        if not member.isfile() or relative.parts[0] != name or ".." in relative.parts or relative.is_absolute():
                            raise SystemExit("Unsafe registry archive entry: " + name)
                        path = directory.joinpath(*relative.parts[1:])
                        if path.read_bytes() != original.extractfile(member).read():
                            raise SystemExit("Registry source checksum mismatch: " + name)
                        files.append(path)
                files.sort()
            else:
                if run("git", "diff", "HEAD", "--", ".", cwd=directory).strip():
                    raise SystemExit("Modified dependency Git source: " + name)
                commit = run("git", "rev-parse", "HEAD", cwd=directory).decode().strip()
                if item["source"].rsplit("#", 1)[1] != commit:
                    raise SystemExit("Dependency Git revision mismatch: " + name)
                files = sorted(directory / relative.decode() for relative in
                               run("git", "ls-files", "-z", "--", ".", cwd=directory).split(b"\0") if relative)
            texts = [path for path in files if legal(path)]
            if item["source"].startswith("git+"):
                git_root = Path(run("git", "rev-parse", "--show-toplevel", cwd=directory).decode().strip())
                texts.extend(path for path in git_root.iterdir() if path.is_file() and legal(path) and path not in texts)
            extra = []
            if name in SUPPLEMENTS:
                repo, commit, filename, checksum = SUPPLEMENTS[name]
                url = "https://raw.githubusercontent.com/" + repo + "/" + commit + "/" + filename
                data = urllib.request.urlopen(url, timeout=60).read()
                if hashlib.sha256(data).hexdigest() != checksum:
                    raise SystemExit("Supplemental license checksum mismatch: " + name)
                extra.append((filename, data))
            if name == "unitrait-1.0.0":
                extra.append(("LICENSE-APACHE-2.0", (root / "LICENSE-APACHE-2.0").read_bytes()))
                extra.append(("NOTICE-DECLARATION", (directory / "Cargo.toml.orig").read_bytes()))
            if name == "rp2040-boot2-0.3.0":
                extra.append(("NOTICE-RP", (root / "ports/rp/NOTICE").read_bytes()))
                extra.append(("NOTICE-BOOT2", (directory / "README.md").read_bytes()))
                extra.extend(("NOTICE-" + path.name, path.read_bytes()) for path in files if path.suffix == ".S")
            if name == "rp-pac-7.0.0":
                extra.append(("NOTICE-RP", (root / "ports/rp/NOTICE").read_bytes()))
                for chip in ("rp2040", "rp235x"):
                    declaration = ET.parse(directory / ("svd/" + chip + ".svd")).getroot().findtext("licenseText")
                    if not declaration:
                        raise SystemExit("Missing SVD license declaration")
                    extra.append(("NOTICE-SVD-" + chip, declaration.encode()))
            if not (texts or extra) or item["license"] not in PERMITTED:
                raise SystemExit("Missing dependency legal material: " + name)
            digest = hashlib.sha256()
            for path in files:
                if path.is_symlink():
                    raise SystemExit("Dependency symlink requires explicit review: " + name)
                relative = path.relative_to(directory).as_posix()
                data = path.read_bytes()
                digest.update(relative.encode() + b"\0" + data + b"\0")
                info = tarfile.TarInfo(name + "/" + relative)
                info.size = len(data)
                info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                archive.addfile(info, io.BytesIO(data))
            for index, (filename, data) in enumerate([(path.name, path.read_bytes()) for path in texts] + extra):
                destination = "dependency-licenses/" + name + "/" + str(index) + "-" + filename
                info = tarfile.TarInfo(destination)
                info.size = len(data)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
                notice = output / destination
                notice.parent.mkdir(parents=True, exist_ok=True)
                notice.write_bytes(data)
            records.append({"name": item["name"], "version": item["version"],
                            "source": item["source"], "license": item["license"],
                            "registry_checksum": locked.get((item["name"], item["version"], item["source"])),
                            "supplement": SUPPLEMENTS.get(name),
                            "source_tree_sha256": digest.hexdigest()})
            notices.append(name + " | " + item["license"] + " | " + item["source"])
    (output / "DEPENDENCIES.json").write_text(json.dumps(records, indent=2) + "\n")
    (output / "THIRD-PARTY-NOTICES").write_text(
        "Original dependency terms are retained in dependency-licenses and dependency-source.tar.gz.\n"
        "This conservative build closure may include dependencies not linked into the final image.\n"
        + "\n".join(notices) + "\n")
    run("git", "archive", "--format=tar.gz", "--output=" + str(output / "manekey-source.tar.gz"), revision, cwd=root)
    (output / "SOURCE").write_text(
        "revision=" + revision + "\n"
        "manekey-source.tar.gz contains the matching project source, locks and build scripts.\n"
        "dependency-source.tar.gz contains the selected locked dependency source snapshots.\n"
        "Extract the project source and run scripts/build-rp-release.sh as described in ports/rp/README.md.\n"
        "Cargo may retrieve dependencies from their fixed sources; DEPENDENCIES.json records their identities.\n"
        "Rust, the C toolchain and UF2 converter are separate build tools, not firmware payloads.\n")
    print("Packaged dependency sources and legal notices:", len(records))


if __name__ == "__main__":
    main()
