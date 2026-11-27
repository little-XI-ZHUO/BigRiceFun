"""Build BigRiceFun.

Steps:
  1. get the base jar - from --base, from the build cache, or from BIGRICEFUN_BASE_JAR
  2. compile src/main/java (JDK 8)
  3. package: every base entry is copied byte-for-byte; only the manifest's Main-Class
     changes, and com/bigricefun/*.class plus the brand icons are added
  4. verify: all base entries must be identical, otherwise the build fails
  5. assemble dist/ as a ready-to-run folder (jar, launcher, icon, dictionary example)

Needs only Python 3 and a JDK 8 (no third-party Python packages).

usage: python -I tools/build.py [--base path/to/base.jar] [--skip-dist]
"""
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "main", "java", "com", "bigricefun")
ASSETS = os.path.join(ROOT, "assets")
DIST = os.path.join(ROOT, "dist")
BUILD = os.path.join(DIST, "build")
OUT_JAR = os.path.join(DIST, "BigRiceFun.jar")

APP_NAME = "BigRiceFun"
VERSION = "1.0.0"
MAIN_CLASS = "com.bigricefun.Launch"

# Base jar: provided locally (env BIGRICEFUN_BASE_JAR, --base, or dist/base cache).
BASE_SHA256 = "5661f72dc4f4a65202d74d10db65aeef8cc2bbb9cdadd651b552aaab70c89d9b"

MANIFEST = ("Manifest-Version: 1.0\r\n"
            "Main-Class: %s\r\n"
            "Implementation-Title: %s\r\n"
            "Implementation-Version: %s\r\n"
            "\r\n" % (MAIN_CLASS, APP_NAME, VERSION))


def say(msg=""):
    print(msg, flush=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- base jar

def get_base(explicit):
    if explicit:
        with open(explicit, "rb") as fh:
            data = fh.read()
        check_base(data, explicit)
        return data

    env = os.environ.get("BIGRICEFUN_BASE_JAR")
    if env and os.path.isfile(env):
        with open(env, "rb") as fh:
            data = fh.read()
        check_base(data, env)
        return data

    cache_dir = os.path.join(DIST, "base")
    if os.path.isdir(cache_dir):
        for name in sorted(os.listdir(cache_dir)):
            if name.lower().endswith(".jar"):
                path = os.path.join(cache_dir, name)
                with open(path, "rb") as fh:
                    data = fh.read()
                if sha256(data) == BASE_SHA256:
                    say("base jar: cached " + path)
                    return data
                say("cached jar has a wrong hash, skipping: " + path)

    raise SystemExit("cannot obtain the base jar.\n"
                     "Put it in dist/base/, set BIGRICEFUN_BASE_JAR, or pass: --base <path>")


def check_base(data, where):
    got = sha256(data)
    if got != BASE_SHA256:
        raise SystemExit("%s is not the expected base jar\n  sha256 %s\n  expected %s" % (where, got, BASE_SHA256))


# ---------------------------------------------------------------- compile

def find_javac():
    cands = []
    if os.environ.get("JAVAC"):
        cands.append(os.environ["JAVAC"])
    if os.environ.get("JAVA_HOME"):
        cands.append(os.path.join(os.environ["JAVA_HOME"], "bin", "javac.exe" if os.name == "nt" else "javac"))
    for base in (r"C:\Program Files\Java", r"C:\Program Files (x86)\Java", "/usr/lib/jvm", "/usr/local"):
        if os.path.isdir(base):
            for name in sorted(os.listdir(base), reverse=True):
                if name.lower().startswith(("jdk1.8", "jdk-8", "jdk8")):
                    cands.append(os.path.join(base, name, "bin", "javac.exe" if os.name == "nt" else "javac"))
    which = shutil.which("javac")
    if which:
        cands.append(which)
    for c in cands:
        if os.path.isfile(c) or (which and c == which):
            return c
    raise SystemExit("javac not found. Install JDK 8 and set JAVA_HOME.")


def javac_version(javac):
    r = subprocess.run([javac, "-version"], capture_output=True)
    return (r.stdout + r.stderr).decode("gbk" if os.name == "nt" else "utf-8", "replace").strip()


def compile_ext(javac):
    classes = os.path.join(BUILD, "classes")
    if os.path.isdir(classes):
        shutil.rmtree(classes)
    os.makedirs(classes)
    basejar = os.path.join(BUILD, "base.jar")
    sources = sorted(os.path.join(SRC, f) for f in os.listdir(SRC) if f.endswith(".java"))
    base = [javac, "-encoding", "UTF-8", "-Xlint:-options", "-cp", basejar, "-d", classes]
    jdk8 = javac_version(javac).startswith("javac 1.8")
    flags = ["-source", "1.8", "-target", "1.8"] if jdk8 else ["--release", "8"]
    r = subprocess.run(base + flags + sources, capture_output=True)
    out = (r.stdout + r.stderr).decode("gbk" if os.name == "nt" else "utf-8", "replace")
    if r.returncode != 0:
        say(out)
        if "javafx" in out:
            say("javac cannot see JavaFX: use an Oracle/GraalJDK 8 build that bundles JavaFX, "
                "or compile with JDK 8's own javac.")
        raise SystemExit("compilation failed")
    if out.strip():
        say(out.strip())
    say("compiled %d sources" % len(sources))
    return classes


# ---------------------------------------------------------------- package + verify

def package(classes, pristine):
    zin = zipfile.ZipFile(io.BytesIO(pristine))
    out = io.BytesIO()
    icons = os.path.join(ASSETS, "icons")
    with zipfile.ZipFile(out, "w") as zout:
        for info in zin.infolist():
            if info.filename == "META-INF/MANIFEST.MF":
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zout.writestr(zi, MANIFEST.encode("utf-8"))
                continue
            zout.writestr(info, zin.read(info.filename), compress_type=info.compress_type)
        for root, _, files in os.walk(classes):
            for f in sorted(files):
                if f.endswith(".class"):
                    zout.write(os.path.join(root, f), "com/bigricefun/" + f, compress_type=zipfile.ZIP_DEFLATED)
        for f in sorted(os.listdir(icons)):
            if f.endswith(".png"):
                zout.write(os.path.join(icons, f), "brand/" + f, compress_type=zipfile.ZIP_DEFLATED)
    return out.getvalue()


def verify(new, pristine):
    a = zipfile.ZipFile(io.BytesIO(pristine))
    b = zipfile.ZipFile(io.BytesIO(new))
    old = {i.filename: (i.CRC, i.file_size) for i in a.infolist()}
    newm = {i.filename: (i.CRC, i.file_size) for i in b.infolist()}
    mf = "META-INF/MANIFEST.MF"
    missing = [n for n in old if n != mf and n not in newm]
    changed = [n for n in old if n != mf and n in newm and old[n] != newm[n]]
    added = sorted(n for n in newm if n not in old)
    bad = b.testzip()
    ok = not missing and not changed and added and bad is None
    say("base entries %d | identical %d | changed %d | missing %d"
        % (len(old), len(old) - 1 - len(changed) - len(missing), len(changed), len(missing)))
    say("added by %s: %d files" % (APP_NAME, len(added)))
    if not ok:
        raise SystemExit("VERIFY FAILED missing=%s changed=%s corrupt=%s" % (missing, changed, bad))


# ---------------------------------------------------------------- dist folder

LAUNCHER = """@echo off
rem %(name)s launcher. Needs Java 8 (JDK or JRE that bundles JavaFX).
rem The app writes its H2 result DB next to the jar, so the jar is run in place.
setlocal
set "DIR=%%~dp0"
set "JAR=%%DIR%%%(jar)s"
set "LOG=%%DIR%%%(name)s.log"
if not exist "%%JAR%%" (
    echo [!] jar not found: "%%JAR%%"
    pause
    exit /b 1
)
set "JAVAW=javaw"
where javaw >nul 2>&1
if errorlevel 1 (
    if exist "%%JAVA_HOME%%\\bin\\javaw.exe" (
        set "JAVAW=%%JAVA_HOME%%\\bin\\javaw.exe"
    ) else (
        echo [!] javaw not found. Install Java 8 ^(with JavaFX^) first.
        pause
        exit /b 1
    )
)
rem javaw = no console window. The app's console output (db path, per-result lines,
rem exceptions) is redirected to %(name)s.log instead.
start "" /b "%%JAVAW%%" -jar "%%JAR%%" > "%%LOG%%" 2>&1
endlocal
"""

SHORTCUT = """@echo off
rem Create a desktop shortcut for %(name)s with its own icon.
setlocal
set "DIR=%%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%%DIR%%create-shortcut.ps1"
if errorlevel 1 (
    echo [!] shortcut not created
    pause
    exit /b 1
)
echo shortcut created on the desktop
endlocal
"""

DICT_EXAMPLE = """# BigRiceFun 通用弱口令字典
# 用法：把这个文件改名为 BigRiceFun-dict.txt，放在 BigRiceFun.jar 同目录，重启生效。
#
# 每行一组「用户名:口令」，会替换内置的 8 组通用口令（产品专属默认口令不受影响）。
# max=N  通用字典最多试几组，默认 8。通用口令可能打到接了域账号的登录口，
#        调大之前先确认目标没有账号锁定策略。
#
# max=20
# admin:Company@2024
# test:Test@123
# root:root
"""


def assemble_dist():
    subs = {"name": APP_NAME, "jar": APP_NAME + ".jar"}
    with open(os.path.join(DIST, APP_NAME + ".bat"), "w", newline="") as fh:
        fh.write(LAUNCHER % subs)
    with open(os.path.join(DIST, "create-shortcut.bat"), "w", newline="") as fh:
        fh.write(SHORTCUT % subs)
    shutil.copy2(os.path.join(ROOT, "tools", "create-shortcut.ps1"), os.path.join(DIST, "create-shortcut.ps1"))
    with open(os.path.join(DIST, APP_NAME + "-dict.example.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(DICT_EXAMPLE)
    shutil.copy2(os.path.join(ASSETS, APP_NAME + ".ico"), os.path.join(DIST, APP_NAME + ".ico"))
    readme = os.path.join(ROOT, "README.md")
    if os.path.isfile(readme):
        shutil.copy2(readme, os.path.join(DIST, "README.md"))


def main():
    argv = sys.argv[1:]
    explicit = None
    skip_dist = False
    i = 0
    while i < len(argv):
        if argv[i] == "--base" and i + 1 < len(argv):
            explicit = argv[i + 1]
            i += 2
        elif argv[i] == "--skip-dist":
            skip_dist = True
            i += 1
        else:
            raise SystemExit("unknown argument: " + argv[i])
    say("=== %s %s build ===" % (APP_NAME, VERSION))
    pristine = get_base(explicit)
    say("base sha256 " + sha256(pristine)[:16] + "  (%.1f MB)" % (len(pristine) / 1048576))

    javac = find_javac()
    say("javac: " + javac + "  [" + javac_version(javac) + "]")
    os.makedirs(BUILD, exist_ok=True)
    with open(os.path.join(BUILD, "base.jar"), "wb") as fh:
        fh.write(pristine)
    classes = compile_ext(javac)

    data = package(classes, pristine)
    if os.path.isfile(OUT_JAR):
        os.remove(OUT_JAR)
    with open(OUT_JAR, "wb") as fh:
        fh.write(data)
    verify(data, pristine)
    say("jar %s  %.1f MB  sha256 %s" % (OUT_JAR, len(data) / 1048576, sha256(data)))
    shutil.rmtree(BUILD)

    if not skip_dist:
        assemble_dist()
        say("dist folder ready: " + DIST)
    say("=== done ===")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
