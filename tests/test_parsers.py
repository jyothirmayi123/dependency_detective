import json
import pytest
from backend.parsers import detect_format, parse_manifest

def parse(name, text):
    return parse_manifest(name, text)[1]

def names(items, status="exact"):
    return {(i["name"], i["version"]) for i in items if i["status"] == status}

def test_package_json_exact_vs_range_and_non_registry():
    items = parse("package.json", json.dumps({"dependencies": {"lodash": "4.17.20", "axios": "^0.21.0", "x": "git+https://h/x.git", "y": "user/repo"}}))
    assert names(items) == {("lodash", "4.17.20")}
    assert {i["name"] for i in items if i["status"] == "unresolved"} == {"axios"}
    assert {i["name"] for i in items if i["status"] == "skipped"} == {"x", "y"}

def test_package_lock_v3_tree_and_nested_resolution():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "^1"}},
        "node_modules/a/node_modules/c": {"version": "1.5.0"},      # nested copy wins for a
        "node_modules/c": {"version": "2.0.0"}, "node_modules/b": {"version": "3.0.0", "dev": True}}}
    items = {i["name"] + i["version"]: i for i in parse("package-lock.json", json.dumps(lock))}
    assert items["a1.0.0"]["direct"] is True and items["c1.5.0"]["direct"] is False
    assert items["a1.0.0"]["deps"] == [("c", "1.5.0")] and items["b3.0.0"]["scope"] == "dev"

def test_package_lock_v1():
    lock = {"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "requires": {"b": "^1"}, "dependencies": {"b": {"version": "1.1.0"}}}}}
    assert names(parse("package-lock.json", json.dumps(lock))) == {("a", "1.0.0"), ("b", "1.1.0")}

POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<properties><v>1.2.3</v></properties>
<dependencyManagement><dependencies><dependency><groupId>g</groupId><artifactId>managed</artifactId><version>9.9</version></dependency></dependencies></dependencyManagement>
<dependencies>
<dependency><groupId>g</groupId><artifactId>a</artifactId><version>${v}</version></dependency>
<dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency>
<dependency><groupId>g</groupId><artifactId>bom</artifactId></dependency>
<dependency><groupId>g</groupId><artifactId>rng</artifactId><version>[1.0,2.0)</version></dependency>
<dependency><groupId>g</groupId><artifactId>t</artifactId><version>4.0</version><scope>test</scope></dependency>
</dependencies></project>"""

def test_pom_properties_management_ranges():
    items = parse("pom.xml", POM)
    assert names(items) == {("g:a", "1.2.3"), ("g:managed", "9.9"), ("g:t", "4.0")}
    assert {i["name"] for i in items if i["status"] == "unresolved"} == {"g:bom", "g:rng"}
    assert [i for i in items if i["name"] == "g:t"][0]["scope"] == "test"

def test_pom_rejects_entity_declarations():
    with pytest.raises(ValueError):
        parse("pom.xml", '<!DOCTYPE x [<!ENTITY a "b">]><project/>')

def test_gradle_string_map_and_dynamic():
    g = """dependencies {
    implementation 'org.a:one:1.0.0'
    // implementation 'org.a:commented:1.0'
    testImplementation("org.b:two:2.0")
    api group: 'org.c', name: 'three', version: '3.0'
    implementation "org.d:dyn:1.+"
    implementation "org.e:novers"
}"""
    items = parse("build.gradle", g)
    assert names(items) == {("org.a:one", "1.0.0"), ("org.b:two", "2.0"), ("org.c:three", "3.0")}
    assert {i["name"] for i in items if i["status"] == "unresolved"} == {"org.d:dyn", "org.e:novers"}
    assert all(i["name"] != "org.a:commented" for i in items)

def test_conanfile():
    items = parse("conanfile.txt", "[requires]\nzlib/1.2.11\nopenssl/1.1.1m@user/stable\nboost/[>=1.78 <1.84]\n[tool_requires]\ncmake/3.27.0\n[generators]\nCMakeDeps\n")
    assert names(items) == {("zlib", "1.2.11"), ("openssl", "1.1.1m"), ("cmake", "3.27.0")}
    assert [i for i in items if i["name"] == "boost"][0]["status"] == "unresolved"
    assert [i for i in items if i["name"] == "cmake"][0]["scope"] == "build"

def test_conan_lock():
    assert names(parse("conan.lock", json.dumps({"requires": ["zlib/1.2.13#abc%123"], "build_requires": []}))) == {("zlib", "1.2.13")}

def test_go_mod_direct_and_indirect():
    items = parse("go.mod", "module m\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.15.0 // indirect\n\tgithub.com/a/b v1.2.3\n)\nrequire github.com/c/d v2.0.0+incompatible\n")
    d = {i["name"]: i for i in items}
    assert d["golang.org/x/net"]["direct"] is False and d["github.com/a/b"]["direct"] is True
    assert d["github.com/c/d"]["version"] == "2.0.0"

def test_cargo_lock_graph_and_sources():
    lock = """[[package]]
name = "root"
version = "0.1.0"
dependencies = ["a"]
[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["b"]
[[package]]
name = "b"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "g"
version = "0.1.0"
source = "git+https://github.com/x/g"
"""
    d = {i["name"]: i for i in parse("Cargo.lock", lock)}
    assert d["a"]["direct"] is True and d["b"]["direct"] is False and d["a"]["deps"] == [("b", "2.0.0")]
    assert d["g"]["status"] == "skipped" and "root" not in d

def test_gemfile_lock():
    lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.10-x86_64-linux)\n      racc (~> 1.4)\n    racc (1.6.2)\n\nDEPENDENCIES\n  nokogiri\n"
    d = {i["name"]: i for i in parse("Gemfile.lock", lock)}
    assert d["nokogiri"]["version"] == "1.13.10" and d["nokogiri"]["direct"] is True and d["racc"]["direct"] is False

def test_composer_lock_skips_platform_requirements():
    lock = {"packages": [{"name": "A/B", "version": "v1.2.3", "require": {"php": ">=8", "ext-json": "*", "c/d": "^1"}},
                         {"name": "c/d", "version": "dev-main"}], "packages-dev": []}
    d = {i["name"]: i for i in parse("composer.lock", json.dumps(lock))}
    assert d["a/b"]["version"] == "1.2.3" and d["a/b"]["deps"] == [("c/d", None)] and d["c/d"]["status"] == "unresolved"

def test_csproj_and_packages_config():
    cs = '<Project><ItemGroup><PackageReference Include="A" Version="1.0.0"/><PackageReference Include="B" Version="[2.0.0]"/><PackageReference Include="C" Version="3.*"/><PackageReference Include="D"/></ItemGroup></Project>'
    items = parse("x.csproj", cs)
    assert names(items) == {("a", "1.0.0"), ("b", "2.0.0")} and len([i for i in items if i["status"] == "unresolved"]) == 2
    assert names(parse("packages.config", '<packages><package id="Z" version="1.1.1"/></packages>')) == {("z", "1.1.1")}

def test_poetry_and_pipfile_lock():
    poetry = '[[package]]\nname = "Flask"\nversion = "2.2.0"\n[package.dependencies]\nwerkzeug = ">=2"\npython = "^3.8"\n[[package]]\nname = "werkzeug"\nversion = "2.2.3"\n[metadata]\ncontent-hash = "x"\n'
    d = {i["name"]: i for i in parse("poetry.lock", poetry)}
    assert d["flask"]["deps"] == [("werkzeug", None)] and d["werkzeug"]["version"] == "2.2.3"
    pip = {"_meta": {}, "default": {"requests": {"version": "==2.28.0"}}, "develop": {"pytest": {"version": "==7.0.0"}, "foo": {"git": "x"}}}
    assert names(parse("Pipfile.lock", json.dumps(pip))) == {("requests", "2.28.0"), ("pytest", "7.0.0")}

@pytest.mark.parametrize("name,text,fmt", [
    ("requirements-dev.txt", "flask==1", "requirements.txt"), ("conanfile.txt", "[requires]\nzlib/1.0", "conanfile.txt"),
    ("app.csproj", "<Project/>", "*.csproj"), ("build.gradle.kts", "", "build.gradle"), ("Cargo.lock", "", "Cargo.lock"),
    ("pasted.txt", "[requires]\nzlib/1.2.11", "conanfile.txt"),
    ("pasted", '{"lockfileVersion": 3, "packages": {}}', "package-lock.json"),
    ("pasted", "module x\n\ngo 1.21\n", "go.mod"), ("pasted", "GEM\n  remote: https://rubygems.org/\n  specs:\n", "Gemfile.lock"),
    ("pasted", '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion></project>', "pom.xml"),
])
def test_detect_format(name, text, fmt):
    assert detect_format(name, text) == fmt

def test_unknown_format_is_a_clear_error():
    with pytest.raises(ValueError, match="Could not recognise"):
        detect_format("mystery.bin", "???")

def test_bad_json_message_names_the_file():
    with pytest.raises(ValueError, match="package.json"):
        parse_manifest("package.json", "{not json")
