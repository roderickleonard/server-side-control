//go:build linux

package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var fastCGIPassPattern = regexp.MustCompile(`fastcgi_pass\s+unix:/run/php/php[0-9.]+-fpm\.sock;`)
var phpExtensionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_+-]*$`)
var phpInstallCandidateVersions = []string{"7.4", "8.0", "8.1", "8.2", "8.3", "8.4"}
var phpINIByteValuePattern = regexp.MustCompile(`(?i)^\d+[kmg]?$`)
var phpININumericValuePattern = regexp.MustCompile(`^\d+$`)

type phpExtensionAlias struct {
	PackageSuffix string
	Modules       []string
}

var phpExtensionAliases = map[string]phpExtensionAlias{
	"mysql":   {PackageSuffix: "mysql", Modules: []string{"mysqli", "pdo_mysql", "mysqlnd"}},
	"pgsql":   {PackageSuffix: "pgsql", Modules: []string{"pgsql", "pdo_pgsql"}},
	"sqlite3": {PackageSuffix: "sqlite3", Modules: []string{"sqlite3", "pdo_sqlite"}},
	"xml":     {PackageSuffix: "xml", Modules: []string{"dom", "simplexml", "xml", "xmlreader", "xmlwriter"}},
}

type linuxPHPManager struct{}

func NewPHPManager() PHPManager {
	return linuxPHPManager{}
}

func (linuxPHPManager) ListAvailableVersions() ([]string, error) {
	versionSet := map[string]struct{}{}

	entries, err := os.ReadDir("/etc/php")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || !phpVersionPattern.MatchString(entry.Name()) {
				continue
			}
			if _, statErr := os.Stat(filepath.Join("/etc/php", entry.Name(), "fpm")); statErr == nil {
				versionSet[entry.Name()] = struct{}{}
			}
		}
	}

	sockets, globErr := filepath.Glob("/run/php/php*-fpm.sock")
	if globErr == nil {
		for _, socketPath := range sockets {
			name := strings.TrimSuffix(filepath.Base(socketPath), "-fpm.sock")
			name = strings.TrimPrefix(name, "php")
			if phpVersionPattern.MatchString(name) {
				versionSet[name] = struct{}{}
			}
		}
	}

	versions := make([]string, 0, len(versionSet))
	for version := range versionSet {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	return versions, nil
}

func (linuxPHPManager) ListInstallableVersions() ([]string, error) {
	versionSet := map[string]struct{}{}
	installedVersions, _ := linuxPHPManager{}.ListAvailableVersions()
	for _, version := range installedVersions {
		versionSet[version] = struct{}{}
	}
	for _, version := range phpInstallCandidateVersions {
		versionSet[version] = struct{}{}
	}
	versions := make([]string, 0, len(versionSet))
	for version := range versionSet {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	return versions, nil
}

func (linuxPHPManager) InstallVersions(versions []string) (string, error) {
	packages := make([]string, 0)
	seenPackages := make(map[string]struct{})
	for _, version := range versions {
		version = strings.TrimSpace(version)
		if !phpVersionPattern.MatchString(version) {
			return "", ErrInvalidPHPVersion
		}
		for _, packageName := range []string{"php" + version + "-fpm", "php" + version + "-cli", "php" + version + "-common"} {
			if _, ok := seenPackages[packageName]; ok {
				continue
			}
			seenPackages[packageName] = struct{}{}
			packages = append(packages, packageName)
		}
	}
	if len(packages) == 0 {
		return "", fmt.Errorf("at least one php version must be selected")
	}
	commandBody := "DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common ca-certificates lsb-release apt-transport-https && add-apt-repository -y ppa:ondrej/php && DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y " + shellJoin(packages)
	cmd := exec.Command("bash", "-lc", commandBody)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(output.String()), fmt.Errorf("php install failed: %w", err)
	}
	return strings.TrimSpace(output.String()), nil
}


func (linuxPHPManager) ListExtensionStatus(version string) (PHPExtensionStatus, error) {
	version = strings.TrimSpace(version)
	if !phpVersionPattern.MatchString(version) {
		return PHPExtensionStatus{}, ErrInvalidPHPVersion
	}
	installed, err := phpModulesForVersion(version)
	if err != nil {
		return PHPExtensionStatus{}, err
	}
	installed = expandPHPExtensionAliases(installed)
	enabled := expandPHPExtensionAliases(phpEnabledModulesForVersion(version))
	available := phpPackageModulesForVersion(version)
	return PHPExtensionStatus{Version: version, InstalledModules: installed, EnabledModules: enabled, AvailableModules: available}, nil
}

func (linuxPHPManager) InstallExtensions(spec PHPExtensionSpec) (string, error) {
	version, extensions, err := normalizePHPExtensionSpec(spec)
	if err != nil {
		return "", err
	}
	installOutput, err := ensurePHPExtensionsInstalled(version, extensions)
	if err != nil {
		return installOutput, err
	}
	enableOutput, err := enablePHPExtensions(version, extensions)
	outputParts := nonEmptyStrings([]string{installOutput, enableOutput})
	return strings.Join(nonEmptyStrings(outputParts), "\n\n"), err
}

func (linuxPHPManager) EnableExtensions(spec PHPExtensionSpec) (string, error) {
	version, extensions, err := normalizePHPExtensionSpec(spec)
	if err != nil {
		return "", err
	}
	installOutput, err := ensurePHPExtensionsInstalled(version, extensions)
	if err != nil {
		return installOutput, err
	}
	enableOutput, err := enablePHPExtensions(version, extensions)
	return strings.Join(nonEmptyStrings([]string{installOutput, enableOutput}), "\n\n"), err
}

func (linuxPHPManager) DisableExtensions(spec PHPExtensionSpec) (string, error) {
	version, extensions, err := normalizePHPExtensionSpec(spec)
	if err != nil {
		return "", err
	}
	modules, err := installedModulesForRequestedExtensions(version, extensions)
	if err != nil {
		return "", err
	}
	args := append([]string{"-v", version, "-s", "cli", "-s", "fpm"}, modules...)
	cmd := exec.Command("phpdismod", args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(output.String()), fmt.Errorf("disable php extensions failed: %w", err)
	}
	return strings.TrimSpace(output.String()), nil
}

func (linuxPHPManager) Diagnostics(version string) (PHPDiagnostics, error) {
	version = strings.TrimSpace(version)
	if !phpVersionPattern.MatchString(version) {
		return PHPDiagnostics{}, ErrInvalidPHPVersion
	}
	phpBinary := "php" + version
	cliOutput, err := exec.Command(phpBinary, "-v").CombinedOutput()
	if err != nil {
		return PHPDiagnostics{}, fmt.Errorf("read php cli version: %w", err)
	}
	moduleOutput, err := exec.Command(phpBinary, "-m").CombinedOutput()
	if err != nil {
		return PHPDiagnostics{}, fmt.Errorf("read php modules: %w", err)
	}
	infoOutput, err := exec.Command(phpBinary, "-i").CombinedOutput()
	if err != nil {
		return PHPDiagnostics{}, fmt.Errorf("read php info: %w", err)
	}
	fpmService := "php" + version + "-fpm"
	fpmOutput, _ := exec.Command("systemctl", "status", fpmService, "--no-pager", "--lines=20").CombinedOutput()
	return PHPDiagnostics{
		Version:      version,
		CLIVersion:   firstLine(string(cliOutput)),
		InfoSummary:  summarizePHPInfo(string(infoOutput)),
		ModuleOutput: strings.TrimSpace(string(moduleOutput)),
		FPMStatus:    strings.TrimSpace(string(fpmOutput)),
	}, nil
}

func (linuxPHPManager) ReadINISettings(version string) (PHPINISettings, error) {
	version = strings.TrimSpace(version)
	if !phpVersionPattern.MatchString(version) {
		return PHPINISettings{}, ErrInvalidPHPVersion
	}
	iniPath := phpINIPath(version, "fpm")
	settings := PHPINISettings{Version: version}
	var err error
	settings.MemoryLimit, err = readPHPINIValue(iniPath, "memory_limit")
	if err != nil {
		return PHPINISettings{}, err
	}
	settings.UploadMaxFilesize, err = readPHPINIValue(iniPath, "upload_max_filesize")
	if err != nil {
		return PHPINISettings{}, err
	}
	settings.PostMaxSize, err = readPHPINIValue(iniPath, "post_max_size")
	if err != nil {
		return PHPINISettings{}, err
	}
	settings.MaxExecutionTime, err = readPHPINIValue(iniPath, "max_execution_time")
	if err != nil {
		return PHPINISettings{}, err
	}
	return settings, nil
}

func (linuxPHPManager) UpdateINISettings(spec PHPINIUpdateSpec) (string, error) {
	version := strings.TrimSpace(spec.Version)
	if !phpVersionPattern.MatchString(version) {
		return "", ErrInvalidPHPVersion
	}
	settings, err := normalizePHPINIUpdateSpec(spec)
	if err != nil {
		return "", err
	}
	paths := []string{phpINIPath(version, "cli"), phpINIPath(version, "fpm")}
	updatedPaths := make([]string, 0, len(paths))
	for _, iniPath := range paths {
		if err := updatePHPINIFile(iniPath, settings); err != nil {
			return strings.Join(updatedPaths, "\n"), err
		}
		updatedPaths = append(updatedPaths, iniPath)
	}
	if output, err := exec.Command("systemctl", "restart", "php"+version+"-fpm").CombinedOutput(); err != nil {
		return strings.Join(updatedPaths, "\n"), fmt.Errorf("restart php%s-fpm failed: %w: %s", version, err, strings.TrimSpace(string(output)))
	}
	return "Updated php.ini settings:\n" + strings.Join(updatedPaths, "\n"), nil
}

func (linuxPHPManager) SwitchSiteVersion(configPath string, version string) error {
	configPath = strings.TrimSpace(configPath)
	version = strings.TrimSpace(version)
	if !filepath.IsAbs(configPath) {
		return ErrInvalidRootDirectory
	}
	if !phpVersionPattern.MatchString(version) {
		return ErrInvalidPHPVersion
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	updated := fastCGIPassPattern.ReplaceAllString(string(content), fmt.Sprintf("fastcgi_pass unix:/run/php/php%s-fpm.sock;", version))
	if updated == string(content) {
		return fmt.Errorf("no php-fpm socket declaration found in nginx config")
	}

	if err := os.WriteFile(configPath, []byte(updated), 0o644); err != nil {
		return err
	}
	if err := exec.Command("nginx", "-t").Run(); err != nil {
		_ = os.WriteFile(configPath, content, 0o644)
		return fmt.Errorf("nginx config validation failed: %w", err)
	}
	if output, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err != nil {
		_ = os.WriteFile(configPath, content, 0o644)
		return fmt.Errorf("nginx reload failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func normalizePHPExtensionSpec(spec PHPExtensionSpec) (string, []string, error) {
	version := strings.TrimSpace(spec.Version)
	if !phpVersionPattern.MatchString(version) {
		return "", nil, ErrInvalidPHPVersion
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		extension = strings.ToLower(strings.TrimSpace(extension))
		if extension == "" {
			continue
		}
		if !phpExtensionPattern.MatchString(extension) {
			return "", nil, fmt.Errorf("invalid php extension: %s", extension)
		}
		if _, ok := seen[extension]; ok {
			continue
		}
		seen[extension] = struct{}{}
		result = append(result, extension)
	}
	if len(result) == 0 {
		return "", nil, fmt.Errorf("at least one php extension must be selected")
	}
	sort.Strings(result)
	return version, result, nil
}

func normalizePHPINIUpdateSpec(spec PHPINIUpdateSpec) (PHPINIUpdateSpec, error) {
	spec.Version = strings.TrimSpace(spec.Version)
	spec.MemoryLimit = normalizePHPINIByteValue(spec.MemoryLimit)
	spec.UploadMaxFilesize = normalizePHPINIByteValue(spec.UploadMaxFilesize)
	spec.PostMaxSize = normalizePHPINIByteValue(spec.PostMaxSize)
	spec.MaxExecutionTime = strings.TrimSpace(spec.MaxExecutionTime)
	if spec.MemoryLimit == "" || !phpINIByteValuePattern.MatchString(spec.MemoryLimit) {
		return PHPINIUpdateSpec{}, fmt.Errorf("memory_limit must look like 128M or 1G")
	}
	if spec.UploadMaxFilesize == "" || !phpINIByteValuePattern.MatchString(spec.UploadMaxFilesize) {
		return PHPINIUpdateSpec{}, fmt.Errorf("upload_max_filesize must look like 64M")
	}
	if spec.PostMaxSize == "" || !phpINIByteValuePattern.MatchString(spec.PostMaxSize) {
		return PHPINIUpdateSpec{}, fmt.Errorf("post_max_size must look like 64M")
	}
	if spec.MaxExecutionTime == "" || !phpININumericValuePattern.MatchString(spec.MaxExecutionTime) {
		return PHPINIUpdateSpec{}, fmt.Errorf("max_execution_time must be numeric seconds")
	}
	return spec, nil
}

func phpModulesForVersion(version string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join("/etc/php", version, "mods-available", "*.ini"))
	if err != nil {
		return nil, err
	}
	modules := make([]string, 0, len(paths))
	for _, iniPath := range paths {
		name := moduleNameFromINI(filepath.Base(iniPath))
		if name != "" {
			modules = append(modules, name)
		}
	}
	sort.Strings(modules)
	return uniqueStrings(modules), nil
}

func phpEnabledModulesForVersion(version string) []string {
	modules := make([]string, 0)
	for _, sapi := range []string{"cli", "fpm"} {
		paths, _ := filepath.Glob(filepath.Join("/etc/php", version, sapi, "conf.d", "*.ini"))
		for _, iniPath := range paths {
			name := moduleNameFromINI(filepath.Base(iniPath))
			if name != "" {
				modules = append(modules, name)
			}
		}
	}
	sort.Strings(modules)
	return uniqueStrings(modules)
}

func phpPackageModulesForVersion(version string) []string {
	output, err := exec.Command("bash", "-lc", "apt-cache search '^php"+version+"-' 2>/dev/null | awk '{print $1}'").Output()
	if err != nil {
		return nil
	}
	ignored := map[string]struct{}{"cgi": {}, "cli": {}, "common": {}, "dev": {}, "fpm": {}, "phpdbg": {}}
	modules := make([]string, 0)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "php"+version+"-") {
			continue
		}
		module := strings.TrimPrefix(line, "php"+version+"-")
		if !phpExtensionPattern.MatchString(module) {
			continue
		}
		if _, skip := ignored[module]; skip {
			continue
		}
		modules = append(modules, module)
	}
	installed, _ := phpModulesForVersion(version)
	modules = append(modules, installed...)
	modules = append(modules, inferLogicalExtensionAliases(modules)...)
	sort.Strings(modules)
	return uniqueStrings(modules)
}

func moduleNameFromINI(fileName string) string {
	fileName = strings.TrimSpace(fileName)
	fileName = strings.TrimSuffix(fileName, ".ini")
	if index := strings.Index(fileName, "-"); index >= 0 {
		prefix := fileName[:index]
		if prefix != "" && isDigits(prefix) {
			fileName = fileName[index+1:]
		}
	}
	if !phpExtensionPattern.MatchString(fileName) {
		return ""
	}
	return fileName
}

func isDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func packageExists(packageName string) bool {
	output, err := exec.Command("bash", "-lc", "apt-cache show "+shellQuote(packageName)+" 2>/dev/null").Output()
	return err == nil && strings.TrimSpace(string(output)) != ""
}

func ensurePHPExtensionsInstalled(version string, extensions []string) (string, error) {
	installedBefore, err := phpModulesForVersion(version)
	if err != nil {
		return "", err
	}
	installedSet := sliceToSet(expandPHPExtensionAliases(installedBefore))
	packages := make([]string, 0)
	missingPackages := make([]string, 0)
	for _, extension := range extensions {
		if _, ok := installedSet[extension]; ok {
			continue
		}
		resolved := resolvePHPExtensionAlias(extension)
		packageName := "php" + version + "-" + resolved.PackageSuffix
		if packageExists(packageName) {
			packages = append(packages, packageName)
			continue
		}
		missingPackages = append(missingPackages, extension)
	}
	var outputParts []string
	if len(packages) > 0 {
		cmd := exec.Command("bash", "-lc", "DEBIAN_FRONTEND=noninteractive apt-get install -y "+shellJoin(packages))
		var installOutput bytes.Buffer
		cmd.Stdout = &installOutput
		cmd.Stderr = &installOutput
		if err := cmd.Run(); err != nil {
			return strings.TrimSpace(installOutput.String()), fmt.Errorf("php extension install failed: %w", err)
		}
		outputParts = append(outputParts, strings.TrimSpace(installOutput.String()))
	}
	modulesAfter, err := phpModulesForVersion(version)
	if err != nil {
		return strings.Join(outputParts, "\n\n"), err
	}
	modulesAfterSet := sliceToSet(expandPHPExtensionAliases(modulesAfter))
	missing := append([]string{}, missingPackages...)
	for _, extension := range extensions {
		if _, ok := modulesAfterSet[extension]; !ok {
			missing = append(missing, extension)
		}
	}
	missing = uniqueStrings(missing)
	if len(missing) > 0 {
		return strings.Join(outputParts, "\n\n"), fmt.Errorf("extensions are not available for php %s: %s", version, strings.Join(missing, ", "))
	}
	return strings.Join(nonEmptyStrings(outputParts), "\n\n"), nil
}

func enablePHPExtensions(version string, extensions []string) (string, error) {
	modules, err := installedModulesForRequestedExtensions(version, extensions)
	if err != nil {
		return "", err
	}
	args := append([]string{"-v", version, "-s", "cli", "-s", "fpm"}, modules...)
	cmd := exec.Command("phpenmod", args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(output.String()), fmt.Errorf("enable php extensions failed: %w", err)
	}
	return strings.TrimSpace(output.String()), nil
}

func resolvePHPExtensionAlias(extension string) phpExtensionAlias {
	if alias, ok := phpExtensionAliases[extension]; ok {
		return alias
	}
	return phpExtensionAlias{PackageSuffix: extension, Modules: []string{extension}}
}

func installedModulesForRequestedExtensions(version string, extensions []string) ([]string, error) {
	installed, err := phpModulesForVersion(version)
	if err != nil {
		return nil, err
	}
	installedSet := sliceToSet(installed)
	modules := make([]string, 0, len(extensions))
	missing := make([]string, 0)
	for _, extension := range extensions {
		resolved := resolvePHPExtensionAlias(extension)
		found := false
		for _, module := range resolved.Modules {
			if _, ok := installedSet[module]; ok {
				modules = append(modules, module)
				found = true
			}
		}
		if !found {
			missing = append(missing, extension)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("extensions are not installed for php %s: %s", version, strings.Join(missing, ", "))
	}
	sort.Strings(modules)
	return uniqueStrings(modules), nil
}

func expandPHPExtensionAliases(modules []string) []string {
	result := append([]string{}, modules...)
	result = append(result, inferLogicalExtensionAliases(modules)...)
	sort.Strings(result)
	return uniqueStrings(result)
}

func inferLogicalExtensionAliases(modules []string) []string {
	moduleSet := sliceToSet(modules)
	aliases := make([]string, 0)
	for aliasName, alias := range phpExtensionAliases {
		for _, module := range alias.Modules {
			if _, ok := moduleSet[module]; ok {
				aliases = append(aliases, aliasName)
				break
			}
		}
	}
	return aliases
}

func sliceToSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[strings.TrimSpace(value)] = struct{}{}
	}
	return result
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func nonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if index := strings.IndexByte(value, '\n'); index >= 0 {
		return strings.TrimSpace(value[:index])
	}
	return value
}

func summarizePHPInfo(info string) string {
	wanted := []string{
		"Loaded Configuration File",
		"Scan this dir for additional .ini files",
		"Additional .ini files parsed",
		"memory_limit",
		"upload_max_filesize",
		"post_max_size",
		"max_execution_time",
		"display_errors",
		"error_reporting",
	}
	result := make([]string, 0, len(wanted))
	lines := strings.Split(info, "\n")
	for _, wantedKey := range wanted {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, wantedKey) {
				result = append(result, trimmed)
				break
			}
		}
	}
	return strings.Join(result, "\n")
}

func phpINIPath(version string, sapi string) string {
	return filepath.Join("/etc/php", version, sapi, "php.ini")
}

func readPHPINIValue(iniPath string, key string) (string, error) {
	content, err := os.ReadFile(iniPath)
	if err != nil {
		return "", err
	}
	prefix := key + " ="
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix)), nil
		}
	}
	return "", fmt.Errorf("%s not found in %s", key, iniPath)
}

func updatePHPINIFile(iniPath string, spec PHPINIUpdateSpec) error {
	content, err := os.ReadFile(iniPath)
	if err != nil {
		return err
	}
	updated := string(content)
	updated = replaceOrAppendPHPINIValue(updated, "memory_limit", spec.MemoryLimit)
	updated = replaceOrAppendPHPINIValue(updated, "upload_max_filesize", spec.UploadMaxFilesize)
	updated = replaceOrAppendPHPINIValue(updated, "post_max_size", spec.PostMaxSize)
	updated = replaceOrAppendPHPINIValue(updated, "max_execution_time", spec.MaxExecutionTime)
	if updated == string(content) {
		return nil
	}
	return os.WriteFile(iniPath, []byte(updated), 0o644)
}

func replaceOrAppendPHPINIValue(content string, key string, value string) string {
	lines := strings.Split(content, "\n")
	replaced := false
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, key+" =") {
			lines[index] = key + " = " + value
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, key+" = "+value)
	}
	return strings.Join(lines, "\n")
}

func normalizePHPINIByteValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) == 1 {
		return strings.ToUpper(value)
	}
	return value[:len(value)-1] + strings.ToUpper(value[len(value)-1:])
}
