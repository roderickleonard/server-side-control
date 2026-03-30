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
var phpInstallCandidateVersions = []string{"8.1", "8.2", "8.3", "8.4"}

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
		if packageExists("php" + version + "-fpm") {
			versionSet[version] = struct{}{}
		}
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
	cmd := exec.Command("bash", "-lc", "DEBIAN_FRONTEND=noninteractive apt-get install -y "+shellJoin(packages))
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
	enabled := phpEnabledModulesForVersion(version)
	return PHPExtensionStatus{Version: version, InstalledModules: installed, EnabledModules: enabled}, nil
}

func (linuxPHPManager) InstallExtensions(spec PHPExtensionSpec) (string, error) {
	version, extensions, err := normalizePHPExtensionSpec(spec)
	if err != nil {
		return "", err
	}
	installedBefore, err := phpModulesForVersion(version)
	if err != nil {
		return "", err
	}
	installedSet := sliceToSet(installedBefore)
	packages := make([]string, 0)
	for _, extension := range extensions {
		if _, ok := installedSet[extension]; ok {
			continue
		}
		packageName := "php" + version + "-" + extension
		if packageExists(packageName) {
			packages = append(packages, packageName)
		}
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
	modulesAfterSet := sliceToSet(modulesAfter)
	missing := make([]string, 0)
	for _, extension := range extensions {
		if _, ok := modulesAfterSet[extension]; !ok {
			missing = append(missing, extension)
		}
	}
	if len(missing) > 0 {
		return strings.Join(outputParts, "\n\n"), fmt.Errorf("extensions are not available for php %s: %s", version, strings.Join(missing, ", "))
	}
	enableOutput, err := linuxPHPManager{}.EnableExtensions(PHPExtensionSpec{Version: version, Extensions: extensions})
	if enableOutput != "" {
		outputParts = append(outputParts, enableOutput)
	}
	return strings.Join(nonEmptyStrings(outputParts), "\n\n"), err
}

func (linuxPHPManager) EnableExtensions(spec PHPExtensionSpec) (string, error) {
	version, extensions, err := normalizePHPExtensionSpec(spec)
	if err != nil {
		return "", err
	}
	installed, err := phpModulesForVersion(version)
	if err != nil {
		return "", err
	}
	installedSet := sliceToSet(installed)
	missing := make([]string, 0)
	for _, extension := range extensions {
		if _, ok := installedSet[extension]; !ok {
			missing = append(missing, extension)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("extensions are not installed for php %s: %s", version, strings.Join(missing, ", "))
	}
	args := append([]string{"-v", version, "-s", "cli", "-s", "fpm"}, extensions...)
	cmd := exec.Command("phpenmod", args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(output.String()), fmt.Errorf("enable php extensions failed: %w", err)
	}
	return strings.TrimSpace(output.String()), nil
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

func moduleNameFromINI(fileName string) string {
	fileName = strings.TrimSpace(fileName)
	if strings.HasSuffix(fileName, ".ini") {
		fileName = strings.TrimSuffix(fileName, ".ini")
	}
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
