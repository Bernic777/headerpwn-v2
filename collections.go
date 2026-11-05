package main

import (
	"bufio"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed wordlists/*.txt
var wordlistFS embed.FS

//go:embed fingerprints/*.txt
var fingerprintFS embed.FS

// collabMarker is auto-replaced by Burp Collaborator when the request is
// copied/pasted through Burp. Outside Burp, use -oob <domain> to swap it.
const collabMarker = "$collabplz"

// whitelistDomain is the trusted domain used by whitelist-bypass payloads.
const whitelistDomain = "google.com"

var collectionNames = []string{"lfi", "sqli", "rce", "xxe", "xss", "ssrf", "ssti", "redirect"}

type fingerprintRule struct {
	Class    string
	Name     string
	Re       *regexp.Regexp
	Negative bool
}

type bugCollection struct {
	Name         string
	Headers      []string
	Fingerprints []fingerprintRule
}

// configDir returns the mandatory config location:
// $XDG_CONFIG_HOME/headerpwn or ~/.config/headerpwn
func configDir() (string, error) {
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "headerpwn"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "headerpwn"), nil
}

// ensureConfigFiles guarantees the wordlists/ and fingerprints/ files exist in
// the config directory. Missing files are seeded from the embedded defaults.
// Existing files are never overwritten, so user edits are preserved.
func ensureConfigFiles() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}

	wordlistsDir := filepath.Join(dir, "wordlists")
	fingerprintsDir := filepath.Join(dir, "fingerprints")
	if err := os.MkdirAll(wordlistsDir, 0o700); err != nil {
		return "", err
	}
	if err := os.MkdirAll(fingerprintsDir, 0o700); err != nil {
		return "", err
	}

	for _, name := range collectionNames {
		if err := seedFile(wordlistFS, "wordlists/"+name+".txt", filepath.Join(wordlistsDir, name+".txt")); err != nil {
			return "", err
		}
		if err := seedFile(fingerprintFS, "fingerprints/"+name+".txt", filepath.Join(fingerprintsDir, name+".txt")); err != nil {
			return "", err
		}
	}

	return dir, nil
}

func seedFile(fsys embed.FS, embeddedName, targetPath string) error {
	if _, err := os.Stat(targetPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	data, err := fsys.ReadFile(embeddedName)
	if err != nil {
		return err
	}
	return os.WriteFile(targetPath, data, 0o600)
}

func loadCollection(name, oobDomain string) (*bugCollection, error) {
	dir, err := configDir()
	if err != nil {
		return nil, err
	}

	headers, err := readHeadersFromFile(filepath.Join(dir, "wordlists", name+".txt"))
	if err != nil {
		return nil, err
	}
	if oobDomain != "" {
		for i, header := range headers {
			headers[i] = strings.ReplaceAll(header, collabMarker, oobDomain)
		}
	}

	fingerprintPath := filepath.Join(dir, "fingerprints", name+".txt")
	if _, err := os.Stat(fingerprintPath); os.IsNotExist(err) {
		// A wordlist without a fingerprint file is allowed (e.g. redirect).
		return &bugCollection{Name: name, Headers: headers}, nil
	}

	fingerprints, err := loadFingerprints(fingerprintPath)
	if err != nil {
		return nil, err
	}
	for i := range fingerprints {
		fingerprints[i].Class = name
	}

	return &bugCollection{Name: name, Headers: headers, Fingerprints: fingerprints}, nil
}

// loadFingerprints parses "name: regex" lines (or bare regex lines, where the
// regex doubles as the name). Lines starting with # are comments. A name
// prefixed with ! marks a negative rule: if it matches, every positive match
// for that response is suppressed (mirrors nuclei's negative matchers).
func loadFingerprints(path string) ([]fingerprintRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rules := make([]fingerprintRule, 0)
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name := line
		pattern := line
		if idx := strings.Index(line, ": "); idx > 0 {
			name = strings.TrimSpace(line[:idx])
			pattern = strings.TrimSpace(line[idx+1:])
		}
		if pattern == "" {
			return nil, fmt.Errorf("%s:%d: empty regex", path, lineNumber)
		}

		negative := strings.HasPrefix(name, "!")
		if negative {
			name = strings.TrimSpace(strings.TrimPrefix(name, "!"))
			if name == "" {
				name = "negative"
			}
		}

		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: invalid regex %q: %w", path, lineNumber, pattern, err)
		}
		rules = append(rules, fingerprintRule{Name: name, Re: compiled, Negative: negative})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

// listCollections prints the config directory layout and per-file counts.
func listCollections() error {
	dir, err := ensureConfigFiles()
	if err != nil {
		return err
	}

	fmt.Printf("Bug-class collections in %s:\n", dir)
	fmt.Println("(edit the files freely; delete a file to restore the default on next run)")
	for _, name := range collectionNames {
		headers, headerErr := countEntries(filepath.Join(dir, "wordlists", name+".txt"))
		patterns, patternErr := countEntries(filepath.Join(dir, "fingerprints", name+".txt"))
		if headerErr != nil || patternErr != nil {
			fmt.Printf("  %-9s wordlists/%s.txt + fingerprints/%s.txt (error reading)\n", name, name, name)
			continue
		}
		fmt.Printf("  %-9s wordlists/%s.txt (%d payloads) + fingerprints/%s.txt (%d patterns)\n", name, name, headers, name, patterns)
	}
	return nil
}

func countEntries(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimRight(scanner.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func containsCollabMarker(headers []string) bool {
	for _, header := range headers {
		if strings.Contains(header, collabMarker) {
			return true
		}
	}
	return false
}
