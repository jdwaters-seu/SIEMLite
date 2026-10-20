package ai

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Hardware is what this server has for running a model. In the Docker setup
// Ollama runs on the same server, so it is what Ollama has too.
type Hardware struct {
	CPUs   int   `json:"cpus"`
	Memory int64 `json:"memory"` // bytes, after any container limit
	// GPU is true once Ollama has run a model on a graphics card; before
	// that it is unknown, and the advice assumes none.
	GPU bool `json:"gpu"`
}

// Catalog is a model Ollama can download, and what it needs.
type Catalog struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Download int64  `json:"download"` // bytes
	Memory   int64  `json:"memory"`   // bytes of memory it needs to run
	Note     string `json:"note"`
	// MinCPUs is how many cores it needs to answer in reasonable time without a GPU.
	MinCPUs int  `json:"-"`
	GPUOnly bool `json:"-"`
}

const gb = int64(1) << 30

// LocalCatalog is the models offered for running on this server: one family,
// good at structured answers, in four sizes.
var LocalCatalog = []Catalog{
	{Name: "qwen2.5-coder:1.5b", Label: "Small", Download: 1 * gb, Memory: 3 * gb, MinCPUs: 1,
		Note: "Fastest. Fine for simple, regular lines."},
	{Name: "qwen2.5-coder:3b", Label: "Medium", Download: 2 * gb, Memory: 5 * gb, MinCPUs: 4,
		Note: "A good balance on most servers."},
	{Name: "qwen2.5-coder:7b", Label: "Large", Download: 5 * gb, Memory: 9 * gb, MinCPUs: 8,
		Note: "Better with messy or varied lines. Slow without many cores or a GPU."},
	{Name: "qwen2.5-coder:14b", Label: "Extra large", Download: 9 * gb, Memory: 16 * gb, MinCPUs: 16, GPUOnly: true,
		Note: "Best results. Needs a GPU to answer quickly."},
}

// DefaultModel is the medium model.
const DefaultModel = "qwen2.5-coder:3b"

// Recommend picks the largest model the hardware can run comfortably: it fits
// in well under the memory (SIEMLite and the database need some too) and,
// without a GPU, there are enough cores for it to answer within a minute.
func Recommend(hw Hardware) string {
	best := LocalCatalog[0].Name
	for _, c := range LocalCatalog {
		fits := hw.Memory == 0 || c.Memory <= hw.Memory*7/10
		fast := hw.GPU || (!c.GPUOnly && hw.CPUs >= c.MinCPUs)
		if fits && fast {
			best = c.Name
		}
	}
	return best
}

// DetectHardware reads the CPU count and memory, honouring container limits.
func DetectHardware() Hardware {
	hw := Hardware{CPUs: runtime.NumCPU(), Memory: memTotal()}
	if q := cgroupCPUs(); q > 0 && q < hw.CPUs {
		hw.CPUs = q
	}
	if l := cgroupMemory(); l > 0 && (hw.Memory == 0 || l < hw.Memory) {
		hw.Memory = l
	}
	return hw
}

func memTotal() int64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseInt(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// cgroupMemory is the container's memory limit (cgroup v2), or 0 for none.
func cgroupMemory() int64 {
	b, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0 // "max"
	}
	return v
}

// cgroupCPUs is the container's CPU limit (cgroup v2), rounded up, or 0 for none.
func cgroupCPUs() int {
	b, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) != 2 || f[0] == "max" {
		return 0
	}
	quota, err1 := strconv.ParseInt(f[0], 10, 64)
	period, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 != nil || err2 != nil || period <= 0 {
		return 0
	}
	return int((quota + period - 1) / period)
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
