package market

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"fairhe/pkg/blob"
	"fairhe/pkg/chain"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// Archive keeps the deliverable blobs of accepted Case 1 claims beyond the
// retention window W on behalf of buyers (option O7, paper Appendix C.5).
// Sync follows the market's Claimed events from the block where it stopped,
// fetches each claim's blob from the network while it is retained, checks it
// against the versioned hash that the event records and stores it in Dir,
// one file per versioned hash; a cursor file keeps the next block to scan,
// so a restarted archive resumes. The archive is trusted for availability
// only: whoever reads from it checks the blob against the versioned hash
// that the ledger keeps for good, as Buyer.Await does. A Case 2 deliverable
// is in the Claimed event itself and needs no archive.
type Archive struct {
	Dir string

	mu   sync.Mutex
	next uint64
}

// ArchiveReport is the outcome of one Sync.
type ArchiveReport struct {
	Stored, Held int        // blobs stored by this Sync, and already held
	Missed       [][32]byte // blobs no longer retained when the archive got to them
}

// OpenArchive opens (or creates) the archive in dir.
func OpenArchive(dir string) (*Archive, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	a := &Archive{Dir: dir}
	if b, err := os.ReadFile(filepath.Join(dir, "cursor")); err == nil {
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("market: archive cursor: %w", err)
		}
		a.next = n
	}
	return a, nil
}

func (a *Archive) path(vh [32]byte) string {
	return filepath.Join(a.Dir, hex.EncodeToString(vh[:])+".blob")
}

// Sync stores the blobs of the claims accepted from the cursor up to the
// head block and moves the cursor past the head.
func (a *Archive) Sync(m *chain.Market, net *BlobNet) (ArchiveReport, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var rep ArchiveReport
	head, err := m.Env.BlockNumber()
	if err != nil || head < a.next {
		return rep, err
	}
	claims, err := m.Claims(a.next, head)
	if err != nil {
		return rep, err
	}
	for _, c := range claims {
		if c.VH == ([32]byte{}) {
			continue
		}
		if _, err := os.Stat(a.path(c.VH)); err == nil {
			rep.Held++
			continue
		}
		b, ok := net.Fetch(c.VH, head)
		if !ok || blob.Check(b, c.VH) != nil {
			rep.Missed = append(rep.Missed, c.VH)
			continue
		}
		if err := writeAtomic(a.path(c.VH), b[:]); err != nil {
			return rep, err
		}
		rep.Stored++
	}
	a.next = head + 1
	return rep, writeAtomic(filepath.Join(a.Dir, "cursor"), []byte(strconv.FormatUint(a.next, 10)))
}

// Fetch returns the stored blob of a versioned hash; the reader checks it
// against the versioned hash.
func (a *Archive) Fetch(vh [32]byte) (*kzg4844.Blob, bool) {
	raw, err := os.ReadFile(a.path(vh))
	var b kzg4844.Blob
	if err != nil || len(raw) != len(b) {
		return nil, false
	}
	copy(b[:], raw)
	return &b, true
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
