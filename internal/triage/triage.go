package triage

import "time"

const MaxSnapshotsPerCase = 8

type Process struct {
	PID            int     `json:"pid"`
	PPID           int     `json:"ppid"`
	UID            int     `json:"uid"`
	LoginUID       *uint32 `json:"login_uid,omitempty"`
	SessionID      *uint32 `json:"session_id,omitempty"`
	Comm           string  `json:"comm"`
	Exe            string  `json:"exe,omitempty"`
	ExeSHA256      string  `json:"exe_sha256,omitempty"`
	ExeSize        int64   `json:"exe_size,omitempty"`
	Cgroup         string  `json:"cgroup,omitempty"`
	StartTimeTicks uint64  `json:"start_time_ticks"`
}

type Connection struct {
	Protocol    string `json:"protocol"`
	Local       string `json:"local"`
	Remote      string `json:"remote"`
	State       string `json:"state"`
	SocketInode string `json:"socket_inode"`
}

type OpenFile struct {
	FD         int       `json:"fd"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
	Inode      string    `json:"inode,omitempty"`
	Deleted    bool      `json:"deleted,omitempty"`
}

type PersistenceArtifact struct {
	Scope      string    `json:"scope"`
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	Size       int64     `json:"size,omitempty"`
	Mode       string    `json:"mode,omitempty"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	LinkTarget string    `json:"link_target,omitempty"`
}

type JournalEntry struct {
	Time          time.Time `json:"time"`
	BootID        string    `json:"boot_id,omitempty"`
	Unit          string    `json:"unit,omitempty"`
	Identifier    string    `json:"identifier,omitempty"`
	Priority      string    `json:"priority,omitempty"`
	MessageBytes  int       `json:"message_bytes,omitempty"`
	MessageSHA256 string    `json:"message_sha256,omitempty"`
}

type Snapshot struct {
	CollectedAt        time.Time             `json:"collected_at"`
	CollectedBy        string                `json:"collected_by"`
	Hostname           string                `json:"hostname"`
	FindingID          string                `json:"finding_id"`
	Process            Process               `json:"process"`
	Ancestors          []Process             `json:"ancestors,omitempty"`
	Connections        []Connection          `json:"connections,omitempty"`
	OpenFiles          []OpenFile            `json:"open_files,omitempty"`
	Persistence        []PersistenceArtifact `json:"persistence,omitempty"`
	JournalWindowStart *time.Time            `json:"journal_window_start,omitempty"`
	JournalWindowEnd   *time.Time            `json:"journal_window_end,omitempty"`
	Journal            []JournalEntry        `json:"journal,omitempty"`
	Warnings           []string              `json:"warnings,omitempty"`
}
