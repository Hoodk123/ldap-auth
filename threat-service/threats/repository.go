package threats

import (
	"database/sql"
	"time"
)

type Threat struct {
	ID         string    `json:"id"`
	DetectedAt time.Time `json:"detected_at"`
	SourceIP   string    `json:"source_ip"`
	Username   string    `json:"username,omitempty"`
	ThreatType string    `json:"threat_type"`
	Severity   string    `json:"severity"`
	Details    string    `json:"details,omitempty"`
	Status     string    `json:"status"`
	Analyst    string    `json:"analyst,omitempty"`
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Insert(t Threat) (Threat, error) {
	query := `
		INSERT INTO threats 
			(source_ip, username, threat_type, severity, details)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, detected_at, source_ip, username, 
		          threat_type, severity, details, status, analyst`

	row := r.db.QueryRow(query,
		t.SourceIP, t.Username, t.ThreatType, t.Severity, t.Details,
	)

	var result Threat
	var username, details, analyst sql.NullString
	err := row.Scan(
		&result.ID, &result.DetectedAt, &result.SourceIP,
		&username, &result.ThreatType, &result.Severity,
		&details, &result.Status, &analyst,
	)
	if err != nil {
		return Threat{}, err
	}

	result.Username = username.String
	result.Details = details.String
	result.Analyst = analyst.String
	return result, nil
}

func (r *Repository) ListOpen() ([]Threat, error) {
	query := `
		SELECT id, detected_at, source_ip, username,
		       threat_type, severity, details, status, analyst
		FROM threats
		WHERE status IN ('OPEN', 'INVESTIGATING')
		ORDER BY detected_at DESC
		LIMIT 100`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var threats []Threat
	for rows.Next() {
		var t Threat
		var username, details, analyst sql.NullString
		err := rows.Scan(
			&t.ID, &t.DetectedAt, &t.SourceIP,
			&username, &t.ThreatType, &t.Severity,
			&details, &t.Status, &analyst,
		)
		if err != nil {
			return nil, err
		}
		t.Username = username.String
		t.Details = details.String
		t.Analyst = analyst.String
		threats = append(threats, t)
	}
	return threats, nil
}

func (r *Repository) UpdateStatus(id, status, analyst string) error {
	query := `
		UPDATE threats 
		SET status = $1, analyst = $2
		WHERE id = $3`
	_, err := r.db.Exec(query, status, analyst, id)
	return err
}