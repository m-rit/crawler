package persistance

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"kai_hiringtest/types"
	"log"
)

// inserts scan results into two tables  - scan_results and vulnerabilties
func Insertintodb(scanData []types.ScanResultWrapper) error {
	var failed bool
	for _, scan := range scanData {
		err := insertScanResult(scan)
		if err != nil {
			log.Println("Failed to insert scan result:", err)
			failed = true
			continue
		}

		for _, vuln := range scan.ScanResult.Vulnerabilities {
			err = insertVulnerability(scan.ScanResult.ScanID, vuln)
			if err != nil {
				log.Println("Failed to insert vulnerability:", err)
				continue
			}
		}
	}

	if failed {
		return errors.New("Failed to insert scan result")
	}

	return nil

}

// inserts into vulnerabilties table some of the columns that have nested objects are kept in JSONB format, rest are seperated.
func insertVulnerability(id string, vuln types.Vulnerability) error {
	log.Println("Inserted vulnerability for scan", id)

	risk_factors, _ := json.Marshal(vuln.RiskFactors)
	_, err := DB.Exec(`
		INSERT INTO vulnerabilities (id, severity, cvss, status, package_name, current_version, fixed_version,
		 description, published_date,link, risk_factors)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,	$10, $11)
		ON CONFLICT (id) DO NOTHING;`,
		vuln.ID, vuln.Severity, vuln.CVSS, vuln.Status, vuln.PackageName, vuln.CurrentVersion, vuln.FixedVersion, vuln.Description, vuln.PublishedDate, vuln.Link, risk_factors,
	)

	if err != nil {
		return err
	}

	return nil
}

// inserts into scan_results table
func insertScanResult(scanresult types.ScanResultWrapper) error {
	scan := scanresult.ScanResult

	scansummary, _ := json.Marshal(scan.Summary)
	scanmeta, _ := json.Marshal(scan.Metadata)

	_, err := DB.Exec(`
		INSERT INTO scan_results (scan_id, timestamp, scan_status, resource_type, resource_name, 
		 summary, scan_metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (scan_id) DO NOTHING;`,
		scan.ScanID, scan.Timestamp, scan.ScanStatus, scan.ResourceType, scan.ResourceName,
		scansummary, scanmeta,
	)

	return err
}

// DB is a global variable for the SQLite database connection
var DB *sql.DB

// InitDB initializes the SQLite database and creates the todos table if it doesn't exist
func InitDB() {
	log.Println("initializing database")
	var err error

	DB, err = sql.Open("sqlite3", "./app.db") // Open a connection to the SQLite database file named app.db
	if err != nil {
		log.Fatal(err) // Log an error and stop the program if the database can't be opened
	}
	//if DB.Exec("Ta")
	sqlStmt1 := `
CREATE TABLE IF NOT EXISTS scan_results (
  scan_id TEXT PRIMARY KEY,
  timestamp TEXT,
  scan_status TEXT,
  resource_type TEXT,
  resource_name TEXT,
  summary JSONB,
  scan_metadata JSONB                               
);`

	_, err = DB.Exec(sqlStmt1)
	if err != nil {
		log.Fatalf("Error creating scan_results table: %q: %s\n", err, sqlStmt1)
	}

	// Create scan_details table
	sqlStmt2 := `CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		severity TEXT NOT NULL,
		cvss NUMERIC(3,1) NOT NULL,
		status TEXT NOT NULL,
		package_name TEXT NOT NULL,
		current_version TEXT NOT NULL,
		fixed_version TEXT,
		description TEXT,
		published_date TIMESTAMP WITH TIME ZONE,
		link TEXT,
		risk_factors JSONB NOT NULL
	);`

	_, err = DB.Exec(sqlStmt2)
	if err != nil {
		log.Fatalf("Error creating scan_details table: %q: %s\n", err, sqlStmt2)

	}

	createIndexForSeverity := `
	CREATE INDEX IF NOT EXISTS idx_vulnerability_severity ON vulnerabilities (severity);
	`
	_, err = DB.Exec(createIndexForSeverity)
	if err != nil {
		log.Fatal(err)
	}

}

// queries vulnerabilties tables for queries with severity HIGH
func QueryfromDB(severity any) []types.Vulnerability {

	results := []types.Vulnerability{}
	querystringforseverity := `SELECT * FROM vulnerabilities WHERE severity = $1;`

	res, err := DB.Query(querystringforseverity, severity.(string))
	if err != nil {
		log.Fatal(err)
	}

	defer res.Close()

	for res.Next() {
		item := types.Vulnerability{}
		risk_factor := []byte{}
		err := res.Scan(&item.ID, &item.Severity, &item.CVSS, &item.Status, &item.PackageName, &item.CurrentVersion, &item.FixedVersion, &item.Description, &item.PublishedDate, &item.Link, &risk_factor)
		if err != nil {
			fmt.Println(err)
			return results
		}
		err = json.Unmarshal(risk_factor, &item.RiskFactors)
		if err != nil {
			fmt.Println(err)
			return results

		}
		log.Println("fetched", item)
		results = append(results, item)
	}

	return results

}

// only used for testing
func DropTables() {

	_, err := DB.Exec("DROP TABLE IF EXISTS " + "scan_results")
	if err != nil {
		log.Printf("Error dropping table ")
	} else {
		log.Printf("Table scan_results dropped.")
	}
	_, err = DB.Exec("DROP TABLE IF EXISTS " + "vulnerabilities")
	if err != nil {
		log.Printf("Error dropping table : %v\n", err)
	} else {
		log.Printf("Table vulnerabilites dropped.")
	}
}
