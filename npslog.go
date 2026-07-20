package main

import (
	"encoding/xml"
	"errors"
	"strings"
	"time"
)

// errInvalidTimestamp marks a record whose time field is missing or unparseable
// — shared by the NPS and DHCP parsers.
var errInvalidTimestamp = errors.New("invalid or missing timestamp")

// RadiusEvent is one parsed NPS accounting record. The username and MAC are
// already tokenized (UserToken/MACToken) — tokenization happens here at parse
// time so the raw Calling-Station-Id and User-Name never leave this file.
type RadiusEvent struct {
	EventTime  time.Time
	AcctStatus string // "Start", "Interim-Update", or "Stop"
	SessionID  string
	UserToken  string
	MACToken   string
	NASIP      string
}

// dtsEvent maps one line of the NPS DTS-compliant XML accounting log. Each line
// is a self-contained <Event> fragment whose children are the RADIUS/DTS
// attributes, e.g.
//
//	<Event><Timestamp data_type="4">07/08/2026 09:15:00.123</Timestamp>
//	  <User-Name data_type="1">MUIC\jdoe</User-Name>
//	  <Calling-Station-Id data_type="1">AA-BB-CC-DD-EE-FF</Calling-Station-Id>
//	  <NAS-IP-Address data_type="3">10.10.0.1</NAS-IP-Address>
//	  <Acct-Status-Type data_type="0">1</Acct-Status-Type>
//	  <Acct-Session-Id data_type="1">A1B2C3D4</Acct-Session-Id></Event>
//
// We only care about the element name and its text; the data_type attribute is
// ignored. Only DTS-XML is handled; the legacy IAS format is out of scope.
type dtsEvent struct {
	XMLName xml.Name   `xml:"Event"`
	Fields  []dtsField `xml:",any"`
}

type dtsField struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// dtsTimeLayouts are the DTS Timestamp spellings we accept. The default NPS
// format is MM/DD/YYYY HH:MM:SS.mmm; the millisecond-less form is tolerated.
// Timestamps are interpreted in the parser's *time.Location — see the LOG_TZ
// note in identity.go on log timezones.
var dtsTimeLayouts = []string{
	"01/02/2006 15:04:05.000",
	"01/02/2006 15:04:05",
}

// parseNPSLine parses one DTS-XML accounting line. The three return values
// distinguish three outcomes the caller treats differently:
//
//	err != nil            -> malformed line (count a parse error, keep going)
//	ok == false, err==nil -> a valid line we don't track (auth event, or an
//	                         accounting status other than Start/Interim/Stop) —
//	                         skip silently
//	ok == true            -> a session event to feed into the store
func parseNPSLine(line string, tok *Tokenizer, loc *time.Location) (RadiusEvent, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return RadiusEvent{}, false, nil
	}

	var ev dtsEvent
	if err := xml.Unmarshal([]byte(line), &ev); err != nil {
		return RadiusEvent{}, false, err
	}

	fields := make(map[string]string, len(ev.Fields))
	for _, f := range ev.Fields {
		fields[f.XMLName.Local] = strings.TrimSpace(f.Value)
	}

	// No Acct-Status-Type means this isn't an accounting record (e.g. an
	// Access-Request/Accept auth event). Not an error — just not ours.
	status := acctStatusName(fields["Acct-Status-Type"])
	if status == "" {
		return RadiusEvent{}, false, nil
	}

	ts, ok := parseDTSTime(fields["Timestamp"], loc)
	if !ok {
		ts, ok = parseDTSTime(fields["Event-Timestamp"], loc)
	}
	if !ok {
		return RadiusEvent{}, false, errInvalidTimestamp
	}

	return RadiusEvent{
		EventTime:  ts,
		AcctStatus: status,
		SessionID:  fields["Acct-Session-Id"],
		UserToken:  tok.UserToken(fields["User-Name"]),
		MACToken:   tok.MACToken(fields["Calling-Station-Id"]),
		NASIP:      fields["NAS-IP-Address"],
	}, true, nil
}

// acctStatusName maps a RADIUS Acct-Status-Type to the three session statuses
// we track. NPS DTS logs store the numeric RADIUS code (1/2/3); the textual
// spellings are accepted too for robustness. Codes we don't act on
// (Accounting-On=7, Accounting-Off=8, anything else) return "".
func acctStatusName(v string) string {
	switch strings.TrimSpace(v) {
	case "1", "Start":
		return "Start"
	case "2", "Stop":
		return "Stop"
	case "3", "Interim-Update", "InterimUpdate":
		return "Interim-Update"
	default:
		return ""
	}
}

func parseDTSTime(v string, loc *time.Location) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	for _, layout := range dtsTimeLayouts {
		if t, err := time.ParseInLocation(layout, v, loc); err == nil {
			// Truncate to whole seconds: the default DTS layout carries
			// milliseconds but identity_radius_events.event_time is DateTime
			// (second resolution) AND an ORDER BY key. Keeping the sub-second
			// part would let the live store order two same-second events by a
			// precision that never reaches ClickHouse, so live and cmd/trace
			// would resolve the same tie differently. Truncate() is safe here:
			// the value is wall-clock-only (no monotonic reading) and UTC-based
			// truncation of a second is zone-independent.
			return t.Truncate(time.Second), true
		}
	}
	return time.Time{}, false
}
