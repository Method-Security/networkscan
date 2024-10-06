// This file was auto-generated by Fern from our API Definition.

package bruteforce

import (
	json "encoding/json"
	fmt "fmt"
	core "github.com/Method-Security/networkscan/generated/go/core"
	time "time"
)

type AttemptInfo struct {
	Request   *RequestUnion  `json:"request,omitempty" url:"request,omitempty"`
	Response  *ResponseUnion `json:"response,omitempty" url:"response,omitempty"`
	Result    *ResultInfo    `json:"result,omitempty" url:"result,omitempty"`
	Timestamp time.Time      `json:"timestamp" url:"timestamp"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (a *AttemptInfo) GetExtraProperties() map[string]interface{} {
	return a.extraProperties
}

func (a *AttemptInfo) UnmarshalJSON(data []byte) error {
	type embed AttemptInfo
	var unmarshaler = struct {
		embed
		Timestamp *core.DateTime `json:"timestamp"`
	}{
		embed: embed(*a),
	}
	if err := json.Unmarshal(data, &unmarshaler); err != nil {
		return err
	}
	*a = AttemptInfo(unmarshaler.embed)
	a.Timestamp = unmarshaler.Timestamp.Time()

	extraProperties, err := core.ExtractExtraProperties(data, *a)
	if err != nil {
		return err
	}
	a.extraProperties = extraProperties

	a._rawJSON = json.RawMessage(data)
	return nil
}

func (a *AttemptInfo) MarshalJSON() ([]byte, error) {
	type embed AttemptInfo
	var marshaler = struct {
		embed
		Timestamp *core.DateTime `json:"timestamp"`
	}{
		embed:     embed(*a),
		Timestamp: core.NewDateTime(a.Timestamp),
	}
	return json.Marshal(marshaler)
}

func (a *AttemptInfo) String() string {
	if len(a._rawJSON) > 0 {
		if value, err := core.StringifyJSON(a._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(a); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", a)
}

type BruteForceAttempt struct {
	Target     string          `json:"target" url:"target"`
	Statistics *StatisticsInfo `json:"statistics,omitempty" url:"statistics,omitempty"`
	Attempts   []*AttemptInfo  `json:"attempts,omitempty" url:"attempts,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (b *BruteForceAttempt) GetExtraProperties() map[string]interface{} {
	return b.extraProperties
}

func (b *BruteForceAttempt) UnmarshalJSON(data []byte) error {
	type unmarshaler BruteForceAttempt
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*b = BruteForceAttempt(value)

	extraProperties, err := core.ExtractExtraProperties(data, *b)
	if err != nil {
		return err
	}
	b.extraProperties = extraProperties

	b._rawJSON = json.RawMessage(data)
	return nil
}

func (b *BruteForceAttempt) String() string {
	if len(b._rawJSON) > 0 {
		if value, err := core.StringifyJSON(b._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(b); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", b)
}

type BruteForceReport struct {
	Module             ModuleType           `json:"module" url:"module"`
	BruteForceAttempts []*BruteForceAttempt `json:"bruteForceAttempts,omitempty" url:"bruteForceAttempts,omitempty"`
	Errors             []string             `json:"errors,omitempty" url:"errors,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (b *BruteForceReport) GetExtraProperties() map[string]interface{} {
	return b.extraProperties
}

func (b *BruteForceReport) UnmarshalJSON(data []byte) error {
	type unmarshaler BruteForceReport
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*b = BruteForceReport(value)

	extraProperties, err := core.ExtractExtraProperties(data, *b)
	if err != nil {
		return err
	}
	b.extraProperties = extraProperties

	b._rawJSON = json.RawMessage(data)
	return nil
}

func (b *BruteForceReport) String() string {
	if len(b._rawJSON) > 0 {
		if value, err := core.StringifyJSON(b._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(b); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", b)
}

type BruteForceRunConfig struct {
	Module           ModuleType `json:"module" url:"module"`
	Targets          []string   `json:"targets,omitempty" url:"targets,omitempty"`
	Usernames        []string   `json:"usernames,omitempty" url:"usernames,omitempty"`
	Passwords        []string   `json:"passwords,omitempty" url:"passwords,omitempty"`
	Timeout          int        `json:"timeout" url:"timeout"`
	Sleep            int        `json:"sleep" url:"sleep"`
	Retries          int        `json:"retries" url:"retries"`
	SuccessfulOnly   bool       `json:"successfulOnly" url:"successfulOnly"`
	StopFirstSuccess bool       `json:"stopFirstSuccess" url:"stopFirstSuccess"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (b *BruteForceRunConfig) GetExtraProperties() map[string]interface{} {
	return b.extraProperties
}

func (b *BruteForceRunConfig) UnmarshalJSON(data []byte) error {
	type unmarshaler BruteForceRunConfig
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*b = BruteForceRunConfig(value)

	extraProperties, err := core.ExtractExtraProperties(data, *b)
	if err != nil {
		return err
	}
	b.extraProperties = extraProperties

	b._rawJSON = json.RawMessage(data)
	return nil
}

func (b *BruteForceRunConfig) String() string {
	if len(b._rawJSON) > 0 {
		if value, err := core.StringifyJSON(b._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(b); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", b)
}

type CredentialPair struct {
	Username string `json:"username" url:"username"`
	Password string `json:"password" url:"password"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (c *CredentialPair) GetExtraProperties() map[string]interface{} {
	return c.extraProperties
}

func (c *CredentialPair) UnmarshalJSON(data []byte) error {
	type unmarshaler CredentialPair
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*c = CredentialPair(value)

	extraProperties, err := core.ExtractExtraProperties(data, *c)
	if err != nil {
		return err
	}
	c.extraProperties = extraProperties

	c._rawJSON = json.RawMessage(data)
	return nil
}

func (c *CredentialPair) String() string {
	if len(c._rawJSON) > 0 {
		if value, err := core.StringifyJSON(c._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(c); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", c)
}

type ModuleType string

const (
	ModuleTypeSsh    ModuleType = "ssh"
	ModuleTypeTelnet ModuleType = "telnet"
)

func NewModuleTypeFromString(s string) (ModuleType, error) {
	switch s {
	case "ssh":
		return ModuleTypeSsh, nil
	case "telnet":
		return ModuleTypeTelnet, nil
	}
	var t ModuleType
	return "", fmt.Errorf("%s is not a valid %T", s, t)
}

func (m ModuleType) Ptr() *ModuleType {
	return &m
}

type RequestUnion struct {
	Type           string
	GeneralRequest *GeneralRequestInfo
}

func NewRequestUnionFromGeneralRequest(value *GeneralRequestInfo) *RequestUnion {
	return &RequestUnion{Type: "generalRequest", GeneralRequest: value}
}

func (r *RequestUnion) UnmarshalJSON(data []byte) error {
	var unmarshaler struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &unmarshaler); err != nil {
		return err
	}
	r.Type = unmarshaler.Type
	if unmarshaler.Type == "" {
		return fmt.Errorf("%T did not include discriminant type", r)
	}
	switch unmarshaler.Type {
	case "generalRequest":
		value := new(GeneralRequestInfo)
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		r.GeneralRequest = value
	}
	return nil
}

func (r RequestUnion) MarshalJSON() ([]byte, error) {
	switch r.Type {
	default:
		return nil, fmt.Errorf("invalid type %s in %T", r.Type, r)
	case "generalRequest":
		return core.MarshalJSONWithExtraProperty(r.GeneralRequest, "type", "generalRequest")
	}
}

type RequestUnionVisitor interface {
	VisitGeneralRequest(*GeneralRequestInfo) error
}

func (r *RequestUnion) Accept(visitor RequestUnionVisitor) error {
	switch r.Type {
	default:
		return fmt.Errorf("invalid type %s in %T", r.Type, r)
	case "generalRequest":
		return visitor.VisitGeneralRequest(r.GeneralRequest)
	}
}

type ResponseUnion struct {
	Type            string
	GeneralResponse *GeneralResponseInfo
}

func NewResponseUnionFromGeneralResponse(value *GeneralResponseInfo) *ResponseUnion {
	return &ResponseUnion{Type: "generalResponse", GeneralResponse: value}
}

func (r *ResponseUnion) UnmarshalJSON(data []byte) error {
	var unmarshaler struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &unmarshaler); err != nil {
		return err
	}
	r.Type = unmarshaler.Type
	if unmarshaler.Type == "" {
		return fmt.Errorf("%T did not include discriminant type", r)
	}
	switch unmarshaler.Type {
	case "generalResponse":
		value := new(GeneralResponseInfo)
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		r.GeneralResponse = value
	}
	return nil
}

func (r ResponseUnion) MarshalJSON() ([]byte, error) {
	switch r.Type {
	default:
		return nil, fmt.Errorf("invalid type %s in %T", r.Type, r)
	case "generalResponse":
		return core.MarshalJSONWithExtraProperty(r.GeneralResponse, "type", "generalResponse")
	}
}

type ResponseUnionVisitor interface {
	VisitGeneralResponse(*GeneralResponseInfo) error
}

func (r *ResponseUnion) Accept(visitor ResponseUnionVisitor) error {
	switch r.Type {
	default:
		return fmt.Errorf("invalid type %s in %T", r.Type, r)
	case "generalResponse":
		return visitor.VisitGeneralResponse(r.GeneralResponse)
	}
}

type ResultInfo struct {
	Login     bool `json:"login" url:"login"`
	Ratelimit bool `json:"ratelimit" url:"ratelimit"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (r *ResultInfo) GetExtraProperties() map[string]interface{} {
	return r.extraProperties
}

func (r *ResultInfo) UnmarshalJSON(data []byte) error {
	type unmarshaler ResultInfo
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*r = ResultInfo(value)

	extraProperties, err := core.ExtractExtraProperties(data, *r)
	if err != nil {
		return err
	}
	r.extraProperties = extraProperties

	r._rawJSON = json.RawMessage(data)
	return nil
}

func (r *ResultInfo) String() string {
	if len(r._rawJSON) > 0 {
		if value, err := core.StringifyJSON(r._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(r); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", r)
}

type StatisticsInfo struct {
	NumUsernames  int                  `json:"numUsernames" url:"numUsernames"`
	NumPasswords  int                  `json:"numPasswords" url:"numPasswords"`
	NumSuccessful int                  `json:"numSuccessful" url:"numSuccessful"`
	NumFailed     int                  `json:"numFailed" url:"numFailed"`
	RunConfig     *BruteForceRunConfig `json:"runConfig,omitempty" url:"runConfig,omitempty"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (s *StatisticsInfo) GetExtraProperties() map[string]interface{} {
	return s.extraProperties
}

func (s *StatisticsInfo) UnmarshalJSON(data []byte) error {
	type unmarshaler StatisticsInfo
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*s = StatisticsInfo(value)

	extraProperties, err := core.ExtractExtraProperties(data, *s)
	if err != nil {
		return err
	}
	s.extraProperties = extraProperties

	s._rawJSON = json.RawMessage(data)
	return nil
}

func (s *StatisticsInfo) String() string {
	if len(s._rawJSON) > 0 {
		if value, err := core.StringifyJSON(s._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(s); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", s)
}

type GeneralRequestInfo struct {
	Username string `json:"username" url:"username"`
	Password string `json:"password" url:"password"`
	Host     string `json:"host" url:"host"`
	Port     int    `json:"port" url:"port"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (g *GeneralRequestInfo) GetExtraProperties() map[string]interface{} {
	return g.extraProperties
}

func (g *GeneralRequestInfo) UnmarshalJSON(data []byte) error {
	type unmarshaler GeneralRequestInfo
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*g = GeneralRequestInfo(value)

	extraProperties, err := core.ExtractExtraProperties(data, *g)
	if err != nil {
		return err
	}
	g.extraProperties = extraProperties

	g._rawJSON = json.RawMessage(data)
	return nil
}

func (g *GeneralRequestInfo) String() string {
	if len(g._rawJSON) > 0 {
		if value, err := core.StringifyJSON(g._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(g); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", g)
}

type GeneralResponseInfo struct {
	Message string `json:"message" url:"message"`

	extraProperties map[string]interface{}
	_rawJSON        json.RawMessage
}

func (g *GeneralResponseInfo) GetExtraProperties() map[string]interface{} {
	return g.extraProperties
}

func (g *GeneralResponseInfo) UnmarshalJSON(data []byte) error {
	type unmarshaler GeneralResponseInfo
	var value unmarshaler
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*g = GeneralResponseInfo(value)

	extraProperties, err := core.ExtractExtraProperties(data, *g)
	if err != nil {
		return err
	}
	g.extraProperties = extraProperties

	g._rawJSON = json.RawMessage(data)
	return nil
}

func (g *GeneralResponseInfo) String() string {
	if len(g._rawJSON) > 0 {
		if value, err := core.StringifyJSON(g._rawJSON); err == nil {
			return value
		}
	}
	if value, err := core.StringifyJSON(g); err == nil {
		return value
	}
	return fmt.Sprintf("%#v", g)
}
