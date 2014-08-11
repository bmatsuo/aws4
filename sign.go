// Package aws4 signs HTTP requests as prescribed in
// http://docs.amazonwebservices.com/general/latest/gr/signature-version-4.html
package aws4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const iSO8601BasicFormat = "20060102T150405Z"
const iSO8601BasicFormatShort = "20060102"

var lf = []byte{'\n'}

// Keys holds a set of Amazon Security Credentials.
type Keys struct {
	AccessKey string
	SecretKey string
}

func (k *Keys) sign(s *Service, t time.Time) []byte {
	h := ghmac([]byte("AWS4"+k.SecretKey), []byte(t.Format(iSO8601BasicFormatShort)))
	h = ghmac(h, []byte(s.Region))
	h = ghmac(h, []byte(s.Name))
	h = ghmac(h, []byte("aws4_request"))
	return h
}

// Service represents an AWS-compatible service.
type Service struct {
	// Name is the name of the service being used (i.e. iam, etc)
	Name string

	// Region is the region you want to communicate with the service through. (i.e. us-east-1)
	Region string
}

func parseService(host string) (*Service, error) {
	parts := strings.Split(host, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("Invalid AWS Endpoint: %s", host)
	}

	s := &Service{
		Name:   parts[0],
		Region: parts[1],
	}
	if len(parts) < 4 {
		// host is something like <service>.amazonaws.com.  when no region is
		// specified us-east-1 is the default.
		s.Region = "us-east-1"
	}

	return s, nil
}

// Sign signs a request with a Service derived from r.Host
func Sign(keys *Keys, r *http.Request) error {
	s, err := parseService(r.Host)
	if err != nil {
		return err
	}
	s.Sign(keys, r)
	return nil
}

// SignURL returns a signed URL with a Service derived from r.Host.
func SignURL(keys *Keys, r *http.Request, dur time.Duration) (string, error) {
	s, err := parseService(r.Host)
	if err != nil {
		return "", err
	}
	return s.SignURL(keys, r, dur)
}

// Sign signs an HTTP request with the given AWS keys for use on service s.
func (s *Service) Sign(keys *Keys, r *http.Request) error {
	date := r.Header.Get("Date")
	t := time.Now().UTC()
	if date != "" {
		var err error
		t, err = time.Parse(http.TimeFormat, date)
		if err != nil {
			return err
		}
	}
	r.Header.Set("Date", t.Format(iSO8601BasicFormat))

	k := keys.sign(s, t)
	h := hmac.New(sha256.New, k)
	s.writeStringToSign(h, t, true, r)

	auth := bytes.NewBufferString("AWS4-HMAC-SHA256 ")
	auth.Write([]byte("Credential=" + keys.AccessKey + "/" + s.creds(t)))
	auth.Write([]byte{',', ' '})
	auth.Write([]byte("SignedHeaders="))
	s.writeHeaderList(auth, r)
	auth.Write([]byte{',', ' '})
	auth.Write([]byte("Signature=" + fmt.Sprintf("%x", h.Sum(nil))))

	r.Header.Set("Authorization", auth.String())

	return nil
}

// SignURL signs r using query parameters and returns the resulting URL.
//
// Any headers present in r are signed and must be included in requests using
// the returned URL.  SignURL sets the Host header in r but, unlike Sign, does
// not set the Date header.
//
// SignURL does not sign the requset body.
func (s *Service) SignURL(keys *Keys, r *http.Request, dur time.Duration) (string, error) {
	r.Header.Set("Host", r.Host)

	// determine if the request already has a date associated with it and use
	// it if so.  if no date is associated, use the current time.
	var t time.Time
	var err error
	date := r.Header.Get("Date")
	if date == "" {
		t = time.Now().UTC()
	} else {
		t, err = time.Parse(http.TimeFormat, date)
		if err != nil {
			return "", err
		}
	}

	// add authorization headers to the query string.  parsing the query is
	// avoided, but as a consequence value MUST be query escaped if the value
	// domain is not known with certainty.
	qstr := "X-Amz-Algorithm=AWS4-HMAC-SHA256"
	qstr += "&X-Amz-Credential=" + url.QueryEscape(keys.AccessKey+"/"+s.creds(t))
	qstr += "&X-Amz-Date=" + t.Format(iSO8601BasicFormat)
	qstr += "&X-Amz-Expires=" + fmt.Sprint(int64(dur/time.Second))
	var hbuf bytes.Buffer
	s.writeHeaderList(&hbuf, r)
	qstr += "&X-Amz-SignedHeaders=" + url.QueryEscape(hbuf.String())
	if r.URL.RawQuery != "" {
		r.URL.RawQuery += "&"
	}
	r.URL.RawQuery += qstr

	// compute the request signature and append it as a query parameter.
	k := keys.sign(s, t)
	h := hmac.New(sha256.New, k)
	s.writeStringToSign(h, t, false, r)
	r.URL.RawQuery += "&X-Amz-Signature=" + fmt.Sprintf("%x", h.Sum(nil))

	return r.URL.String(), nil
}

func (s *Service) writeQuery(w io.Writer, r *http.Request) {
	var a []string
	for k, vs := range r.URL.Query() {
		k = url.QueryEscape(k)
		for _, v := range vs {
			if v == "" {
				a = append(a, k)
			} else {
				v = url.QueryEscape(v)
				a = append(a, k+"="+v)
			}
		}
	}
	sort.Strings(a)
	for i, s := range a {
		if i > 0 {
			w.Write([]byte{'&'})
		}
		w.Write([]byte(s))
	}
}

func (s *Service) writeHeader(w io.Writer, r *http.Request) {
	i, a := 0, make([]string, len(r.Header))
	for k, v := range r.Header {
		sort.Strings(v)
		a[i] = strings.ToLower(k) + ":" + strings.Join(v, ",")
		i++
	}
	sort.Strings(a)
	for i, s := range a {
		if i > 0 {
			w.Write(lf)
		}
		io.WriteString(w, s)
	}
}

func (s *Service) writeHeaderList(w io.Writer, r *http.Request) {
	i, a := 0, make([]string, len(r.Header))
	for k, _ := range r.Header {
		a[i] = strings.ToLower(k)
		i++
	}
	sort.Strings(a)
	for i, s := range a {
		if i > 0 {
			w.Write([]byte{';'})
		}
		w.Write([]byte(s))
	}
}

func (s *Service) writeBody(w io.Writer, r *http.Request) {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(b))

	h := sha256.New()
	h.Write(b)
	fmt.Fprintf(w, "%x", h.Sum(nil))
}

func (s *Service) writeURI(w io.Writer, r *http.Request) {
	path := r.URL.RequestURI()
	if r.URL.RawQuery != "" {
		path = path[:len(path)-len(r.URL.RawQuery)-1]
	}
	slash := strings.HasSuffix(path, "/")
	path = filepath.Clean(path)
	if path != "/" && slash {
		path += "/"
	}
	w.Write([]byte(path))
}

func (s *Service) writeRequest(w io.Writer, payload bool, r *http.Request) {
	r.Header.Set("host", r.Host)

	w.Write([]byte(r.Method))
	w.Write(lf)
	s.writeURI(w, r)
	w.Write(lf)
	s.writeQuery(w, r)
	w.Write(lf)
	s.writeHeader(w, r)
	w.Write(lf)
	w.Write(lf)
	s.writeHeaderList(w, r)
	w.Write(lf)
	if payload {
		s.writeBody(w, r)
	} else {
		w.Write([]byte("UNSIGNED-PAYLOAD"))
	}
}

func (s *Service) writeStringToSign(w io.Writer, t time.Time, payload bool, r *http.Request) {
	w.Write([]byte("AWS4-HMAC-SHA256"))
	w.Write(lf)
	w.Write([]byte(t.Format(iSO8601BasicFormat)))
	w.Write(lf)

	w.Write([]byte(s.creds(t)))
	w.Write(lf)

	h := sha256.New()
	s.writeRequest(h, payload, r)
	fmt.Fprintf(w, "%x", h.Sum(nil))
}

func (s *Service) creds(t time.Time) string {
	return t.Format(iSO8601BasicFormatShort) + "/" + s.Region + "/" + s.Name + "/aws4_request"
}

func ghmac(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
