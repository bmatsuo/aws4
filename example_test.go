package aws4_test

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bmizerany/aws4"
)

func Example_jSONBody() {
	data := strings.NewReader("{}")
	r, _ := http.NewRequest("POST", "https://dynamodb.us-east-1.amazonaws.com/", data)
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")
	r.Header.Set("X-Amz-Target", "DynamoDB_20111205.ListTables")

	resp, err := aws4.DefaultClient.Do(r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(resp.StatusCode)
	// Output:
	// 200
}

func Example_formEncodedBody() {
	v := make(url.Values)
	v.Set("Action", "DescribeAutoScalingGroups")

	resp, err := aws4.PostForm("https://autoscaling.us-east-1.amazonaws.com/", v)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(resp.StatusCode)
	// Output:
	// 200
}

func Example_signURL() {
	r, err := http.NewRequest("GET", "https://s3.amazonaws.com/", nil)
	if err != nil {
		log.Fatal(err)
	}

	// clearing headers allows "dumb clients" to use the signed URLs.
	r.Header = make(http.Header)

	keys := aws4.DefaultClient.Keys
	u, err := aws4.SignURL(keys, r, 300*time.Second)
	if err != nil {
		log.Fatal(err)
	}

	// perform a request using the url string returned from SignURL
	resp, err := http.Get(u)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()

	fmt.Println(resp.StatusCode)
	// Output:
	// 200
}
