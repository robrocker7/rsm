# RSM - Rust Secrets Manager

A simple Secret Mangager for JSON payloads using SQLite3 and AES-256 encryption.

## Installation

`git clone --depth=1 https://github.com/robrocker7/rsm && cd rsm && cargo install --path .`

## Environment Variables

The `RMS_KEY` and `RMS_IV` environment variables are required to be set.

### RMS_KEY 

32byte value required

`export RMS_KEY="1234567890ABCDEF1234567890ABCDEF"`

### RMS_IV

16byte value required

`export RMS_KEY="1234567890ABCDEF"`

## Example Usage

### Put a Secret

`rms put awslocal '{"aws_access_key_id":"SuperSecretValue","aws_access_secret_key":"SuperSecretValue"}'`

Response
`{"success":"awslocal"}`

### Get a Secret

`rms get awslocal`

Response:
`{"aws_access_key_id":"SuperSecretValue","aws_access_secret_key":"SuperSecretValue"}`


### Simple Rust Subprocess Example

```
fn get_secret_rsm(name: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let output = Command::new("rsm")
        .arg("get")
        .arg(name)
        .output()?;

    if !output.status.success() {
        eprintln!("Command executed with failing error code");
        std::process::exit(1);
    }
    let output_str = str::from_utf8(&output.stdout)?;
    let json: Value = serde_json::from_str(output_str)?;
    Ok(json)
}
```