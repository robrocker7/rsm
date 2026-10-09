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

### RSM_DB

Optional path to the SQLite database. When it is unset, rsm uses `secrets.db` next to the executable. The `--db` flag overrides this variable.

`export RSM_DB="/path/to/secrets.db"`

`rsm --db /path/to/secrets.db get awslocal`

## Example Usage

### Put a Secret

`rms put awslocal '{"aws_access_key_id":"SuperSecretValue","aws_access_secret_key":"SuperSecretValue"}'`

Response
`{"success":"awslocal"}`

### Get a Secret

`rms get awslocal`

Response:
`{"aws_access_key_id":"SuperSecretValue","aws_access_secret_key":"SuperSecretValue"}`

### Share secrets

Copy named secrets into a new database encrypted with new keys. The current `RSM_KEY` and `RSM_IV` stay unchanged.

`rsm share shared.db slack,openai`

Response:
`{"filename":"shared.db","RSM_KEY":"...","RSM_IV":"...","secrets":["slack","openai"]}`

Read from the new database with the printed keys:

`RSM_KEY="..." RSM_IV="..." rsm --db shared.db get slack`

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
