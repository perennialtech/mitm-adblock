use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn replay_child_handles_requests_and_responses_without_reloading() {
    let corpus = tempfile::tempdir().unwrap();
    fs::write(
        corpus.path().join("easylist.txt"),
        "||ads.test^$all\n||page.test/bounce^$document,method=get\npage.test##.sponsor\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_replay-policy"))
        .arg(corpus.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut inputs = child.stdin.take().unwrap();
    let mut outputs = BufReader::new(child.stdout.take().unwrap());

    fn read_message(stream: &mut impl BufRead) -> Value {
        let mut line = String::new();
        assert!(stream.read_line(&mut line).unwrap() > 0);
        serde_json::from_str(&line).unwrap()
    }

    assert_eq!(read_message(&mut outputs), json!({"ready": true}));
    let mut evaluate = |url, response| {
        // "document" is the base64-encoded value of Sec-Fetch-Dest.
        let event = json!({
            "url": url,
            "method": "POST",
            "request_headers": [["sec-fetch-dest", "ZG9jdW1lbnQ="]],
            "response": response,
        });
        writeln!(inputs, "{event}").unwrap();
        read_message(&mut outputs)
    };

    let blocked = evaluate("https://ads.test/", Value::Null);
    assert_eq!(blocked["outcome"], "block");
    assert_eq!(blocked["status"], 403);
    assert_eq!(blocked["rule"], "||ads.test^$all");
    assert_eq!(blocked["navigation"], Value::Null);
    let allowed = evaluate("https://page.test/", Value::Null);
    assert_eq!(allowed["outcome"], "unchanged");
    let redirect = evaluate(
        "https://page.test/",
        json!({"status": 303, "headers": [["location", "L2JvdW5jZQ=="]]}),
    );
    assert_eq!(redirect["outcome"], "block");
    assert_eq!(redirect["navigation"], "redirect");
    let html = evaluate(
        "https://page.test/",
        json!({
            "status": 200,
            "headers": [["content-type", "dGV4dC9odG1s"]],
            "html": "<html><head></head><body>Original</body></html>",
        }),
    );
    assert_eq!(html["outcome"], "rewrite");
    assert_eq!(html["injected"], true);
    assert!(
        html["html"]
            .as_str()
            .unwrap()
            .contains("<style data-mitm-adblock>.sponsor{display:none!important}</style>")
    );

    drop(inputs);
    assert!(child.wait().unwrap().success());
}
