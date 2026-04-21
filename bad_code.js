const fake_aws_key = "DUMMY_AWS_KEY";
const github_token = "DUMMY_GITHUB_TOKEN";

function intentionallyBadJavascript() {
    console.log("This has no semicolon")
    let unused_var = 42;
    var a = a + b; // undefined variable
    eval("console.log('Very Bad')")
}
