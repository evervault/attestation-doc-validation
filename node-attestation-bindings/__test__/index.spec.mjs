import test from "ava";

import { attestConnection } from "../index.js";

import { readdirSync, readFileSync } from "fs";

const BASE_TEST_PATH = "..";
const directory = readdirSync(`${BASE_TEST_PATH}/test-specs`, "utf8");

function resolveCert(filePath) {
  const rawCert = readFileSync(`${BASE_TEST_PATH}/${filePath}`);
  if (!filePath.endsWith(".pem")) {
    return rawCert;
  }
  const certString = rawCert.toString("utf8");
  const derContent = certString.split("\n").slice(1, -1).join("");
  return Buffer.from(derContent, "base64");
}

for (let testSpec of directory) {
  test(testSpec, (t) => {
    const specText = readFileSync(
      `${BASE_TEST_PATH}/test-specs/${testSpec}`,
      "utf8"
    );
    const { file, pcrs, isAttestationDocValid, shouldPcrsMatch } =
      JSON.parse(specText);

    const inputFile = resolveCert(file);
    const isConnectionValid = attestConnection(inputFile, pcrs);
    t.deepEqual(isConnectionValid, isAttestationDocValid && shouldPcrsMatch);
  });
}
