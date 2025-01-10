import test from "ava";

import { attestEnclave } from "../index.js";

import { readdirSync, readFileSync } from "fs";

const BASE_TEST_PATH = "..";
const directory = readdirSync(`${BASE_TEST_PATH}/test-specs/ga`, "utf8");

function resolveFile(filePath, encoding) {
  const rawCert = readFileSync(`${BASE_TEST_PATH}/${filePath}`, encoding);
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
      `${BASE_TEST_PATH}/test-specs/ga/${testSpec}`,
      "utf8"
    );
    const {
      cert,
      attestationDoc,
      pcrs,
      isAttestationDocValid,
      shouldPcrsMatch,
    } = JSON.parse(specText);

    const certBuf = resolveFile(cert);
    const attestationDocString = resolveFile(attestationDoc, "utf8");
    const attestationDocBuf = Buffer.from(attestationDocString, "base64");
    const isConnectionValid = attestEnclave(certBuf, [pcrs], attestationDocBuf);
    t.deepEqual(isConnectionValid, isAttestationDocValid);
    t.deepEqual(isConnectionValid, shouldPcrsMatch);
  });
}
