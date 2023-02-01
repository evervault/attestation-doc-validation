import test from "ava";

import { attestConnection } from "../index.js";

import { readdirSync, readFileSync } from "fs";

const BASE_TEST_PATH = "..";
const directory = readdirSync(`${BASE_TEST_PATH}/test-specs`, "utf8");

for (let testSpec of directory) {
  test(testSpec, (t) => {
    const specText = readFileSync(
      `${BASE_TEST_PATH}/test-specs/${testSpec}`,
      "utf8"
    );
    const { file, pcrs, isAttestationDocValid, shouldPcrsMatch } =
      JSON.parse(specText);

    const inputFile = readFileSync(`${BASE_TEST_PATH}/${file}`);
    const isConnectionValid = attestConnection(inputFile, pcrs);
    t.deepEqual(isConnectionValid, isAttestationDocValid && shouldPcrsMatch);
  });
}
