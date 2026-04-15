/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  moduleFileExtensions: ["ts", "js"],
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        diagnostics: false,
        tsconfig: {
          strict: true,
          noUncheckedIndexedAccess: false,
          exactOptionalPropertyTypes: false,
          noImplicitOverride: false,
        },
      },
    ],
  },
  testMatch: ["**/*.test.ts"],
};
