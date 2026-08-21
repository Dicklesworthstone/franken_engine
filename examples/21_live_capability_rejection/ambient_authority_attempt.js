// Attempt to access the filesystem without the required fs:read capability.
const fs = require("fs");
fs.readFileSync("/etc/passwd");
